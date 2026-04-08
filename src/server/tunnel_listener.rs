//! Listens for tunnel client connections using pool-based architecture.
//!
//! Each incoming TCP connection does a Noise handshake, then reads the first message:
//! - Register -> control channel (heartbeat loop)
//! - DataReady -> data channel (push to router, await assignment)

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::tunnel::noise::{NoiseStream, derive_psk};
use crate::tunnel::protocol::TunnelMessage;
use crate::tunnel::router::Router;

/// Maximum concurrent tunnel connections (control + data channels).
const MAX_TUNNEL_CONNECTIONS: usize = 2048;

pub async fn run_tunnel_listener(
    listen_addr: &str,
    secret: &str,
    router: Arc<Router>,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    let psk = derive_psk(secret);
    let semaphore = Arc::new(Semaphore::new(MAX_TUNNEL_CONNECTIONS));

    tracing::info!(%listen_addr, max_tunnel_conns = MAX_TUNNEL_CONNECTIONS, "tunnel listener started");

    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!("tunnel listener shutting down");
                break;
            }
            result = listener.accept() => {
                let (stream, peer_addr) = result?;
                stream.set_nodelay(true)?;

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(%peer_addr, "tunnel connection limit reached, dropping");
                        drop(stream);
                        continue;
                    }
                };

                let router = router.clone();
                let cancel = cancel.clone();

                tasks.spawn(async move {
                    let _permit = permit; // held until task completes
                    match NoiseStream::accept(stream, &psk).await {
                        Ok(mut noise) => {
                            // Read first message to determine channel type
                            let data = match noise.recv().await {
                                Ok(d) => d,
                                Err(e) => {
                                    tracing::debug!(%peer_addr, error = %e, "failed to read first message");
                                    return;
                                }
                            };

                            match TunnelMessage::decode(&data) {
                                Ok(TunnelMessage::Register { client_id, pool_size }) => {
                                    if let Err(e) = handle_control_channel(noise, &client_id, pool_size, &router, cancel).await {
                                        tracing::debug!(%peer_addr, %client_id, error = %e, "control channel error");
                                    }
                                }
                                Ok(TunnelMessage::DataReady { client_id }) => {
                                    if let Err(e) = handle_data_channel(noise, &client_id, &router).await {
                                        tracing::debug!(%peer_addr, %client_id, error = %e, "data channel error");
                                    }
                                }
                                Ok(other) => {
                                    tracing::debug!(%peer_addr, msg = ?other, "unexpected first message");
                                }
                                Err(e) => {
                                    tracing::debug!(%peer_addr, error = %e, "failed to decode first message");
                                }
                            }
                        }
                        Err(e) => tracing::warn!(%peer_addr, error = %e, "noise handshake failed"),
                    }
                });
            }
        }
    }

    tasks.abort_all();
    Ok(())
}

/// Handle a control channel: register client, run heartbeat loop.
async fn handle_control_channel(
    mut noise: NoiseStream,
    client_id: &str,
    pool_size: u16,
    router: &Router,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    tracing::info!(%client_id, %pool_size, "client registered (pool)");

    let _data_tx = router.register(client_id.to_string(), pool_size).await;

    let mut heartbeat_tick = tokio::time::interval(std::time::Duration::from_secs(15));
    heartbeat_tick.tick().await;
    let mut last_recv = tokio::time::Instant::now();
    let deadline = std::time::Duration::from_secs(45);

    let result = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                let msg = TunnelMessage::Disconnect { reason: "server shutting down".into() };
                let _ = noise.send(&msg.encode()).await;
                break Ok(());
            }
            _ = heartbeat_tick.tick() => {
                if last_recv.elapsed() > deadline {
                    tracing::warn!(%client_id, "heartbeat timeout");
                    break Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "heartbeat timeout"));
                }
                // Send heartbeat
                let _ = noise.send(&TunnelMessage::Heartbeat.encode()).await;
            }
            result = noise.recv() => {
                match result {
                    Ok(data) => {
                        last_recv = tokio::time::Instant::now();
                        if let Ok(TunnelMessage::Disconnect { reason }) = TunnelMessage::decode(&data) {
                            tracing::info!(%client_id, %reason, "client disconnected");
                            break Ok(());
                        }
                        // Heartbeat response — already updated last_recv
                    }
                    Err(e) => {
                        break Err(e);
                    }
                }
            }
        }
    };

    router.unregister(client_id).await;
    tracing::info!(%client_id, "client session ended");

    result
}

/// Handle a data channel: push to router, await assignment to keep alive.
async fn handle_data_channel(
    noise: NoiseStream,
    client_id: &str,
    router: &Router,
) -> std::io::Result<()> {
    // Push the noise stream to the router's pool for this client
    let assign_rx = router.push_data_conn(client_id, noise).await?;

    // Wait until the connection is assigned (taken by a SOCKS handler)
    // This keeps this task alive so the underlying connection stays open
    let _ = assign_rx.await;

    Ok(())
}

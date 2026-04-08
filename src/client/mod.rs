//! Tunnel client — pool-based connections over separate TCP streams.
//!
//! Architecture:
//! - Control channel: one TCP + Noise connection for Register + heartbeat
//! - Data pool: pool_size workers, each opening a separate TCP + Noise connection
//! - Each worker sends DataReady, serves one proxy request, then reconnects

pub mod worker;

use std::time::Duration;

use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::tunnel::noise::{NoiseStream, derive_psk};
use crate::tunnel::pool::ConnectionPool;
use crate::tunnel::protocol::TunnelMessage;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_addr: String,
    pub secret: String,
    pub client_id: String,
    pub pool_size: u16,
    pub reconnect_interval: Duration,
}

/// Maximum time to keep retrying before giving up.
const MAX_RECONNECT_DURATION: Duration = Duration::from_secs(30 * 60); // 30 minutes

pub async fn run_client(config: ClientConfig, cancel: CancellationToken) {
    let mut reconnect_since: Option<tokio::time::Instant> = None;

    loop {
        tracing::info!(server = %config.server_addr, client_id = %config.client_id, "connecting...");

        // Each session gets its own cancel token so a failed session
        // doesn't cancel the entire client.
        let session_cancel = CancellationToken::new();
        let _link = cancel.clone().drop_guard();

        match run_client_session(&config, session_cancel.clone(), cancel.clone()).await {
            Ok(()) => {
                if cancel.is_cancelled() {
                    return;
                }
                // Connected successfully at some point — reset reconnect timer
                reconnect_since = None;
                tracing::info!("session ended, reconnecting...");
            }
            Err(e) => {
                if cancel.is_cancelled() {
                    return;
                }
                tracing::warn!(error = %e, "session failed");

                // Start tracking reconnect duration from first failure
                let since = *reconnect_since.get_or_insert_with(tokio::time::Instant::now);
                let elapsed = since.elapsed();

                if elapsed >= MAX_RECONNECT_DURATION {
                    tracing::error!(
                        elapsed_mins = elapsed.as_secs() / 60,
                        "exceeded max reconnect duration (30 min), exiting"
                    );
                    return;
                }

                let remaining = MAX_RECONNECT_DURATION - elapsed;
                tracing::info!(
                    retry_in_secs = config.reconnect_interval.as_secs(),
                    remaining_mins = remaining.as_secs() / 60,
                    "reconnecting..."
                );
            }
        }

        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(config.reconnect_interval) => {}
        }
    }
}

async fn run_client_session(
    config: &ClientConfig,
    session_cancel: CancellationToken,
    global_cancel: CancellationToken,
) -> std::io::Result<()> {
    let psk = derive_psk(&config.secret);

    // 1. TCP + Noise connect for control channel
    let tcp = TcpStream::connect(&config.server_addr).await?;
    tcp.set_nodelay(true)?;
    let mut control = NoiseStream::connect(tcp, &psk).await?;

    // 2. Send Register on control channel
    let register = TunnelMessage::Register {
        client_id: config.client_id.clone(),
        pool_size: config.pool_size,
    };
    control.send(&register.encode()).await?;

    tracing::info!(client_id = %config.client_id, "registered (pool)");

    // 3. Start ConnectionPool (spawns workers)
    let pool = ConnectionPool::new(
        config.server_addr.clone(),
        config.client_id.clone(),
        &config.secret,
        config.pool_size,
    );
    pool.start(session_cancel.clone());

    // 4. Heartbeat loop using tokio::time::interval
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    tick.tick().await;
    let mut last_recv = tokio::time::Instant::now();
    let deadline = Duration::from_secs(45);

    let result = loop {
        tokio::select! {
            biased;
            _ = global_cancel.cancelled() => {
                let msg = TunnelMessage::Disconnect { reason: "shutting down".into() };
                let _ = control.send(&msg.encode()).await;
                break Ok(());
            }
            _ = tick.tick() => {
                if last_recv.elapsed() > deadline {
                    break Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "heartbeat timeout"));
                }
                if let Err(e) = control.send(&TunnelMessage::Heartbeat.encode()).await {
                    break Err(e);
                }
            }
            result = control.recv() => {
                match result {
                    Ok(data) => {
                        last_recv = tokio::time::Instant::now();
                        if let Ok(TunnelMessage::Disconnect { reason }) = TunnelMessage::decode(&data) {
                            tracing::info!(%reason, "server disconnected");
                            break Ok(());
                        }
                    }
                    Err(e) => break Err(e),
                }
            }
        }
    };

    // Cancel this session's pool workers, but don't cancel the global client
    session_cancel.cancel();
    result
}

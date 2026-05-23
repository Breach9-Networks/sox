//! Listens for tunnel client connections — each connection becomes one yamux session.
//!
//! Per connection: Noise handshake → `Hello`/`HelloAck` → register a `SessionHandle`
//! with the `Router` → drive the yamux session until it ends.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::tunnel::apply_tunnel_keepalive;
use crate::tunnel::noise::{NoiseStream, derive_psk};
use crate::tunnel::protocol::{Hello, HelloAck, PROTO_VERSION};
use crate::tunnel::router::{Router, SessionHandle};
use crate::tunnel::session::server_session_driver;

/// Maximum concurrent tunnel sessions.
const MAX_TUNNEL_CONNECTIONS: usize = 2048;

/// Buffer for pending "open outbound stream" requests per session.
const OPEN_REQUEST_BUFFER: usize = 64;

/// Upper bound on the Noise + `Hello`/`HelloAck` handshake. A peer that
/// completes the TCP connection but stalls mid-handshake must not hold a
/// tunnel-connection slot indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run_tunnel_listener(
    listen_addr: &str,
    secret: &str,
    router: Arc<Router>,
    cancel: CancellationToken,
    max_streams: usize,
    recv_window_mb: usize,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    let psk = derive_psk(secret);
    let semaphore = Arc::new(Semaphore::new(MAX_TUNNEL_CONNECTIONS));

    tracing::info!(
        %listen_addr,
        max_tunnel_conns = MAX_TUNNEL_CONNECTIONS,
        "tunnel listener started"
    );

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
                // Half-open dead-connection detection — OS-level TCP keepalive.
                let _ = apply_tunnel_keepalive(&stream);

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
                    let _permit = permit;
                    if let Err(e) = handle_tunnel_conn(
                        stream, psk, router, cancel, max_streams, recv_window_mb,
                    ).await {
                        tracing::debug!(%peer_addr, error = %e, "tunnel session ended");
                    }
                });
            }
        }
    }

    tasks.abort_all();
    Ok(())
}

/// Handshake phase: Noise `accept` + `Hello`/`HelloAck`. Returns the
/// handshake-complete `NoiseStream` and the client's `Hello`. The caller
/// wraps this in a timeout (S2: slow-loris protection).
async fn tunnel_handshake(
    stream: tokio::net::TcpStream,
    psk: &[u8; 32],
) -> std::io::Result<(NoiseStream, Hello)> {
    let mut noise = NoiseStream::accept(stream, psk).await?;

    // Read the client's Hello.
    let hello_bytes = noise.recv().await?;
    let hello = Hello::decode(&hello_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    if hello.proto_version != PROTO_VERSION {
        let ack = HelloAck {
            accepted: false,
            reason: format!(
                "proto version mismatch: server {PROTO_VERSION}, client {}",
                hello.proto_version
            ),
        };
        let _ = noise.send(&ack.encode()).await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tunnel client proto version mismatch",
        ));
    }

    noise
        .send(&HelloAck { accepted: true, reason: String::new() }.encode())
        .await?;

    Ok((noise, hello))
}

/// Handle one incoming tunnel connection: handshake, register, drive the session.
async fn handle_tunnel_conn(
    stream: tokio::net::TcpStream,
    psk: [u8; 32],
    router: Arc<Router>,
    cancel: CancellationToken,
    max_streams: usize,
    recv_window_mb: usize,
) -> std::io::Result<()> {
    // S2: bound the whole handshake — a peer that connects but never (or
    // slowly) completes Noise/Hello must not pin a tunnel-connection slot.
    let (noise, hello) =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, tunnel_handshake(stream, &psk)).await {
            Ok(r) => r?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "tunnel handshake timed out",
                ));
            }
        };

    let client_id = hello.client_id.clone();
    tracing::info!(%client_id, session_index = hello.session_index, "tunnel session accepted");

    // Register a SessionHandle and drive the yamux session to completion.
    let byte_stream = noise.into_byte_stream();
    let (open_tx, open_rx) = mpsc::channel(OPEN_REQUEST_BUFFER);
    let handle = SessionHandle::new(open_tx);
    let session_id = handle.id;
    router.register_session(client_id.clone(), handle).await;

    server_session_driver(byte_stream, open_rx, max_streams, recv_window_mb, cancel).await;

    router.remove_session(&client_id, session_id).await;
    Ok(())
}

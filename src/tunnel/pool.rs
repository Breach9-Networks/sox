//! Client-side connection pool management.
//!
//! Each pool connection is established once (TCP + Noise handshake),
//! then serves multiple proxy requests in a loop. Only reconnects
//! when the connection is broken.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::client::worker;
use crate::tunnel::noise::{NoiseStream, derive_psk};
use crate::tunnel::protocol::TunnelMessage;

/// Manages a pool of data connections to the tunnel server.
pub struct ConnectionPool {
    server_addr: String,
    client_id: String,
    psk: [u8; 32],
    pool_size: u16,
}

impl ConnectionPool {
    pub fn new(server_addr: String, client_id: String, secret: &str, pool_size: u16) -> Self {
        Self {
            server_addr,
            client_id,
            psk: derive_psk(secret),
            pool_size,
        }
    }

    /// Start the pool — spawns `pool_size` workers, each maintaining one connection.
    /// Each connection now serves multiple requests before reconnecting.
    pub fn start(&self, cancel: CancellationToken) {
        for _ in 0..self.pool_size {
            let server_addr = self.server_addr.clone();
            let client_id = self.client_id.clone();
            let psk = self.psk;
            let cancel = cancel.clone();

            tokio::spawn(async move {
                pool_slot(server_addr, client_id, psk, cancel).await;
            });
        }
    }
}

/// A single pool slot — establishes a connection, then serves requests in a loop.
/// Only reconnects when the connection breaks or an error occurs.
async fn pool_slot(
    server_addr: String,
    client_id: String,
    psk: [u8; 32],
    cancel: CancellationToken,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }

        match establish_and_serve_loop(&server_addr, &client_id, &psk, &cancel).await {
            Ok(()) => {
                // Cancelled cleanly
                return;
            }
            Err(e) => {
                if cancel.is_cancelled() {
                    return;
                }
                tracing::debug!(error = %e, "pool slot: connection lost, reconnecting...");
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                }
            }
        }
    }
}

/// Establish one connection and serve multiple proxy requests on it.
/// Returns Ok(()) only on cancellation. Returns Err on connection failure.
async fn establish_and_serve_loop(
    server_addr: &str,
    client_id: &str,
    psk: &[u8; 32],
    cancel: &CancellationToken,
) -> std::io::Result<()> {
    let tcp = TcpStream::connect(server_addr).await?;
    tcp.set_nodelay(true)?;

    let mut noise = NoiseStream::connect(tcp, psk).await?;

    // Tell server this is a data connection
    let msg = TunnelMessage::DataReady {
        client_id: client_id.to_string(),
    };
    noise.send(&msg.encode()).await?;

    // Serve requests in a loop on this connection.
    // After each relay, send DataReady to signal the server we're ready for the next request.
    // The server waits for DataReady before returning the connection to the pool,
    // preventing a race where a new ProxyRequest arrives while the relay is still running.
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }

        match worker::handle_data_connection(noise, cancel.clone()).await {
            Ok(returned_noise) => {
                noise = returned_noise;
                tracing::trace!("pool slot: request served, signaling ready");
                let ready_msg = TunnelMessage::DataReady {
                    client_id: client_id.to_string(),
                };
                noise.send(&ready_msg.encode()).await?;
            }
            Err(e) => {
                // Connection broken — caller will reconnect
                return Err(e);
            }
        }
    }
}

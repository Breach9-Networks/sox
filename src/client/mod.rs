//! Tunnel client — maintains a pool of yamux sessions to the tunnel server.
//!
//! Each session is one TCP + Noise connection carrying many multiplexed
//! streams. The server opens a stream per proxy flow; the client dials the
//! target and relays. Sessions reconnect independently with exponential backoff.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::tunnel::session::{SessionPool, SessionPoolConfig};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_addr: String,
    pub secret: String,
    pub client_id: String,
    /// Number of concurrent yamux sessions to maintain.
    pub tunnel_sessions: u16,
    /// Per-session yamux stream limit.
    pub max_streams: usize,
    /// Per-session yamux receive window (MiB).
    pub recv_window_mb: usize,
    /// Reconnect backoff base.
    pub reconnect_interval: Duration,
    /// Reconnect backoff cap.
    pub reconnect_max: Duration,
    /// Timeout for dialing a proxied target.
    pub connect_timeout: Duration,
    /// Idle timeout for a relay (no data in either direction).
    pub idle_timeout: Duration,
    /// Timeout for resolving a UDP target's domain.
    pub dns_timeout: Duration,
    /// On shutdown, how long in-flight relays get to finish.
    pub drain_timeout: Duration,
}

/// Run the tunnel client until cancelled, then drain. Sessions self-heal via
/// backoff.
pub async fn run_client(config: ClientConfig, cancel: CancellationToken) {
    tracing::info!(
        server = %config.server_addr,
        client_id = %config.client_id,
        sessions = config.tunnel_sessions,
        "tunnel client starting"
    );

    let pool = SessionPool::new(
        config.server_addr,
        config.client_id,
        &config.secret,
        SessionPoolConfig {
            sessions: config.tunnel_sessions,
            max_streams: config.max_streams,
            recv_window_mb: config.recv_window_mb,
            reconnect_base: config.reconnect_interval,
            reconnect_max: config.reconnect_max,
            connect_timeout: config.connect_timeout,
            idle_timeout: config.idle_timeout,
            dns_timeout: config.dns_timeout,
            drain_timeout: config.drain_timeout,
        },
    );
    let workers = pool.start(cancel.clone());

    cancel.cancelled().await;
    tracing::info!("tunnel client shutting down, draining in-flight relays");
    // Each worker returns once its session has drained (bounded by
    // `drain_timeout`) — returning earlier would let the process exit and cut
    // every in-flight relay.
    for worker in workers {
        let _ = worker.await;
    }
    tracing::info!("tunnel client stopped");
}

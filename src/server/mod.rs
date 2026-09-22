pub mod connection;
pub mod extended_metrics;
pub mod limits;
pub mod metrics;
pub mod monitor;
pub mod tunnel_listener;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::auth::AuthProvider;
use crate::config::{AuthConfig, Config};
use crate::server::limits::{PerIpLimiter, check_fd_limit};
use crate::server::extended_metrics::ExtendedMetrics;
use crate::server::metrics::Metrics;
use crate::tunnel::router::Router;

/// Shared context passed to each connection handler.
pub struct ServerContext {
    pub config: Config,
    pub metrics: Metrics,
    pub extended_metrics: ExtendedMetrics,
    pub ip_limiter: PerIpLimiter,
    pub auth: Option<Arc<dyn AuthProvider>>,
    /// Router for tunnel mode. None = standalone (direct connect).
    pub router: Option<Arc<Router>>,
}

/// Run the SOCKS proxy server in standalone mode.
pub async fn run_standalone(
    config: Config,
    shutdown: CancellationToken,
) -> Result<(), crate::error::ServerError> {
    // Check and raise FD limit
    match check_fd_limit() {
        Ok(limit) => {
            if (limit as usize) < config.max_connections * 2 + 100 {
                tracing::warn!(
                    fd_limit = limit,
                    max_connections = config.max_connections,
                    "FD limit may be too low for configured max_connections"
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to check FD limit"),
    }

    let listener = TcpListener::bind(config.listen_addr).await?;

    // Build auth provider from config
    let auth: Option<Arc<dyn AuthProvider>> = match &config.auth {
        AuthConfig::None => {
            tracing::info!("authentication: disabled");
            None
        }
        AuthConfig::Password(users) => {
            tracing::info!(users = users.len(), "authentication: username/password");
            Some(Arc::new(crate::auth::password::PasswordAuth::new(
                users.clone(),
            )))
        }
    };

    tracing::info!("SOCKS proxy listening on {}", config.listen_addr);

    let limiter = Arc::new(Semaphore::new(config.max_connections));
    let ctx = Arc::new(ServerContext {
        ip_limiter: PerIpLimiter::new(config.max_connections_per_ip),
        config,
        metrics: Metrics::default(),
        extended_metrics: ExtendedMetrics::new(),
        auth,
        router: None,
    });

    // Spawn monitor dashboard if configured
    if ctx.config.monitor_addr.is_some() {
        let ctx_mon = ctx.clone();
        let cancel_mon = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = monitor::run_monitor(ctx_mon, cancel_mon).await {
                tracing::error!(error = %e, "monitor server failed");
            }
        });
    }

    // Spawn traffic sampling background task
    spawn_traffic_sampler(ctx.clone(), shutdown.clone());

    serve_socks(&listener, &ctx, &limiter, &shutdown).await;

    let snap = ctx.metrics.snapshot();
    tracing::info!(%snap, "server stopped");

    Ok(())
}

/// How often a "connection rejected by a limit" warning may be logged. Under
/// an attack every rejected connection would otherwise produce a log line.
const REJECT_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Pause after a failed `accept()` so fd exhaustion does not become a busy loop.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Rate-limits a repetitive warning: `ready()` is true at most once per
/// `REJECT_LOG_INTERVAL`, and reports how many events were suppressed since.
struct LogThrottle {
    last: Option<std::time::Instant>,
    suppressed: u64,
}

impl LogThrottle {
    fn new() -> Self {
        Self { last: None, suppressed: 0 }
    }

    fn ready(&mut self) -> Option<u64> {
        if self.last.is_some_and(|t| t.elapsed() < REJECT_LOG_INTERVAL) {
            self.suppressed += 1;
            return None;
        }
        self.last = Some(std::time::Instant::now());
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// The SOCKS accept loop shared by standalone and tunnel mode: accept, apply
/// the connection limits, spawn a handler per connection — then, once
/// `shutdown` fires, stop accepting and drain the in-flight connections
/// (bounded by `drain_timeout`) instead of abandoning relays mid-flight.
async fn serve_socks(
    listener: &TcpListener,
    ctx: &Arc<ServerContext>,
    limiter: &Arc<Semaphore>,
    shutdown: &CancellationToken,
) {
    let mut tasks = JoinSet::new();
    let mut reject_log = LogThrottle::new();

    loop {
        tokio::select! {
            biased;

            _ = shutdown.cancelled() => {
                tracing::info!(
                    active = tasks.len(),
                    "shutdown signal received, draining connections..."
                );
                break;
            }

            // Reap finished handlers as we go. A JoinSet keeps every finished
            // task's result until it is joined — never joining while serving
            // would grow memory by one entry per connection, forever.
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(e) = joined && e.is_panic() {
                    tracing::error!(error = %e, "connection handler panicked");
                }
            }

            result = listener.accept() => {
                let (stream, peer_addr) = match result {
                    Ok(pair) => pair,
                    Err(e) => {
                        // A failed accept (e.g. EMFILE/ENFILE — fd exhaustion)
                        // must not kill the server. Back off briefly so we do
                        // not busy-spin, then keep accepting.
                        tracing::warn!(error = %e, "accept failed, backing off");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };

                // Global, then per-IP connection limit.
                let Ok(permit) = limiter.clone().try_acquire_owned() else {
                    if let Some(suppressed) = reject_log.ready() {
                        tracing::warn!(%peer_addr, suppressed, "global connection limit reached");
                    }
                    continue;
                };
                let Some(ip_guard) = ctx.ip_limiter.try_acquire(peer_addr.ip()) else {
                    if let Some(suppressed) = reject_log.ready() {
                        tracing::warn!(%peer_addr, suppressed, "per-IP connection limit reached");
                    }
                    continue;
                };

                let ctx = ctx.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ip_guard = ip_guard;
                    // The active count is decremented by this guard on drop.
                    let _conn = ctx.metrics.connection_opened();
                    ctx.extended_metrics.update_peak(
                        ctx.metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed),
                    );

                    if let Err(e) = handle_client(stream, peer_addr, &ctx).await {
                        tracing::debug!(%peer_addr, error = %e, "connection ended with error");
                    }
                });
            }
        }
    }

    // Drain active connections with timeout
    let drain_deadline = tokio::time::sleep(ctx.config.drain_timeout);
    tokio::pin!(drain_deadline);

    while !tasks.is_empty() {
        tokio::select! {
            _ = tasks.join_next() => {}
            _ = &mut drain_deadline => {
                tracing::warn!(
                    remaining = tasks.len(),
                    "drain timeout, aborting remaining connections"
                );
                tasks.abort_all();
                return;
            }
        }
    }
    tracing::info!("all connections drained");
}

async fn handle_client(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    ctx: &ServerContext,
) -> Result<(), crate::error::ServerError> {
    tracing::debug!(%peer_addr, "new connection");

    crate::net::configure_stream(&stream, &ctx.config.keepalive())?;

    // Run to completion. Graceful shutdown is handled by the accept loop
    // halting and the JoinSet drain bounding in-flight connections — not by
    // abandoning a relay mid-flight.
    connection::handle_connection(&mut stream, peer_addr, ctx).await
}

/// Run the SOCKS proxy server in tunnel mode.
///
/// Starts both the SOCKS listener (for external users) and the tunnel listener
/// (for internal clients). SOCKS requests are routed through tunnel clients.
pub async fn run_server(
    config: Config,
    tunnel_listen_addr: String,
    secret: String,
    shutdown: CancellationToken,
) -> Result<(), crate::error::ServerError> {
    check_fd_limit().ok();

    let router = Arc::new(Router::new());

    // Build auth provider
    let auth: Option<Arc<dyn AuthProvider>> = match &config.auth {
        AuthConfig::None => None,
        AuthConfig::Password(users) => {
            Some(Arc::new(crate::auth::password::PasswordAuth::new(users.clone())))
        }
    };

    let ctx = Arc::new(ServerContext {
        ip_limiter: PerIpLimiter::new(config.max_connections_per_ip),
        config: config.clone(),
        metrics: Metrics::default(),
        extended_metrics: ExtendedMetrics::new(),
        auth,
        router: Some(router.clone()),
    });

    // Spawn monitor dashboard if configured
    if ctx.config.monitor_addr.is_some() {
        let ctx_mon = ctx.clone();
        let cancel_mon = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = monitor::run_monitor(ctx_mon, cancel_mon).await {
                tracing::error!(error = %e, "monitor server failed");
            }
        });
    }

    spawn_traffic_sampler(ctx.clone(), shutdown.clone());

    // Start tunnel listener. It runs on its own cancellation token so it can
    // outlive the SOCKS-connection drain during shutdown.
    let tunnel_cancel = CancellationToken::new();
    let listener_cancel = tunnel_cancel.clone();
    let tunnel_router = router.clone();
    let tunnel_max_streams = config.tunnel_max_streams;
    let tunnel_recv_window_mb = config.tunnel_recv_window_mb;
    let mut tunnel_handle = tokio::spawn(async move {
        if let Err(e) = tunnel_listener::run_tunnel_listener(
            &tunnel_listen_addr,
            &secret,
            tunnel_router,
            listener_cancel,
            tunnel_max_streams,
            tunnel_recv_window_mb,
        )
        .await
        {
            tracing::error!(error = %e, "tunnel listener failed");
        }
    });

    // Start SOCKS listener (reuse the same accept loop as standalone)
    let listener = TcpListener::bind(config.listen_addr).await?;
    tracing::info!(socks = %config.listen_addr, "SOCKS proxy listening (tunnel mode)");

    let limiter = Arc::new(Semaphore::new(config.max_connections));

    // Accept, then drain in-flight SOCKS connections (bounded by
    // drain_timeout) before stopping the tunnel — relays keep their tunnel
    // sessions alive while they finish.
    serve_socks(&listener, &ctx, &limiter, &shutdown).await;

    // SOCKS connections drained — now stop the tunnel sessions.
    // The listener gets a moment to close its sessions cleanly (GoAway) so
    // clients reconnect promptly instead of waiting out a dead socket.
    tunnel_cancel.cancel();
    if tokio::time::timeout(crate::tunnel::CLOSE_TIMEOUT * 2, &mut tunnel_handle)
        .await
        .is_err()
    {
        tunnel_handle.abort();
    }

    let snap = ctx.metrics.snapshot();
    tracing::info!(%snap, "server stopped");

    Ok(())
}

/// Spawn a background task that samples traffic every 5 seconds for the chart.
fn spawn_traffic_sampler(ctx: Arc<ServerContext>, cancel: CancellationToken) {
    tokio::spawn(async move {
        const SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
        let mut interval = tokio::time::interval(SAMPLE_INTERVAL);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    let snap = ctx.metrics.snapshot();
                    ctx.extended_metrics.sample_traffic(
                        snap.bytes_client_to_target,
                        snap.bytes_target_to_client,
                    );
                    ctx.extended_metrics
                        .sample_connection_rate(snap.total_connections, SAMPLE_INTERVAL);
                }
            }
        }
    });
}

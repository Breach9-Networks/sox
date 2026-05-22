pub mod connection;
pub mod extended_metrics;
pub mod limits;
pub mod metrics;
pub mod monitor;
pub mod tunnel_listener;

use std::net::SocketAddr;
use std::sync::Arc;

use socket2::SockRef;
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

    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;

            _ = shutdown.cancelled() => {
                let snap = ctx.metrics.snapshot();
                tracing::info!(
                    active = snap.active_connections,
                    "shutdown signal received, draining connections..."
                );
                break;
            }

            result = listener.accept() => {
                let (stream, peer_addr) = result?;

                // Global connection limit
                let permit = match limiter.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(%peer_addr, "global connection limit reached");
                        drop(stream);
                        continue;
                    }
                };

                // Per-IP connection limit
                let ip_guard = match ctx.ip_limiter.try_acquire(peer_addr.ip()) {
                    Some(guard) => guard,
                    None => {
                        tracing::warn!(%peer_addr, "per-IP connection limit reached");
                        drop(stream);
                        continue;
                    }
                };

                let ctx = ctx.clone();
                let shutdown = shutdown.clone();

                tasks.spawn(async move {
                    let _permit = permit;
                    let _ip_guard = ip_guard;
                    let _conn = ctx.metrics.connection_opened();
                    ctx.extended_metrics.record_connection();
                    ctx.extended_metrics.record_ip_connect(peer_addr.ip());

                    let active = ctx.metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed);
                    ctx.extended_metrics.update_peak(active);

                    let (authed_user, result) = handle_client(stream, peer_addr, &ctx, shutdown).await;

                    if let Some(ref user) = authed_user {
                        ctx.extended_metrics.record_user_connect(user);
                    }
                    if let Err(e) = result {
                        tracing::debug!(%peer_addr, error = %e, "connection ended with error");
                    }
                    if let Some(ref user) = authed_user {
                        ctx.extended_metrics.record_user_disconnect(user);
                    }

                    ctx.extended_metrics.record_ip_disconnect(peer_addr.ip());
                    // active count is decremented by the `_conn` guard on drop.
                });
            }
        }
    }

    // Drain active connections with timeout
    let drain_deadline = tokio::time::sleep(ctx.config.drain_timeout);
    tokio::pin!(drain_deadline);

    loop {
        if tasks.is_empty() {
            tracing::info!("all connections drained");
            break;
        }

        tokio::select! {
            _ = tasks.join_next() => {}
            _ = &mut drain_deadline => {
                let remaining = tasks.len();
                tracing::warn!(remaining, "drain timeout, aborting remaining connections");
                tasks.abort_all();
                break;
            }
        }
    }

    let snap = ctx.metrics.snapshot();
    tracing::info!(%snap, "server stopped");

    Ok(())
}

async fn handle_client(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    ctx: &ServerContext,
    shutdown: CancellationToken,
) -> (Option<String>, Result<(), crate::error::ServerError>) {
    tracing::debug!(%peer_addr, "new connection");

    // Apply TCP_NODELAY + keepalive via socket2
    if let Err(e) = configure_socket(&stream, &ctx.config) {
        return (None, Err(crate::error::ServerError::Io(e)));
    }

    let mut stream = stream;

    let (authed_user, result) = tokio::select! {
        biased;
        _ = shutdown.cancelled() => {
            tracing::debug!(%peer_addr, "connection cancelled by shutdown");
            (None, Ok(()))
        }
        result = connection::handle_connection(&mut stream, peer_addr, ctx) => {
            result
        }
    };

    // Return the authenticated username for the caller to track
    if let Some(ref user) = authed_user {
        tracing::trace!(%peer_addr, %user, "authenticated session ended");
    }

    (authed_user, result)
}

/// Configure TCP socket options: NODELAY + keepalive.
fn configure_socket(
    stream: &tokio::net::TcpStream,
    config: &Config,
) -> Result<(), std::io::Error> {
    let sock_ref = SockRef::from(stream);

    // Disable Nagle's algorithm for lower latency
    sock_ref.set_nodelay(true)?;

    // Enable TCP keepalive for dead connection detection
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(config.tcp_keepalive_idle)
        .with_interval(config.tcp_keepalive_interval);

    // Note: with_retries() is not available on all platforms (macOS, musl)
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    let keepalive = keepalive.with_retries(config.tcp_keepalive_probes);

    sock_ref.set_tcp_keepalive(&keepalive)?;

    Ok(())
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

    // Start tunnel listener
    let tunnel_cancel = shutdown.clone();
    let tunnel_router = router.clone();
    let tunnel_max_streams = config.tunnel_max_streams;
    let tunnel_recv_window_mb = config.tunnel_recv_window_mb;
    let tunnel_handle = tokio::spawn(async move {
        if let Err(e) = tunnel_listener::run_tunnel_listener(
            &tunnel_listen_addr,
            &secret,
            tunnel_router,
            tunnel_cancel,
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
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            result = listener.accept() => {
                let (stream, peer_addr) = result?;

                let permit = match limiter.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => { drop(stream); continue; }
                };
                let ip_guard = match ctx.ip_limiter.try_acquire(peer_addr.ip()) {
                    Some(g) => g,
                    None => { drop(stream); continue; }
                };

                let ctx = ctx.clone();
                let shutdown = shutdown.clone();

                tasks.spawn(async move {
                    let _permit = permit;
                    let _ip_guard = ip_guard;
                    let _conn = ctx.metrics.connection_opened();
                    ctx.extended_metrics.record_connection();
                    ctx.extended_metrics.record_ip_connect(peer_addr.ip());

                    let active = ctx.metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed);
                    ctx.extended_metrics.update_peak(active);

                    let (authed_user, result) = handle_client(stream, peer_addr, &ctx, shutdown).await;

                    if let Some(ref user) = authed_user {
                        ctx.extended_metrics.record_user_connect(user);
                    }
                    if let Err(e) = result {
                        tracing::debug!(%peer_addr, error = %e, "connection ended with error");
                    }
                    if let Some(ref user) = authed_user {
                        ctx.extended_metrics.record_user_disconnect(user);
                    }

                    ctx.extended_metrics.record_ip_disconnect(peer_addr.ip());
                    // active count is decremented by the `_conn` guard on drop.
                });
            }
        }
    }

    tunnel_handle.abort();

    let snap = ctx.metrics.snapshot();
    tracing::info!(%snap, "server stopped");

    Ok(())
}

/// Spawn a background task that samples traffic every 5 seconds for the chart.
fn spawn_traffic_sampler(ctx: Arc<ServerContext>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
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
                }
            }
        }
    });
}

//! Embedded HTTP monitor server for the dashboard.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::config::AuthConfig;
use crate::server::ServerContext;

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Concurrent dashboard requests. The dashboard is a diagnostic aid — it must
/// never be able to take fds or memory from the proxy itself.
const MAX_MONITOR_CONNECTIONS: usize = 64;

/// Run the monitor HTTP server.
pub async fn run_monitor(
    ctx: Arc<ServerContext>,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let addr = match ctx.config.monitor_addr {
        Some(addr) => addr,
        None => return Ok(()),
    };

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "monitor dashboard listening");

    let limiter = Arc::new(Semaphore::new(MAX_MONITOR_CONNECTIONS));

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = listener.accept() => {
                let mut stream = match result {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        // A failed accept (e.g. fd exhaustion) must not end
                        // the dashboard for good.
                        tracing::debug!(error = %e, "monitor accept failed, backing off");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = limiter.clone().try_acquire_owned() else {
                    continue; // over the cap — drop the connection
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        handle_http(&mut stream, &ctx),
                    ).await;
                    match result {
                        Ok(Err(e)) => tracing::trace!(error = %e, "monitor HTTP error"),
                        Err(_) => tracing::trace!("monitor HTTP handler timed out"),
                        Ok(Ok(())) => {}
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_http(
    stream: &mut tokio::net::TcpStream,
    ctx: &ServerContext,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;

    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let full_path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    // Parse path and query string
    let (path, query) = match full_path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (full_path, ""),
    };

    // Parse window parameter from query string
    let window_secs = parse_query_param(query, "window").unwrap_or(300);

    match path {
        "/" => serve_html(stream, DASHBOARD_HTML).await,
        "/api/status" => serve_json(stream, &build_full_status(ctx, window_secs)).await,
        "/api/metrics" => serve_json(stream, &build_metrics(ctx)).await,
        "/api/clients" => serve_json(stream, &build_clients(ctx)).await,
        _ => serve_404(stream).await,
    }
}

fn parse_query_param(query: &str, key: &str) -> Option<u64> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key { v.parse().ok() } else { None }
    })
}

async fn serve_html(stream: &mut tokio::net::TcpStream, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await
}

async fn serve_json<T: Serialize>(
    stream: &mut tokio::net::TcpStream,
    data: &T,
) -> std::io::Result<()> {
    let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await
}

async fn serve_404(stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    let body = "404 Not Found";
    let response = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await
}

// ── API response builders ──

#[derive(Serialize)]
struct FullStatus {
    server: ServerInfo,
    connections: ConnectionInfo,
    users: UsersInfo,
    traffic: TrafficInfo,
    errors: ErrorInfo,
    rate: RateInfo,
    top_ips: Vec<crate::server::extended_metrics::IpCount>,
    clients: Vec<crate::tunnel::router::ClientSnapshot>,
    traffic_history: crate::server::extended_metrics::TrafficHistorySnapshot,
}

#[derive(Serialize)]
struct ServerInfo {
    mode: &'static str,
    version: &'static str,
    listen_addr: String,
    uptime_secs: u64,
    auth_enabled: bool,
    max_connections: usize,
    max_connections_per_ip: usize,
}

#[derive(Serialize)]
struct ConnectionInfo {
    active: u64,
    total: u64,
    peak: u64,
}

#[derive(Serialize)]
struct TrafficInfo {
    tx_bytes: u64,
    rx_bytes: u64,
    tx_rate_bps: u64,
    rx_rate_bps: u64,
}

#[derive(Serialize)]
struct ErrorInfo {
    connection_failed: u64,
    dns_timeout: u64,
    auth_rejected: u64,
    relay_error: u64,
}

#[derive(Serialize)]
struct RateInfo {
    connections_per_sec: f64,
}

#[derive(Serialize)]
struct UsersInfo {
    count: usize,
    authenticated: bool,
}

#[derive(Serialize)]
struct MetricsCompact {
    active_connections: u64,
    total_connections: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

fn build_full_status(ctx: &ServerContext, window_secs: u64) -> FullStatus {
    let snap = ctx.metrics.snapshot();
    let ext = &ctx.extended_metrics;

    let mode = if ctx.router.is_some() {
        "server"
    } else {
        "standalone"
    };

    let (tx_rate, rx_rate) = ext.current_rates();

    let clients = build_clients(ctx);

    FullStatus {
        server: ServerInfo {
            mode,
            version: env!("CARGO_PKG_VERSION"),
            listen_addr: ctx.config.listen_addr.to_string(),
            uptime_secs: ext.start_time.elapsed().as_secs(),
            auth_enabled: !matches!(ctx.config.auth, AuthConfig::None),
            max_connections: ctx.config.max_connections,
            max_connections_per_ip: ctx.config.max_connections_per_ip,
        },
        connections: ConnectionInfo {
            active: snap.active_connections,
            total: snap.total_connections,
            peak: ext.peak_connections.load(Ordering::Relaxed),
        },
        users: UsersInfo {
            count: ext.active_user_count(),
            authenticated: !matches!(ctx.config.auth, AuthConfig::None),
        },
        traffic: TrafficInfo {
            tx_bytes: snap.bytes_client_to_target,
            rx_bytes: snap.bytes_target_to_client,
            tx_rate_bps: tx_rate,
            rx_rate_bps: rx_rate,
        },
        errors: ErrorInfo {
            connection_failed: ext.errors_connection_failed.load(Ordering::Relaxed),
            dns_timeout: ext.errors_dns_timeout.load(Ordering::Relaxed),
            auth_rejected: ext.errors_auth_rejected.load(Ordering::Relaxed),
            relay_error: ext.errors_relay.load(Ordering::Relaxed),
        },
        rate: RateInfo {
            connections_per_sec: ext.connections_per_sec(),
        },
        top_ips: ctx.ip_limiter.top(5),
        clients,
        traffic_history: ext.get_traffic_history(window_secs),
    }
}

fn build_metrics(ctx: &ServerContext) -> MetricsCompact {
    let snap = ctx.metrics.snapshot();
    MetricsCompact {
        active_connections: snap.active_connections,
        total_connections: snap.total_connections,
        tx_bytes: snap.bytes_client_to_target,
        rx_bytes: snap.bytes_target_to_client,
    }
}

fn build_clients(ctx: &ServerContext) -> Vec<crate::tunnel::router::ClientSnapshot> {
    ctx.router
        .as_ref()
        .map(|router| router.client_snapshots())
        .unwrap_or_default()
}

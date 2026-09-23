use tokio_util::sync::CancellationToken;

/// Set up cross-platform shutdown signal handling.
///
/// The first signal cancels `token`, which starts the graceful drain. A
/// **second** signal exits immediately — the escape hatch when a drain is
/// taking longer than the operator is willing to wait.
///
/// - Unix: SIGINT (Ctrl+C) and SIGTERM.
/// - Windows: Ctrl+C, Ctrl+Break, console close and system shutdown — a
///   service stop or a closed console window must drain too, not just Ctrl+C.
pub async fn shutdown_signal(token: CancellationToken) {
    wait_for_signal().await;
    token.cancel();

    wait_for_signal().await;
    tracing::warn!("second signal received, exiting without waiting for the drain");
    std::process::exit(130);
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
    tokio::select! {
        _ = sigint.recv() => tracing::info!("received SIGINT"),
        _ = sigterm.recv() => tracing::info!("received SIGTERM"),
    }
}

#[cfg(windows)]
async fn wait_for_signal() {
    use tokio::signal::windows;

    let mut ctrl_c = windows::ctrl_c().expect("failed to install Ctrl+C handler");
    let mut ctrl_break = windows::ctrl_break().expect("failed to install Ctrl+Break handler");
    let mut ctrl_close = windows::ctrl_close().expect("failed to install close handler");
    let mut ctrl_shutdown = windows::ctrl_shutdown().expect("failed to install shutdown handler");
    tokio::select! {
        _ = ctrl_c.recv() => tracing::info!("received Ctrl+C"),
        _ = ctrl_break.recv() => tracing::info!("received Ctrl+Break"),
        _ = ctrl_close.recv() => tracing::info!("console closing"),
        _ = ctrl_shutdown.recv() => tracing::info!("system shutting down"),
    }
}

#[cfg(not(any(unix, windows)))]
async fn wait_for_signal() {
    tokio::signal::ctrl_c().await.expect("failed to listen for Ctrl+C");
    tracing::info!("received Ctrl+C");
}

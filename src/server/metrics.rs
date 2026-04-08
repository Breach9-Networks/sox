use std::sync::atomic::{AtomicU64, Ordering};

/// Server-wide metrics using atomic counters.
///
/// `bytes_client_to_target` and `bytes_target_to_client` are updated
/// **live** during relay (not just at the end), so the traffic sampler
/// can observe bandwidth in real-time.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Currently active connections.
    pub active_connections: AtomicU64,
    /// Total connections accepted since server start.
    pub total_connections: AtomicU64,
    /// Total bytes sent from clients to targets (updated live during relay).
    pub bytes_client_to_target: AtomicU64,
    /// Total bytes sent from targets to clients (updated live during relay).
    pub bytes_target_to_client: AtomicU64,
}

impl Metrics {
    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_relay(&self, client_to_target: u64, target_to_client: u64) {
        self.bytes_client_to_target
            .fetch_add(client_to_target, Ordering::Relaxed);
        self.bytes_target_to_client
            .fetch_add(target_to_client, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            bytes_client_to_target: self.bytes_client_to_target.load(Ordering::Relaxed),
            bytes_target_to_client: self.bytes_target_to_client.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_client_to_target: u64,
    pub bytes_target_to_client: u64,
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "active={}, total={}, tx={}, rx={}",
            self.active_connections,
            self.total_connections,
            format_bytes(self.bytes_client_to_target),
            format_bytes(self.bytes_target_to_client),
        )
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes}B")
    }
}

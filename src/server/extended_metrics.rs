use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;

/// Extended metrics for the monitor dashboard.
pub struct ExtendedMetrics {
    // Peak connections
    pub peak_connections: AtomicU64,

    // Error counters
    pub errors_connection_failed: AtomicU64,
    pub errors_dns_timeout: AtomicU64,
    pub errors_auth_rejected: AtomicU64,
    pub errors_relay: AtomicU64,

    // Uptime
    pub start_time: Instant,

    // Connection rate, in milli-connections/sec, derived by the periodic
    // sampler from the `total_connections` counter — the accept path itself
    // takes no lock for it.
    conn_rate_milli: AtomicU64,
    prev_total_conns: AtomicU64,

    // Traffic history (ring buffer for chart)
    traffic_history: Mutex<TrafficHistory>,

    // Authenticated user tracking
    active_users: Mutex<HashMap<String, u64>>,

    // Previous byte counts for rate calculation
    prev_tx: AtomicU64,
    prev_rx: AtomicU64,
}

impl Default for ExtendedMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtendedMetrics {
    pub fn new() -> Self {
        Self {
            peak_connections: AtomicU64::new(0),
            errors_connection_failed: AtomicU64::new(0),
            errors_dns_timeout: AtomicU64::new(0),
            errors_auth_rejected: AtomicU64::new(0),
            errors_relay: AtomicU64::new(0),
            start_time: Instant::now(),
            conn_rate_milli: AtomicU64::new(0),
            prev_total_conns: AtomicU64::new(0),
            traffic_history: Mutex::new(TrafficHistory::new(720)),
            active_users: Mutex::new(HashMap::new()),
            prev_tx: AtomicU64::new(0),
            prev_rx: AtomicU64::new(0),
        }
    }

    /// Update peak connections if current exceeds previous peak.
    pub fn update_peak(&self, current: u64) {
        self.peak_connections.fetch_max(current, Ordering::Relaxed);
    }

    /// Update the connection rate from the cumulative connection count
    /// (called periodically by the background sampler).
    pub fn sample_connection_rate(&self, total_connections: u64, interval: std::time::Duration) {
        let prev = self.prev_total_conns.swap(total_connections, Ordering::Relaxed);
        let delta = total_connections.saturating_sub(prev);
        let millis = interval.as_millis().max(1) as u64;
        self.conn_rate_milli
            .store(delta.saturating_mul(1_000_000) / millis, Ordering::Relaxed);
    }

    /// Get connections per second (over the last sampling interval).
    pub fn connections_per_sec(&self) -> f64 {
        self.conn_rate_milli.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Record a traffic sample (called periodically by background task).
    pub fn sample_traffic(&self, total_tx: u64, total_rx: u64) {
        let prev_tx = self.prev_tx.swap(total_tx, Ordering::Relaxed);
        let prev_rx = self.prev_rx.swap(total_rx, Ordering::Relaxed);

        let delta_tx = total_tx.saturating_sub(prev_tx);
        let delta_rx = total_rx.saturating_sub(prev_rx);

        if let Ok(mut th) = self.traffic_history.lock() {
            th.push(delta_tx, delta_rx);
        }
    }

    /// Get traffic history for a given window (in seconds).
    pub fn get_traffic_history(&self, window_secs: u64) -> TrafficHistorySnapshot {
        self.traffic_history
            .lock()
            .map(|mut th| th.snapshot(window_secs))
            .unwrap_or_default()
    }

    /// Track an authenticated user's connection for as long as the returned
    /// guard lives — so the active-user count covers the whole session, not
    /// just the instant it ends.
    #[must_use]
    pub fn user_session(&self, username: &str) -> UserSessionGuard<'_> {
        self.record_user_connect(username);
        UserSessionGuard {
            metrics: self,
            username: username.to_string(),
        }
    }

    /// Record an authenticated user connection.
    pub fn record_user_connect(&self, username: &str) {
        if let Ok(mut users) = self.active_users.lock() {
            *users.entry(username.to_string()).or_insert(0) += 1;
        }
    }

    /// Record an authenticated user disconnection.
    pub fn record_user_disconnect(&self, username: &str) {
        if let Ok(mut users) = self.active_users.lock()
            && let Some(count) = users.get_mut(username) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    users.remove(username);
                }
            }
    }

    /// Get count of unique authenticated users with active connections.
    pub fn active_user_count(&self) -> usize {
        self.active_users
            .lock()
            .map(|u| u.len())
            .unwrap_or(0)
    }

    /// Current TX/RX rate in bytes per second (based on last two samples).
    pub fn current_rates(&self) -> (u64, u64) {
        self.traffic_history
            .lock()
            .map(|th| th.current_rates())
            .unwrap_or((0, 0))
    }
}

/// Removes the user's connection from the active set on drop.
pub struct UserSessionGuard<'a> {
    metrics: &'a ExtendedMetrics,
    username: String,
}

impl Drop for UserSessionGuard<'_> {
    fn drop(&mut self) {
        self.metrics.record_user_disconnect(&self.username);
    }
}

// ── Traffic History ──

struct TrafficSample {
    tx_bytes: u64,
    rx_bytes: u64,
}

struct TrafficHistory {
    samples: std::collections::VecDeque<TrafficSample>,
    max_samples: usize,
    sample_interval_secs: u64,
}

impl TrafficHistory {
    fn new(max_samples: usize) -> Self {
        Self {
            samples: std::collections::VecDeque::new(),
            max_samples,
            sample_interval_secs: 5,
        }
    }

    fn push(&mut self, tx_bytes: u64, rx_bytes: u64) {
        self.samples.push_back(TrafficSample { tx_bytes, rx_bytes });
        while self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
    }

    fn snapshot(&mut self, window_secs: u64) -> TrafficHistorySnapshot {
        let num_samples = (window_secs / self.sample_interval_secs) as usize;
        let available = self.samples.len().min(num_samples);
        let start = self.samples.len().saturating_sub(available);
        let slice = &self.samples.make_contiguous()[start..];

        // Return only actual data (no zero padding).
        // Frontend adapts chart to whatever data length it gets.
        TrafficHistorySnapshot {
            interval_secs: self.sample_interval_secs,
            tx: slice.iter().map(|s| s.tx_bytes).collect(),
            rx: slice.iter().map(|s| s.rx_bytes).collect(),
        }
    }

    fn current_rates(&self) -> (u64, u64) {
        // Average of last 3 samples for smoother rate display
        let n = self.samples.len().min(3);
        if n == 0 {
            return (0, 0);
        }
        let start = self.samples.len() - n;
        let (tx_sum, rx_sum) = self.samples.iter().skip(start).fold((0u64, 0u64), |(tx, rx), s| {
            (tx + s.tx_bytes, rx + s.rx_bytes)
        });
        let window_secs = (n as u64) * self.sample_interval_secs.max(1);
        (tx_sum / window_secs, rx_sum / window_secs)
    }
}

#[derive(Debug, Default, Serialize)]
pub struct TrafficHistorySnapshot {
    pub interval_secs: u64,
    pub tx: Vec<u64>,
    pub rx: Vec<u64>,
}

// ── Per-IP counts (produced by `PerIpLimiter::top`) ──

#[derive(Debug, Serialize)]
pub struct IpCount {
    pub ip: String,
    pub connections: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peak_connections() {
        let m = ExtendedMetrics::new();
        m.update_peak(5);
        assert_eq!(m.peak_connections.load(Ordering::Relaxed), 5);
        m.update_peak(3);
        assert_eq!(m.peak_connections.load(Ordering::Relaxed), 5);
        m.update_peak(10);
        assert_eq!(m.peak_connections.load(Ordering::Relaxed), 10);
        m.update_peak(0);
        assert_eq!(m.peak_connections.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn test_traffic_history_push_and_snapshot() {
        let mut th = TrafficHistory::new(720);
        // Push 10 samples
        for i in 0..10 {
            th.push(i * 100, i * 50);
        }
        // window=60 => num_samples = 60/5 = 12, but only 10 available
        let snap = th.snapshot(60);
        assert_eq!(snap.tx.len(), 10);
        assert_eq!(snap.rx.len(), 10);
        assert_eq!(snap.interval_secs, 5);
        assert_eq!(snap.tx[0], 0);
        assert_eq!(snap.tx[9], 900);
        assert_eq!(snap.rx[9], 450);

        // window=25 => num_samples = 25/5 = 5, should return last 5
        let snap = th.snapshot(25);
        assert_eq!(snap.tx.len(), 5);
        assert_eq!(snap.tx[0], 500); // sample index 5
    }

    #[test]
    fn test_traffic_history_no_zero_padding() {
        let mut th = TrafficHistory::new(720);
        for i in 0..5 {
            th.push(i * 10, i * 20);
        }
        // window=300 => num_samples = 300/5 = 60, but only 5 samples exist
        let snap = th.snapshot(300);
        assert_eq!(snap.tx.len(), 5);
        assert_eq!(snap.rx.len(), 5);
    }

    #[test]
    fn test_traffic_history_window_limits() {
        let mut th = TrafficHistory::new(720);
        for i in 0..100 {
            th.push(i, i * 2);
        }
        // window=60 => num_samples = 60/5 = 12
        let snap = th.snapshot(60);
        assert_eq!(snap.tx.len(), 12);
        // Should be last 12 samples: 88..99
        assert_eq!(snap.tx[0], 88);
        assert_eq!(snap.tx[11], 99);
    }

    #[test]
    fn test_connection_rate_sampling() {
        let m = ExtendedMetrics::new();
        assert_eq!(m.connections_per_sec(), 0.0);
        m.sample_connection_rate(50, std::time::Duration::from_secs(5));
        assert_eq!(m.connections_per_sec(), 10.0);
        // No new connections in the next interval → rate drops to zero.
        m.sample_connection_rate(50, std::time::Duration::from_secs(5));
        assert_eq!(m.connections_per_sec(), 0.0);
    }

    #[test]
    fn test_user_session_guard_covers_the_session() {
        let m = ExtendedMetrics::new();
        {
            let _alice = m.user_session("alice");
            assert_eq!(m.active_user_count(), 1, "user must count as active during the session");
        }
        assert_eq!(m.active_user_count(), 0);
    }

    #[test]
    fn test_user_tracking() {
        let m = ExtendedMetrics::new();
        assert_eq!(m.active_user_count(), 0);

        m.record_user_connect("alice");
        m.record_user_connect("bob");
        m.record_user_connect("alice");
        assert_eq!(m.active_user_count(), 2);

        m.record_user_disconnect("alice");
        assert_eq!(m.active_user_count(), 2); // alice still has 1 connection

        m.record_user_disconnect("alice");
        assert_eq!(m.active_user_count(), 1); // alice fully disconnected

        m.record_user_disconnect("bob");
        assert_eq!(m.active_user_count(), 0);
    }
}

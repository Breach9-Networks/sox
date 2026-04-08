use std::collections::HashMap;
use std::net::IpAddr;
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

    // Rate tracking
    rate_tracker: Mutex<RateTracker>,

    // Traffic history (ring buffer for chart)
    traffic_history: Mutex<TrafficHistory>,

    // Per-IP tracking
    ip_tracker: Mutex<IpTracker>,

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
            rate_tracker: Mutex::new(RateTracker::new()),
            traffic_history: Mutex::new(TrafficHistory::new(720)),
            active_users: Mutex::new(HashMap::new()),
            ip_tracker: Mutex::new(IpTracker::new()),
            prev_tx: AtomicU64::new(0),
            prev_rx: AtomicU64::new(0),
        }
    }

    /// Update peak connections if current exceeds previous peak.
    pub fn update_peak(&self, current: u64) {
        self.peak_connections.fetch_max(current, Ordering::Relaxed);
    }

    /// Record a new connection for rate tracking.
    pub fn record_connection(&self) {
        if let Ok(mut rt) = self.rate_tracker.lock() {
            rt.record();
        }
    }

    /// Get connections per second.
    pub fn connections_per_sec(&self) -> f64 {
        self.rate_tracker
            .lock()
            .map(|rt| rt.rate())
            .unwrap_or(0.0)
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

    /// Record a connection from an IP.
    pub fn record_ip_connect(&self, ip: IpAddr) {
        if let Ok(mut it) = self.ip_tracker.lock() {
            it.connect(ip);
        }
    }

    /// Record a disconnection from an IP.
    pub fn record_ip_disconnect(&self, ip: IpAddr) {
        if let Ok(mut it) = self.ip_tracker.lock() {
            it.disconnect(ip);
        }
    }

    /// Get top N IPs by active connection count.
    pub fn top_ips(&self, n: usize) -> Vec<IpCount> {
        self.ip_tracker
            .lock()
            .map(|it| it.top(n))
            .unwrap_or_default()
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

// ── Rate Tracker ──

struct RateTracker {
    timestamps: std::collections::VecDeque<Instant>,
    window: std::time::Duration,
}

impl RateTracker {
    fn new() -> Self {
        Self {
            timestamps: std::collections::VecDeque::new(),
            window: std::time::Duration::from_secs(10),
        }
    }

    fn record(&mut self) {
        let now = Instant::now();
        self.timestamps.push_back(now);
        self.cleanup(now);
    }

    fn rate(&self) -> f64 {
        if self.timestamps.is_empty() {
            return 0.0;
        }
        let now = Instant::now();
        let count = self
            .timestamps
            .iter()
            .filter(|t| now.duration_since(**t) < self.window)
            .count();
        count as f64 / self.window.as_secs_f64()
    }

    fn cleanup(&mut self, now: Instant) {
        while let Some(front) = self.timestamps.front() {
            if now.duration_since(*front) > self.window {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
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

// ── IP Tracker ──

struct IpTracker {
    counts: HashMap<IpAddr, u64>,
}

impl IpTracker {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    fn connect(&mut self, ip: IpAddr) {
        *self.counts.entry(ip).or_insert(0) += 1;
    }

    fn disconnect(&mut self, ip: IpAddr) {
        if let Some(count) = self.counts.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.counts.remove(&ip);
            }
        }
    }

    fn top(&self, n: usize) -> Vec<IpCount> {
        let mut sorted: Vec<_> = self
            .counts
            .iter()
            .map(|(ip, count)| IpCount {
                ip: ip.to_string(),
                connections: *count,
            })
            .collect();
        sorted.sort_by(|a, b| b.connections.cmp(&a.connections));
        sorted.truncate(n);
        sorted
    }
}

#[derive(Debug, Serialize)]
pub struct IpCount {
    pub ip: String,
    pub connections: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
    fn test_rate_tracker() {
        let mut rt = RateTracker::new();
        for _ in 0..5 {
            rt.record();
        }
        let rate = rt.rate();
        assert!(rate > 0.0, "rate should be positive after recording connections");
    }

    #[test]
    fn test_ip_tracker() {
        let mut it = IpTracker::new();
        let ip_a: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        it.connect(ip_a);
        it.connect(ip_a);
        it.connect(ip_a);
        it.connect(ip_b);

        let top = it.top(10);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].ip, "10.0.0.1");
        assert_eq!(top[0].connections, 3);
        assert_eq!(top[1].ip, "10.0.0.2");
        assert_eq!(top[1].connections, 1);

        it.disconnect(ip_a);
        let top = it.top(10);
        assert_eq!(top[0].connections, 2);

        // Disconnect all of ip_b — should be removed
        it.disconnect(ip_b);
        let top = it.top(10);
        assert_eq!(top.len(), 1);
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

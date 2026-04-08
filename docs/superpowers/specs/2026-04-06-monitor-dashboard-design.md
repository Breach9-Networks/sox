# socksr Monitor Dashboard — Design Spec

## Overview

Embed a lightweight web-based monitoring dashboard into socksr's server/standalone mode. The dashboard provides real-time visibility into proxy health, traffic, tunnel clients, and server configuration through a browser UI backed by JSON API endpoints.

**Trigger**: `--monitor` flag or `monitor` config section enables the dashboard on a configurable HTTP port.

## Architecture

```
Browser (dashboard UI)
    |
    | HTTP GET /api/status, /api/metrics, /api/clients, /api/config
    | HTTP GET / (serves embedded HTML/JS/CSS)
    | Polling every 3 seconds
    |
[socksr HTTP server]  ← lightweight, embedded in existing tokio runtime
    |
    reads from → ServerContext.metrics (AtomicU64, lock-free)
    reads from → ServerContext.router (tunnel client registry)
    reads from → ServerContext.config (server configuration)
    reads from → ExtendedMetrics (new: errors, rates, per-IP counts)
```

### Key Decisions

- **No new dependencies for HTTP**: Use raw `tokio::net::TcpListener` + manual HTTP/1.1 response construction. The dashboard serves ~5 endpoints and static assets — a full framework (axum/warp) is overkill and adds binary size.
- **Frontend embedded in binary**: Single HTML file with inline CSS/JS, compiled into the binary via `include_str!()`. Zero external files needed at runtime.
- **Polling at 3s**: Frontend fetches `/api/status` every 3 seconds. Simple, no WebSocket dependency.
- **Read-only**: Dashboard is purely observational. No configuration changes through the UI.

## API Endpoints

### `GET /` — Dashboard HTML

Returns the embedded single-page HTML/JS/CSS dashboard. Content-Type: `text/html`.

### `GET /api/status` — Full status snapshot

Returns all dashboard data in one response (reduces round trips for polling).

```json
{
  "server": {
    "mode": "server",
    "version": "0.1.0",
    "listen_addr": "0.0.0.0:1080",
    "tunnel_addr": "0.0.0.0:9090",
    "uptime_secs": 302400,
    "auth_enabled": true,
    "max_connections": 10000,
    "max_connections_per_ip": 100
  },
  "connections": {
    "active": 42,
    "total": 12847,
    "peak": 128
  },
  "traffic": {
    "tx_bytes": 1330000000,
    "rx_bytes": 4090000000,
    "tx_rate_bps": 13000000,
    "rx_rate_bps": 37300000
  },
  "errors": {
    "connection_failed": 23,
    "dns_timeout": 5,
    "auth_rejected": 12,
    "relay_error": 3
  },
  "rate": {
    "connections_per_sec": 2.4
  },
  "top_ips": [
    { "ip": "192.168.1.100", "connections": 15 },
    { "ip": "10.0.0.42", "connections": 8 }
  ],
  "clients": [
    {
      "client_id": "office-node",
      "status": "online",
      "pool_size": 10,
      "pool_ready": 8,
      "tx_bytes": 1330000000,
      "rx_bytes": 4090000000,
      "connected_since": "2026-04-03T08:21:00Z"
    }
  ],
  "traffic_history": {
    "interval_secs": 5,
    "tx": [120000, 145000, 132000, ...],
    "rx": [340000, 310000, 355000, ...]
  }
}
```

### `GET /api/metrics` — Minimal metrics only

Lightweight endpoint for external monitoring tools (Prometheus-style scraping).

```json
{
  "active_connections": 42,
  "total_connections": 12847,
  "tx_bytes": 1330000000,
  "rx_bytes": 4090000000
}
```

### `GET /api/clients` — Tunnel clients only

```json
[
  {
    "client_id": "office-node",
    "status": "online",
    "pool_size": 10,
    "pool_ready": 8,
    "tx_bytes": 1330000000,
    "rx_bytes": 4090000000,
    "connected_since": "2026-04-03T08:21:00Z"
  }
]
```

## Extended Metrics

Current `Metrics` struct only tracks connections and bytes. New `ExtendedMetrics` adds:

```rust
pub struct ExtendedMetrics {
    // Existing (in Metrics)
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub peak_connections: AtomicU64,       // NEW
    pub bytes_client_to_target: AtomicU64,
    pub bytes_target_to_client: AtomicU64,

    // Error counters
    pub errors_connection_failed: AtomicU64,  // NEW
    pub errors_dns_timeout: AtomicU64,        // NEW
    pub errors_auth_rejected: AtomicU64,      // NEW
    pub errors_relay: AtomicU64,              // NEW

    // Rate tracking
    pub start_time: Instant,                   // NEW: for uptime
    pub rate_tracker: RateTracker,             // NEW: connections/sec

    // Per-IP tracking (top N)
    pub ip_tracker: IpTracker,                 // NEW: top IPs by connection count

    // Traffic history (ring buffer for chart)
    pub traffic_history: TrafficHistory,        // NEW: time-series for chart
}
```

### Traffic History

Ring buffer storing traffic samples for the chart. Sampled every 5 seconds, keeps last 720 samples (1 hour).

```rust
pub struct TrafficHistory {
    samples: Mutex<VecDeque<TrafficSample>>,
    max_samples: usize,  // 720 = 1 hour at 5s intervals
}

pub struct TrafficSample {
    pub timestamp: Instant,
    pub tx_bytes: u64,  // bytes since last sample
    pub rx_bytes: u64,
}
```

Frontend requests a time window (5m/15m/30m/1h) and the API returns the corresponding slice of the history.

### Rate Tracker

Sliding window counter for connections/second.

```rust
pub struct RateTracker {
    window: Mutex<VecDeque<Instant>>,  // timestamps of recent connections
}
```

### IP Tracker

Tracks top source IPs by active connection count. Uses the existing `PerIpLimiter` data — extend it to expose counts.

## Frontend Design

### Visual Style: Cyber Dashboard (Dark)

- Background: linear-gradient `#0f172a` → `#1e293b`
- Font: monospace (SF Mono / Cascadia Code / Consolas)
- Cards: semi-transparent with subtle borders, large numbers
- Chart: SVG polyline with gradient fill, TX (blue) / RX (green)
- Architecture diagram: colored nodes with connection arrows

### Layout (top to bottom)

1. **Header**: `socksr monitor` logo + server mode badge + health status dot
2. **Status cards** (4 columns): Active Connections / Throughput / Tunnel Clients / Uptime
3. **Two-column row**:
   - Left: Real-time traffic chart with time slot switcher (5m / 15m / 30m / 1h)
   - Right: Architecture topology diagram (Users → Server → Clients → Internal)
4. **Two-column row**:
   - Left: Error statistics panel (counters for each error type)
   - Right: Connection rate chart + Top IPs list
5. **Full-width row**: Tunnel clients table (status, ID, pool bar, TX/RX, latency, connected since)
6. **Footer**: version + API endpoints + refresh interval

### Traffic Chart Time Slots

Buttons: `5m` `15m` `30m` `1h` — clicking a button filters `traffic_history` to that window. Default: 5 minutes.

Frontend JS calculates which samples to display based on the selected window and redraws the SVG polyline.

## Configuration

### CLI

```bash
# Enable monitor on standalone
socksr standalone --monitor 0.0.0.0:8080

# Enable monitor on server mode
socksr server --socks-listen :1080 --tunnel-listen :9090 --secret key --monitor :8080
```

### TOML

```toml
[monitor]
listen = "0.0.0.0:8080"
```

### Config struct addition

```rust
pub struct Config {
    // ...existing fields...
    pub monitor_addr: Option<SocketAddr>,  // None = disabled
}
```

## Files to Create / Modify

### New files
- `src/server/monitor.rs` — HTTP server, API handlers, static file serving
- `src/server/extended_metrics.rs` — ExtendedMetrics, TrafficHistory, RateTracker, IpTracker
- `src/server/dashboard.html` — Single-page dashboard (embedded via `include_str!`)

### Modified files
- `src/server/mod.rs` — spawn monitor HTTP server alongside SOCKS listener
- `src/server/connection.rs` — record error metrics, update IP tracker
- `src/server/metrics.rs` — add peak_connections tracking
- `src/config.rs` — add `monitor_addr: Option<SocketAddr>`
- `src/main.rs` — add `--monitor` CLI flag to standalone and server subcommands
- `src/tunnel/router.rs` — expose per-client metrics (tx/rx bytes, connected_since)

## Verification

1. `cargo build` — compiles with zero warnings
2. `cargo test` — all existing + new tests pass
3. `cargo clippy` — zero warnings
4. Manual test: start socksr with `--monitor :8080`, open `http://localhost:8080`, verify:
   - Status cards show live data
   - Traffic chart updates every 3s
   - Time slot buttons switch chart window
   - Architecture diagram reflects current mode (standalone vs server)
   - Client table shows connected tunnel clients (server mode)
   - Error counters increment on failures
   - Top IPs list shows active source IPs
5. API test: `curl http://localhost:8080/api/status | jq .` returns valid JSON

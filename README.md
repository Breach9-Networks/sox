# sox

[![CI](https://github.com/zet235/sox/actions/workflows/ci.yml/badge.svg)](https://github.com/zet235/sox/actions/workflows/ci.yml)

A high-performance, cross-platform SOCKS proxy server with reverse tunnel support, written in Rust.

## Features

- **SOCKS5** full support (CONNECT, UDP ASSOCIATE, IPv4/IPv6/Domain)
- **SOCKS4/4a** backward compatible
- **Reverse tunnel** - punch through NAT from internal networks
- **Noise Protocol encryption** - lightweight, no certificates needed (same as WireGuard)
- **Monitor Dashboard** - real-time web UI with traffic charts, client topology, and connection stats
- **Username/password authentication** (RFC 1929)
- **Stream multiplexing** - many proxy flows share a few yamux sessions over one Noise handshake
- **Connection stability** - half-open detection (TCP keepalive + tunnel heartbeat/watchdog), true inactivity timeouts, one deadline per handshake, graceful half-close
- **Resource protection** - global + per-IP connection limits, tunnel connection limits, FD limit check, bounded per-association UDP state
- **Auto-reconnect** - tunnel sessions reconnect independently with exponential backoff; stale sessions are evicted on reconnect
- **Graceful shutdown** - both server and client drain in-flight relays with a configurable timeout; a second signal exits immediately
- **Multi-client failover** - requests rotate across tunnel clients and fall through to the next one when a session is dead or wedged
- **Security hardened** - BLAKE2s PSK derivation, constant-time auth, Noise encryption, length-capped wire decoding
- **TOML configuration** - CLI > file > defaults, same precedence in every mode
- **Cross-platform** - Linux (static musl), macOS (ARM), Windows (x64); tests run on all three in CI
- **Lightweight** - ~1.7MB release binary, written in Rust, 103 tests

## Architecture

```
                    Standalone Mode
                    ===============
  User --> SOCKS5/4 --> [sox] --> Target

                    Tunnel Mode
                    ===========
  User --> SOCKS5/4 --> [Server]  <=== Noise encrypted ===>  [Client] --> Internal Target
           (public)      :1080        tunnel :9090           (internal)
                           |                                 8 yamux sessions
                           |
                    Monitor Dashboard
                    =================
                    http://0.0.0.0:8080   (--monitor flag)
```

**Standalone mode**: Traditional SOCKS proxy, connects directly to targets.

**Tunnel mode**: Server runs on public network, Client runs on internal network.
Client connects outward to Server (NAT traversal), then Server routes SOCKS requests
through the encrypted tunnel to Client, which connects to targets on the internal network.
The Client maintains a small set of yamux sessions (default 8) — each one TCP + Noise — and
the Server multiplexes every SOCKS request as an independent yamux stream over them. yamux's
per-stream flow control keeps a slow flow from blocking its co-tenants on the same session.

## Quick Start

### Build

```bash
cargo build --release
# Binary at target/release/sox (~1.7MB)

# Cross-compile for all platforms
./build-cross.sh
# Output in dist/:
#   sox-v0.1.0-macos-arm64
#   sox-v0.1.0-windows-amd64.exe
#   sox-v0.1.0-linux-amd64       (static musl)
```

The release profile is `opt-level = "z"` for the binary as a whole and `3` for the
AEAD/yamux crates only — the tunnel data path is cipher-bound, and this recovers most of
the throughput of a full `-O3` build for ~32 KB of binary. Benchmarks:

```bash
cargo test --release --test tunnel_e2e bench_ -- --ignored --nocapture --test-threads=1
```

### Standalone Proxy

```bash
# Basic - listen on localhost:1080, no auth
sox standalone

# Listen on all interfaces
sox standalone -l 0.0.0.0:1080

# With authentication
sox standalone -u alice:secret -u bob:hunter2

# With TOML config
sox standalone -c config.toml

# Debug logging
sox standalone -v debug
```

Test it:

```bash
curl --proxy socks5h://127.0.0.1:1080 http://httpbin.org/ip
curl --proxy socks5://alice:secret@127.0.0.1:1080 https://example.com
curl --proxy socks4a://127.0.0.1:1080 http://example.com
```

### SOCKS Protocol Variants

sox supports multiple SOCKS protocol variants. When using tools like `curl`, the proxy URL scheme determines which protocol and DNS behavior is used:

| Scheme | Protocol | DNS Resolution | Description |
|--------|----------|---------------|-------------|
| `socks5h://` | SOCKS5 | **Server-side** | Client sends the domain name to the proxy. The proxy resolves DNS and connects. Best for privacy and tunnel mode — the target hostname never leaks on the client's network. |
| `socks5://` | SOCKS5 | **Client-side** | Client resolves DNS locally first, then sends the IP address to the proxy. The proxy only sees an IP, not the hostname. Useful when the client has access to a specific DNS server. |
| `socks4a://` | SOCKS4a | **Server-side** | Legacy protocol with server-side DNS. Like `socks5h` but without IPv6 or authentication support. |
| `socks4://` | SOCKS4 | **Client-side** | Original SOCKS4 protocol. Client resolves DNS locally and sends the IP. IPv4 only, no auth. |

**Which to use?**

- **Tunnel mode**: Always use `socks5h://` — DNS must be resolved on the internal network, not on the user's machine.
- **Privacy**: Use `socks5h://` — prevents DNS leaks on the client side.
- **Standalone mode**: Either `socks5://` or `socks5h://` works. Use `socks5h://` for domain names that only the proxy can resolve.

```bash
# Server-side DNS (recommended for tunnel mode)
curl --proxy socks5h://proxy:1080 http://internal-service.local:8080

# Client-side DNS (client resolves, proxy sees IP only)
curl --proxy socks5://proxy:1080 http://example.com

# SOCKS4a with server-side DNS (legacy)
curl --proxy socks4a://proxy:1080 http://example.com

# SOCKS4 with client-side DNS (legacy, IPv4 only)
curl --proxy socks4://proxy:1080 http://93.184.216.34
```

### Tunnel Mode

On the **public server**:

```bash
sox server \
  --socks-listen 0.0.0.0:1080 \
  --tunnel-listen 0.0.0.0:9090 \
  --secret "your-shared-key" \
  --monitor 0.0.0.0:8080
```

On the **internal machine**:

```bash
sox client \
  --server-addr your-server.com:9090 \
  --secret "your-shared-key" \
  --client-id office-node \
  --tunnel-sessions 8
```

Now, users can proxy through the public server to reach internal resources:

```bash
curl --proxy socks5h://your-server.com:1080 http://internal-service:8080
```

## Monitor Dashboard

Enable the real-time monitor dashboard with the `--monitor` flag:

```bash
sox server --secret "key" --monitor 0.0.0.0:8080
sox standalone --monitor 0.0.0.0:8080
```

The dashboard provides a **Cyber Dark** themed web UI with:

- **Real-time traffic charts** — bytes in/out over 5m, 15m, 30m, and 1h windows
- **Architecture topology** — visual diagram of Server/Client tunnel connections
- **Client table** — connected clients with session count, traffic stats, requests served
- **Error stats** — authentication failures, connection errors, protocol errors
- **Connection rate** — current connections per second
- **Top IPs** — most active source IPs by connection count

### API Endpoints

The monitor also exposes JSON API endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard web UI |
| `GET /api/status` | Full status: server info, connections, traffic (live), errors, rate, top IPs, clients, traffic history |
| `GET /api/status?window=N` | Same, with traffic history for last N seconds (300/900/1800/3600) |
| `GET /api/metrics` | Compact metrics: active connections, total, tx/rx bytes |
| `GET /api/clients` | Tunnel clients: session count, live tx/rx, requests served, uptime |

```bash
# Full status with 5-minute traffic history
curl http://localhost:8080/api/status?window=300 | jq

# Compact metrics for external monitoring
curl http://localhost:8080/api/metrics | jq

# Tunnel client list
curl http://localhost:8080/api/clients | jq
```

Features:
- Embedded single-page HTML via `include_str!()`, zero external files at runtime
- Hand-rolled HTTP/1.1 (no framework dependency)
- 3-second polling interval
- Traffic metrics update live during relay (not just after connection close)
- Per-client traffic tracked via shared atomic counters

> **macOS proxy bypass note**: If you configure macOS to use the SOCKS proxy system-wide
> and the monitor dashboard is on the same machine, add `localhost` and `127.0.0.1` to the
> proxy bypass list in System Settings > Network > Proxies. Otherwise, dashboard requests
> will loop through the SOCKS proxy and fail.

## Configuration

### CLI Options

```
sox standalone [OPTIONS]
  -l, --listen <ADDR>           Listen address [default: 127.0.0.1:1080]
  -c, --config <FILE>           TOML config file
  -u, --user <USER:PASS>        Add credentials (repeatable)
      --max-connections <N>     Max concurrent connections [default: 10000]
      --max-per-ip <N>          Max connections per IP [default: 100]
      --idle-timeout <SECS>     Relay idle timeout [default: 300]
      --monitor <ADDR>          Enable monitor dashboard [e.g. 0.0.0.0:8080]
  -v, --verbosity <LEVEL>       Log level [default: info]

sox server [OPTIONS]
  -s, --socks-listen <ADDR>     SOCKS listen address [default: 0.0.0.0:1080]
  -t, --tunnel-listen <ADDR>    Tunnel listen address [default: 0.0.0.0:9090]
  -c, --config <FILE>           TOML config file
      --secret <SECRET>         Shared secret (or set [tunnel] secret in config)
  -u, --user <USER:PASS>        Add SOCKS auth credentials (repeatable)
      --max-connections <N>     Max concurrent connections [default: 10000]
      --monitor <ADDR>          Enable monitor dashboard [e.g. 0.0.0.0:8080]

sox client [OPTIONS]
  -s, --server-addr <ADDR>      Server tunnel address (or set [tunnel] server_addr in config)
  -c, --config <FILE>           TOML config file
      --secret <SECRET>         Shared secret (or set [tunnel] secret in config)
      --client-id <ID>          Client identifier [default: default]
      --tunnel-sessions <N>     Concurrent yamux sessions [default: 8]
      --reconnect-interval <S>  Reconnect backoff base in seconds [default: 5]
```

Every option that also exists in the TOML file has no built-in CLI default that could
shadow the file: a flag you pass wins, otherwise the file value applies, otherwise the
default shown above.

### TOML Config File

```toml
listen = "0.0.0.0:1080"
max_connections = 10000
max_connections_per_ip = 100
handshake_timeout = 5     # whole SOCKS negotiation, one deadline
connect_timeout = 10      # target dial (all resolved addresses share it)
dns_timeout = 5
idle_timeout = 300        # inactivity in both directions, TCP and UDP
drain_timeout = 30        # in-flight relays get this long on shutdown

[auth]
users = [
  { username = "alice", password = "secret" },
]

[keepalive]
idle = 30
interval = 10
probes = 3

[tunnel]
listen = "0.0.0.0:9090"            # server: tunnel listen address
secret = "your-shared-key"          # shared between server and client
server_addr = "your-server:9090"    # client: where to connect
client_id = "office-node"           # client: identifier
tunnel_sessions = 8                 # client: concurrent yamux sessions
max_streams_per_session = 256       # per-session yamux stream cap
recv_window_mb = 256                # per-session yamux receive window (MiB); keep well above
                                    # max_streams_per_session × 0.25 or single-stream throughput caps
reconnect_interval = 5              # reconnect backoff base (seconds)
reconnect_max = 60                  # reconnect backoff cap (seconds)
```

Config priority: CLI args > TOML file > defaults, in all three modes. The client also
reads the top-level `connect_timeout` / `idle_timeout` / `dns_timeout` / `drain_timeout`
for its side of each proxied flow. An unparsable value (e.g. a bad `listen`) is an error,
not silently ignored.

See [`config.example.toml`](config.example.toml) for a full example.

## How It Works

### Tunnel Protocol

The tunnel is a small set of **yamux-multiplexed sessions** (default 8). Each session is
one TCP connection wrapped in Noise encryption; every SOCKS request becomes an independent
yamux stream multiplexed over a session.

When a SOCKS request arrives at the Server:

```
1. Server receives SOCKS5 CONNECT example.com:80
2. Server opens a new yamux stream on one of the Client's sessions (round-robin)
3. Server writes a StreamOpen preamble { target: "example.com:80" } on the stream
4. Client accepts the stream, connects to example.com:80 on the internal network
5. Client writes a StreamReply { status: ok, bound address }
6. Server replies SOCKS5 success to the user
7. Bidirectional relay over the stream: User <-> Server <--(Noise)--> Client <-> Target
8. When either side closes, the yamux stream closes — no pooling, no reuse dance
```

UDP ASSOCIATE works the same way over a dedicated yamux stream that carries framed
datagrams. yamux provides per-stream credit-based flow control, so a slow or stalled
flow only backs up its own stream, never its co-tenants on the same session.

### Multi-Client Routing

When multiple Clients are connected, the Server rotates across them; within a Client,
new streams are opened round-robin across its sessions. Opening a stream is bounded by
`connect_timeout`: a session that is dead, full, or wedged is skipped and the next
session — or the next Client — is tried, so losing one Client does not lose service.
A Client reconnecting on a session slot it already holds replaces the stale session.

Per-client traffic counters (TX/RX bytes, requests served) are **preserved across
reconnects** — cumulative stats continue from where they left off.

### Encryption

Tunnel connections use **Noise Protocol** (Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s):

- Pre-shared key derived via BLAKE2s (cryptographically secure KDF)
- ChaCha20-Poly1305 authenticated encryption (all relay data encrypted)
- Curve25519 key exchange
- Same cryptographic foundation as WireGuard
- Constant-time password comparison (timing attack resistant)
- Each session performs one Noise handshake; all of its multiplexed streams share that channel

### Stability

- **Custom TCP relay** with explicit half-close handling (avoids [tokio#3876](https://github.com/tokio-rs/tokio/issues/3876))
- **Per-state timeouts**: handshake (5s, one deadline for the whole negotiation), connect (10s, shared across all resolved addresses so a blackholed AAAA cannot eat it), DNS (5s), idle (5min)
- **Idle means idle**: the idle timeout is an inactivity timer for TCP relays and UDP associations alike — an active transfer is never cut
- **Half-open detection, two layers**: OS TCP keepalive on every socket (idle 30s / interval 10s / 3 probes; tunnel sockets tighter) — and, because keepalive does not probe while data is unacknowledged, tunnel sessions also send a heartbeat every 10s and drop the connection after 45s of silence
- **UDP associations** are a single future each: one v4 + one v6 outbound socket, replies accepted only from targets actually sent to, a per-datagram error costs one datagram (not the association), everything released the moment the control connection closes
- **Three-layer connection protection**: global semaphore + per-IP limit + FD limit check; finished connections are reaped continuously, so memory does not grow with connection count
- **Accept-loop resilience**: `accept()` failures (fd exhaustion, aborted connections) back off and continue instead of ending the listener
- **Graceful shutdown**: stop accepting -> drain in-flight relays (server *and* client) -> timeout abort; a second signal exits at once
- **Auto-reconnect**: each tunnel session reconnects independently with exponential backoff (base 5s, cap 60s, ±20% jitter; degenerate values are clamped)
- **Tunnel connection limit**: max 2048 concurrent tunnel sessions to prevent resource exhaustion

## Comparison

| Feature | sox | shinysocks | fast-socks5 | microsocks | merino |
|---------|--------|-----------|-------------|------------|--------|
| Language | Rust | C++ | Rust | C | Rust |
| SOCKS5 CONNECT | Y | Y | Y | Y | Y |
| SOCKS4/4a | Y | Y | - | - | - |
| UDP ASSOCIATE | Y | - | Y | - | - |
| IPv6 | Y | - | Y | Y | ~ |
| Authentication | Y | - | Y | Y | Y |
| Reverse tunnel | Y | - | - | - | - |
| Encrypted tunnel | Y | - | - | - | - |
| Monitor dashboard | Y | - | - | - | - |
| Multi-client routing | Y | - | - | - | - |
| Connection limits | Y | - | - | - | - |
| Graceful shutdown | Y | - | - | - | - |
| Cross-platform | Y | Y | Y | - | Y |
| Auto-reconnect | Y | - | - | - | - |
| Binary size | ~1.7MB | ~2MB | lib | <50KB | ~2MB |

## License

MIT

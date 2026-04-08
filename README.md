# sox

A high-performance, cross-platform SOCKS proxy server with reverse tunnel support, written in Rust.

## Features

- **SOCKS5** full support (CONNECT, UDP ASSOCIATE, IPv4/IPv6/Domain)
- **SOCKS4/4a** backward compatible
- **Reverse tunnel** - punch through NAT from internal networks
- **Noise Protocol encryption** - lightweight, no certificates needed (same as WireGuard)
- **Monitor Dashboard** - real-time web UI with traffic charts, client topology, and connection stats
- **Username/password authentication** (RFC 1929)
- **Connection reuse** - pool connections serve multiple requests without re-handshaking
- **Connection stability** - TCP keepalive, per-state timeouts, graceful half-close
- **Resource protection** - global + per-IP connection limits, tunnel connection limits, FD limit check
- **Auto-reconnect** - client retries for up to 30 minutes on server disconnect
- **Graceful shutdown** - connection draining with configurable timeout
- **Security hardened** - BLAKE2s PSK derivation, constant-time auth, Noise encryption
- **TOML configuration** - file + CLI + env layered config
- **Cross-platform** - Linux (static musl), macOS (ARM), Windows (x64)
- **Lightweight** - ~1.3-1.9MB release binary, ~5000 lines of Rust, 49 unit tests

## Architecture

```
                    Standalone Mode
                    ===============
  User --> SOCKS5/4 --> [sox] --> Target

                    Tunnel Mode
                    ===========
  User --> SOCKS5/4 --> [Server]  <=== Noise encrypted ===>  [Client] --> Internal Target
           (public)      :1080        tunnel :9090           (internal)
                           |                                   pool-size=200
                           |
                    Monitor Dashboard
                    =================
                    http://0.0.0.0:8080   (--monitor flag)
```

**Standalone mode**: Traditional SOCKS proxy, connects directly to targets.

**Tunnel mode**: Server runs on public network, Client runs on internal network.
Client connects outward to Server (NAT traversal), then Server routes SOCKS requests
through the encrypted tunnel to Client, which connects to targets on the internal network.
The connection pool (default 200 connections) pre-establishes Noise-encrypted TCP connections
so that each SOCKS request can be served immediately without handshake latency.
Each pool connection reuses the same Noise stream across multiple requests — after a relay
completes, the connection is returned to the pool and immediately available for the next request,
eliminating reconnection overhead.

## Quick Start

### Build

```bash
cargo build --release
# Binary at target/release/sox (~1.3MB)

# Cross-compile for all platforms
./build-cross.sh
# Output in dist/:
#   sox-v0.1.0-macos-arm64       (~1.3MB)
#   sox-v0.1.0-windows-amd64.exe (~1.5MB)
#   sox-v0.1.0-linux-amd64       (~1.9MB, static musl)
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
  --pool-size 200
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
- **Client table** — connected clients with pool size, active/idle connections, traffic stats
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
| `GET /api/clients` | Tunnel clients: pool status, live tx/rx, requests served, uptime |

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
      --max-connections <N>     Max concurrent connections [default: 50000]
      --max-per-ip <N>          Max connections per IP [default: 10000]
      --idle-timeout <SECS>     Relay idle timeout [default: 300]
      --monitor <ADDR>          Enable monitor dashboard [e.g. 0.0.0.0:8080]
  -v, --verbosity <LEVEL>       Log level [default: info]

sox server [OPTIONS] --secret <SECRET>
  -s, --socks-listen <ADDR>     SOCKS listen address [default: 0.0.0.0:1080]
  -t, --tunnel-listen <ADDR>    Tunnel listen address [default: 0.0.0.0:9090]
      --secret <SECRET>         Shared secret for Noise encryption
  -u, --user <USER:PASS>        Add SOCKS auth credentials (repeatable)
      --monitor <ADDR>          Enable monitor dashboard [e.g. 0.0.0.0:8080]

sox client [OPTIONS] --server-addr <ADDR> --secret <SECRET>
  -s, --server-addr <ADDR>      Server tunnel address
      --secret <SECRET>         Shared secret (must match server)
      --client-id <ID>          Client identifier [default: default]
      --pool-size <N>           Pre-established connections [default: 200]
      --reconnect-interval <S>  Reconnect interval in seconds [default: 5]
```

### TOML Config File

```toml
listen = "0.0.0.0:1080"
max_connections = 10000
max_connections_per_ip = 100
idle_timeout = 300

[auth]
users = [
  { username = "alice", password = "secret" },
]

[keepalive]
idle = 30
interval = 10
probes = 3

[tunnel]
listen = "0.0.0.0:9090"
secret = "your-shared-key"
```

Config priority: CLI args > TOML file > defaults.

See [`config.example.toml`](config.example.toml) for a full example.

## How It Works

### Tunnel Protocol

The tunnel uses a **Connection Pool** architecture (default pool size: 200):

1. **Control channel** - one persistent TCP connection (Noise encrypted) for registration and heartbeat
2. **Data channels** - N pre-established TCP connections, each individually Noise-encrypted, ready to serve SOCKS requests

When a SOCKS request arrives at the Server:

```
1. Server receives SOCKS5 CONNECT example.com:80
2. Server picks an idle data connection from the Client's pool
3. Server sends ProxyRequest { target: "example.com:80" } over the data connection
4. Client receives it, connects to example.com:80 on the internal network
5. Client sends ProxyReply { success: true }
6. Server replies SOCKS5 success to the user
7. Bidirectional relay: User <-> Server <--(Noise encrypted)--> Client <-> Target
8. Client sends DataReady to signal completion
9. Server receives DataReady, returns connection to pool for reuse (no reconnect needed)
```

### Multi-Client Routing

When multiple Clients are connected, the Server picks the first Client with an available
idle connection (HashMap iteration order, pseudo-random). Traffic is not round-robin —
a Client whose hash key comes first will be used until its pool is exhausted, then the
next Client is tried.

Per-client traffic counters (TX/RX bytes, requests served) are **preserved across reconnects** —
if a Client disconnects and reconnects, its cumulative stats continue from where they left off.

### Encryption

Tunnel connections use **Noise Protocol** (Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s):

- Pre-shared key derived via BLAKE2s (cryptographically secure KDF)
- ChaCha20-Poly1305 authenticated encryption (all relay data encrypted)
- Curve25519 key exchange
- Same cryptographic foundation as WireGuard
- Constant-time password comparison (timing attack resistant)
- Each pool connection performs its own Noise handshake once, then reuses for multiple requests

### Stability

- **Custom TCP relay** with explicit half-close handling (avoids [tokio#3876](https://github.com/tokio-rs/tokio/issues/3876))
- **Per-state timeouts**: handshake (5s), connect (10s), DNS (5s), idle (5min)
- **TCP keepalive**: idle 30s, interval 10s, 3 probes
- **Three-layer connection protection**: global semaphore + per-IP limit + FD limit check
- **Graceful shutdown**: stop accepting -> drain connections -> timeout abort
- **Auto-reconnect**: Client retries every 5s (configurable), gives up after 30 minutes of continuous failure
- **Tunnel connection limit**: max 2048 concurrent tunnel connections to prevent resource exhaustion

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
| Binary size | ~1.3MB | ~2MB | lib | <50KB | ~2MB |

## License

MIT

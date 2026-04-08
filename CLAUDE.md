### 1. Plan Node Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)  
- If something goes sideways, STOP and re-plan immediately - don't keep pushing  
- Use plan mode for verification steps, not just building  
- Write detailed specs upfront to reduce ambiguity  

---

### 2. Subagent Strategy
- Use subagents liberally to keep main context window clean  
- Offload research, exploration, and parallel analysis to subagents  
- For complex problems, throw more compute at it via subagents  
- One task per subagent for focused execution  

---

### 3. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern  
- Write rules for yourself that prevent the same mistake  
- Ruthlessly iterate on these lessons until mistake rate drops  
- Review lessons at session start for relevant project  

---

### 4. Verification Before Done
- Never mark a task complete without proving it works  
- Diff behavior between main and your changes when relevant  
- Ask yourself: "Would a staff engineer approve this?"  
- Run tests, check logs, demonstrate correctness  

---

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"  
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"  
- Skip this for simple, obvious fixes - don't over-engineer  
- Challenge your own work before presenting it  

---

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding  
- Point at logs, errors, failing tests - then resolve them  
- Zero context switching required from the user  
- Go fix failing CI tests without being told how  

---

## Task Management
1. **Plan First**: Write plan to `tasks/todo.md` with checkable items  
2. **Verify Plan**: Check in before starting implementation  
3. **Track Progress**: Mark items complete as you go  
4. **Explain Changes**: High-level summary at each step  
5. **Document Results**: Add review section to `tasks/todo.md`  
6. **Capture Lessons**: Update `tasks/lessons.md` after corrections  

---

## Core Principles
- **Simplicity First**: Make every change as simple as possible. Impact minimal code  
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards

---

## Project: sox

### Architecture
- `src/protocol/` — Pure SOCKS4/4a/5 parsing (no I/O, no async), testable without tokio
- `src/relay/tcp.rs` — Bidirectional TCP relay with explicit half-close + live atomic byte counting + relay_tunneled() for framed Noise relay
- `src/relay/udp.rs` — UDP ASSOCIATE relay with per-target socket management
- `src/server/mod.rs` — Accept loop, connection limits (Semaphore + per-IP), graceful shutdown
- `src/server/connection.rs` — SOCKS state machine: version detect → auth → command → relay/tunnel
- `src/server/monitor.rs` — Embedded HTTP server for dashboard (hand-rolled HTTP/1.1, no framework)
- `src/server/dashboard.html` — Single-page Cyber Dark web UI, included via `include_str!()`
- `src/server/extended_metrics.rs` — Atomic counters, traffic history ring buffer, rate tracker, IP tracker
- `src/client/mod.rs` — Tunnel client: control channel + heartbeat + pool management + auto-reconnect (30 min max)
- `src/client/worker.rs` — Pool worker: recv ProxyRequest → connect target → framed relay → return NoiseStream for reuse
- `src/tunnel/noise.rs` — NoiseStream: Noise_NNpsk0 handshake + encrypted send/recv + split()/reunite() for concurrent relay
- `src/tunnel/pool.rs` — ConnectionPool: N workers, each maintains 1 TCP+Noise conn, serves multiple reqs in a loop (reconnects only on error)
- `src/tunnel/router.rs` — Router: PendingDataConn with oneshot keepalive, return_data_conn() for connection reuse, per-client Arc<AtomicU64> live traffic
- `src/tunnel/protocol.rs` — Binary tunnel message codec (Register/Heartbeat/ProxyRequest/ProxyReply/RelayData/RelayEnd/etc)
- `src/auth/` — AuthProvider trait (sync), PasswordAuth (HashMap)
- `src/config.rs` — TOML + CLI + env layered config with FileConfig serde

### Key Patterns
- Protocol parsing: pure `&[u8]` → struct functions, zero async dependency
- TCP relay: explicit half-close (avoids tokio#3876 hang), shared `Arc<AtomicU64>` for live metrics
- Connection reuse: after relay, client sends DataReady → server waits for it → pushes conn back to pool (prevents race condition)
- NoiseStream split/reunite: Arc<Mutex<TransportState>> for concurrent send/recv, must drop(receiver.transport) before Arc::try_unwrap in reunite
- Framed relay (relay_tunneled): uses tokio::join! (not try_join!) to prevent mid-operation cancellation corrupting Noise frames
- Connection pool: oneshot channel keeps server-side handler alive until connection is consumed; return_data_conn for reuse
- Per-client traffic: `Arc<AtomicU64>` counters passed into relay loop for live updates (not post-relay)
- Monitor: query string `?window=N` controls traffic history window; no zero-padding (adapt to actual data)
- Dashboard: mode-aware topology (standalone vs server), auth-aware (dim irrelevant elements)
- Defaults: max_connections=50000, max_per_ip=10000, pool_size=200, max_tunnel_conns=2048, reconnect_timeout=30min

### Testing
- `cargo test` — 49 unit tests covering:
  - Protocol parsing: SOCKS4/4a/5 handshake, command, reply, addr (IPv4/IPv6/domain roundtrip)
  - Auth: password valid/invalid/empty edge cases
  - Tunnel protocol: all message types roundtrip, invalid/empty decode errors
  - Router: register/unregister, cumulative counter preservation across reconnects, snapshots
  - ExtendedMetrics: peak, traffic history (push/snapshot/no-padding/window), rate tracker, IP tracker, user tracking
- `curl --proxy socks5h://127.0.0.1:1080 http://httpbin.org/ip` — standalone test
- `curl --proxy socks4a://127.0.0.1:1080 http://example.com` — SOCKS4a test
- Server+Client tunnel: start both with `--secret`, curl through SOCKS
- Dashboard: `--monitor :8080`, open browser, verify charts/topology/client table
- API: `curl http://localhost:8080/api/status?window=300 | jq`

### Cross-Compilation
- `./build-cross.sh` — builds macOS ARM, Windows x64 (mingw), Linux x64 (musl static)
- Requires: `brew install mingw-w64 filosottile/musl-cross/musl-cross`
- `socket2::with_retries()` unavailable on musl → gated with `cfg(not(target_env = "musl"))`
- Linux binary is fully static (musl), zero runtime dependencies

### Known Decisions & Lessons
- Pool-based tunnel (not yamux) — yamux `Connection` is `!Clone`, can't split inbound/outbound across tasks
- All relay data encrypted through Noise (ChaCha20-Poly1305) — enables connection reuse at cost of ~10% crypto overhead
- `copy_bidirectional` has half-close hang bug → custom relay with explicit `shutdown()`
- relay_tunneled uses `tokio::join!` not `try_join!` — try_join cancels mid-operation, corrupts Noise frames, breaks WebSocket
- Per-connection `record_traffic` at end misses long-lived connections → use live `fetch_add` in relay loop
- Pool busy-loop fix: each worker is a dedicated task (no mpsc channel + consumer pattern that caused infinite spawn)
- Server-side oneshot keepalive: `handle_data_channel` awaits oneshot to prevent TCP drop before consumption
- DataReady-on-reuse: client must send DataReady after relay before server returns conn to pool (prevents ProxyRequest-during-relay race)
- NoiseStream::reunite: must `drop(receiver.transport)` before `Arc::try_unwrap(sender.transport)` — both hold Arc refs
- macOS system proxy: must bypass localhost in proxy settings for dashboard access
- Per-client cumulative counters: saved to `Router.cumulative` HashMap on unregister, restored on re-register
- Multi-client routing: HashMap iteration order (pseudo-random), not round-robin
- PSK derivation: BLAKE2s with domain separator "sox-psk-v1:" (was DefaultHasher, insecure)
- Password auth: constant-time XOR comparison (was ==, timing attack vulnerable)
- Tunnel listener: Semaphore(2048) caps concurrent tunnel connections (was unlimited, DoS vector)
- Client auto-reconnect: session-scoped CancellationToken so failed session doesn't kill entire client; 30 min max retry
- push_data_conn/return_data_conn: clone mpsc::Sender, drop Mutex, then await send (was holding lock across await)

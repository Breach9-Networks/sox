# Lessons

Project-specific gotchas. Read at session start.

## yamux Config: `recv_window_mb` must give the BDP auto-tune headroom

**Symptom:** single TCP stream through tunnel mode caps at `~256 KiB / RTT`
(≈ 200 Mbps at 10 ms RTT) regardless of physical bandwidth.

**Root cause:** yamux v0.13 starts every stream at `DEFAULT_CREDIT = 256 KiB`
and grows `max_receive_window` to BDP × 2 *only if* there is room in the
connection-level budget:

```
headroom = max_connection_receive_window − max_num_streams × DEFAULT_CREDIT
         − accumulated_extra_windows_already_allocated
```

If `recv_window_mb` is set *equal* to the lower bound
(`max_streams × 256 KiB`, e.g. `max_streams=256, recv_window_mb=64`), the
auto-tune loop computes `headroom = 0` and `new_max = min(2×current, current)`
— **the window never grows**. Auto-tune is silently disabled.

**Rule:** keep `recv_window_mb ≥ 4 × (max_streams × 256 KiB / MiB)`. Defaults
in `src/main.rs` and `src/config.rs` enforce this (`max_streams=256,
recv_window_mb=256 → 192 MiB headroom`).

**Reference:** `flow_control.rs::next_window_update` in yamux source; long
comment in `src/tunnel/session.rs::yamux_config`.

## `opt-level = "z"` halves tunnel throughput — keep the per-package overrides

**Symptom:** tunnel mode tops out around 0.8 Gbps on loopback while standalone
does 3.5 Gbps; CPU is pegged in ChaCha20-Poly1305.

**Root cause:** at `"z"` the AEAD loops are not vectorized or inlined.
Measured 2026-09-22 (release, loopback): `"z"` 100 MiB/s → global `3`
170 MiB/s (+0.9 MB binary) → `"z"` + `opt-level = 3` for `chacha20`,
`poly1305`, `chacha20poly1305`, `snow`, `yamux` only: 160 MiB/s (+32 KB).

**Rule:** do not remove the `[profile.release.package.*]` overrides in
`Cargo.toml`. If the Noise cipher suite ever changes, move the override to the
new cipher crates and re-measure (`cargo test --release --test tunnel_e2e
bench_ -- --ignored --nocapture --test-threads=1`).

## yamux 0.13 pings have no timer — idle sessions are silent

`Rtt::next_ping` only runs when the `Connection` is polled; nothing wakes an
idle connection. So an idle session carries **zero** traffic, and any
"peer went quiet" detection would kill healthy sessions. The session drivers
tick every `HEARTBEAT_INTERVAL` (10s) purely to poll the connection; the
`NoiseByteStream` read watchdog (`READ_IDLE_TIMEOUT`, 45s) relies on it.

**Rule:** the heartbeat and the watchdog are a pair. Never enable/shorten the
watchdog without the heartbeat; keep `READ_IDLE_TIMEOUT` ≥ 3× the heartbeat.
`idle_tunnel_session_survives_the_read_watchdog` (ignored, 55s) guards this —
run it after touching either.

## yamux writes header and body separately — the Noise layer must coalesce

`frame/io.rs` issues one `poll_write` for the 12-byte header and another for
the body. A transport that encrypts per `poll_write` turns every frame into two
AEAD messages and two syscalls. `NoiseByteStream` therefore buffers plaintext
and seals on `poll_flush` / when a message is full. Anything written through it
**must be flushed** to reach the wire (yamux does; ad-hoc callers must too).

Raising yamux `split_send_size` to 64 KiB on top of that measured no gain —
left at the default on purpose.

## A `JoinSet` that is only spawned into is a memory leak

`JoinSet` keeps every finished task's output until `join_next` returns it.
Accept loops must reap while serving (`Some(_) = tasks.join_next(), if
!tasks.is_empty()` as a `select!` arm), not only during the shutdown drain.

## clap `default_value` silently overrides the config file

A flag with a clap default is indistinguishable from one the user typed, so
"CLI overrides file" code applied the *default* over the TOML value. Options
that also live in the TOML file must be `Option<T>` with the default applied
last (CLI > file > built-in), and the default documented in the help text.


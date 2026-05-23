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

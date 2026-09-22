//! Socket-level helpers shared by the SOCKS server, the tunnel transport and
//! the tunnel client: keepalive configuration, DNS resolution and dialing.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::Instant;

/// OS-level TCP keepalive parameters — how half-open dead connections (peer
/// lost power, NAT silently dropped the flow) get detected.
#[derive(Debug, Clone, Copy)]
pub struct KeepaliveParams {
    /// Idle time before the first probe.
    pub idle: Duration,
    /// Interval between probes.
    pub interval: Duration,
    /// Unanswered probes before the connection is declared dead.
    pub probes: u32,
}

impl KeepaliveParams {
    /// Proxied connections (SOCKS clients and targets): dead within ~60s.
    pub const PROXY_DEFAULT: Self = Self {
        idle: Duration::from_secs(30),
        interval: Duration::from_secs(10),
        probes: 3,
    };

    /// Tunnel transport sockets: tighter, dead within ~35s — a dead tunnel
    /// session takes every flow multiplexed on it down with it.
    pub const TUNNEL: Self = Self {
        idle: Duration::from_secs(20),
        interval: Duration::from_secs(5),
        probes: 3,
    };
}

/// Apply `TCP_NODELAY` and keepalive to a stream. The single place socket
/// options are set, so every socket — client-facing, target-facing, tunnel —
/// gets the same treatment on every platform.
pub fn configure_stream(stream: &TcpStream, keepalive: &KeepaliveParams) -> io::Result<()> {
    let sock = socket2::SockRef::from(stream);
    sock.set_nodelay(true)?;
    sock.set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(keepalive.idle)
            .with_interval(keepalive.interval),
    )?;
    set_keepalive_probes(stream, keepalive.probes);
    Ok(())
}

/// 在 unix 平台直接以 libc::setsockopt 設定 `TCP_KEEPCNT`(探測次數)。
///
/// `socket2` 的 `TcpKeepalive::with_retries` 只在 Linux/Android 可用,
/// macOS / musl Linux 因而拿不到自訂值。這個 helper 用 libc 直接呼叫
/// setsockopt,把支援平台統一到所有 unix。失敗只 log 不傳染。
#[cfg(unix)]
fn set_keepalive_probes(stream: &TcpStream, count: u32) {
    use std::os::fd::AsRawFd;
    let retries: libc::c_int = count as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            &retries as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        tracing::debug!(
            error = %io::Error::last_os_error(),
            "TCP_KEEPCNT setsockopt failed; using OS default probe count"
        );
    }
}

/// Windows: `TCP_KEEPCNT` is not exposed per-socket; the system-wide
/// `TcpMaxDataRetransmissions` registry value applies instead.
#[cfg(not(unix))]
fn set_keepalive_probes(_stream: &TcpStream, _count: u32) {}

/// Resolve `host:port` to every address it maps to, bounded by `timeout`.
pub async fn resolve(host: &str, port: u16, timeout: Duration) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS timeout"))??
        .collect();
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no addresses found"));
    }
    Ok(addrs)
}

/// Order addresses so the families alternate, starting with the resolver's
/// first choice — a dead family then costs one attempt, not one per address.
fn interleave_families(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let first_is_v6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
    let (mut a, mut b): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs
        .iter()
        .copied()
        .partition(|addr| addr.is_ipv6() == first_is_v6);
    a.reverse();
    b.reverse();
    let mut out = Vec::with_capacity(addrs.len());
    while !a.is_empty() || !b.is_empty() {
        out.extend(a.pop());
        out.extend(b.pop());
    }
    out
}

/// Connect to the first address that answers, within `budget` overall.
///
/// Each attempt gets an equal share of the time still left, so one blackholed
/// address (typically an AAAA record on a host without working IPv6) cannot
/// eat the whole budget before the working address is even tried. With a
/// single address this is exactly `timeout(budget, connect)`.
pub async fn connect_any(addrs: &[SocketAddr], budget: Duration) -> io::Result<TcpStream> {
    let addrs = interleave_families(addrs);
    let deadline = Instant::now() + budget;
    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no addresses to connect to");

    for (i, addr) in addrs.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let share = remaining / (addrs.len() - i) as u32;
        match tokio::time::timeout(share, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = e,
            Err(_) => last_err = io::Error::new(io::ErrorKind::TimedOut, "connect timed out"),
        }
        tracing::trace!(%addr, error = %last_err, "connect attempt failed");
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleave_alternates_families_keeping_resolver_preference() {
        let p = |s: &str| s.parse::<SocketAddr>().unwrap();
        let addrs = [p("[::1]:1"), p("[::2]:1"), p("1.1.1.1:1"), p("[::3]:1"), p("2.2.2.2:1")];
        assert_eq!(
            interleave_families(&addrs),
            [p("[::1]:1"), p("1.1.1.1:1"), p("[::2]:1"), p("2.2.2.2:1"), p("[::3]:1")]
        );
        assert!(interleave_families(&[]).is_empty());
    }

    #[tokio::test]
    async fn connect_any_falls_through_a_dead_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        // A port nothing listens on → refused; the good address must still win.
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = dead_listener.local_addr().unwrap();
        drop(dead_listener);

        let stream = connect_any(&[dead, good], Duration::from_secs(5)).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap(), good);
    }

    #[tokio::test]
    async fn connect_any_reports_the_last_error() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = l.local_addr().unwrap();
        drop(l);
        let err = connect_any(&[dead], Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert!(connect_any(&[], Duration::from_secs(1)).await.is_err());
    }
}

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::protocol::addr::TargetAddr;
use crate::protocol::socks5::udp::{UdpHeader, parse_udp_header, write_udp_header};
use crate::relay::tcp::IdleClock;
use crate::tunnel::protocol::{encode_udp_frame, read_udp_frame};

/// Standard DNS port. UDP flows whose peer port is 53 are treated as DNS.
const DNS_PORT: u16 = 53;

/// A UDP association that has only ever carried DNS traffic is closed this
/// long after its last datagram — DNS is request/response and short-lived,
/// so there is no need to hold the association for the full idle timeout.
const DNS_IDLE: Duration = Duration::from_secs(3);

/// Largest UDP datagram we can receive.
const MAX_UDP_PACKET: usize = 65535;

/// Per-association cap on remembered `resolved dest → original target`
/// entries; the oldest is evicted first. Keeps a long-lived association that
/// talks to many targets from growing without bound.
const MAX_UDP_DESTS: usize = 4096;

/// Per-association DNS cache: entry lifetime and size cap.
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_CACHE_MAX: usize = 256;

/// Errors on an *unconnected* UDP socket that concern a single datagram, not
/// the socket. Windows reports an ICMP port-unreachable for an earlier send as
/// `WSAECONNRESET` on the next receive; none of these may end the association.
fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::Interrupted
    )
}

// ───────────────────────── activity / idle ─────────────────────────

/// Tracks one UDP association's activity: drives both the true idle timeout
/// and the DNS-aware early close.
struct UdpActivity {
    clock: IdleClock,
    /// Cleared once any non-DNS datagram (peer port != 53) is seen.
    dns_only: AtomicBool,
    /// Set once any datagram is seen.
    seen: AtomicBool,
}

impl UdpActivity {
    fn new() -> Self {
        Self {
            clock: IdleClock::new(),
            dns_only: AtomicBool::new(true),
            seen: AtomicBool::new(false),
        }
    }

    /// Record a datagram; `peer_port` is the port of the datagram's peer
    /// (destination for client→target, source for target→client).
    fn touch(&self, peer_port: u16) {
        self.clock.touch();
        self.seen.store(true, Ordering::Relaxed);
        if peer_port != DNS_PORT {
            self.dns_only.store(false, Ordering::Relaxed);
        }
    }
}

/// Returns once the association has been idle for `idle` — or for `DNS_IDLE`
/// if it has only ever carried DNS. A true inactivity timer: an association
/// that keeps exchanging datagrams is never cut.
async fn udp_idle_watcher(activity: &UdpActivity, idle: Duration) {
    loop {
        let dns_only = activity.dns_only.load(Ordering::Relaxed);
        let limit = if dns_only && activity.seen.load(Ordering::Relaxed) {
            DNS_IDLE.min(idle)
        } else {
            idle
        };
        let elapsed = activity.clock.idle_for();
        if elapsed >= limit {
            return;
        }
        let mut wait = limit - elapsed;
        if dns_only {
            // The first datagram can still flip `seen` and *shorten* the limit
            // while we sleep; re-check every second until a non-DNS datagram
            // makes the limit final.
            wait = wait.min(Duration::from_secs(1));
        }
        tokio::time::sleep(wait).await;
    }
}

/// Resolves when the SOCKS5 TCP control connection closes (EOF or error) —
/// per RFC 1928 the UDP association lives exactly as long as it. Stray bytes
/// the client sends on the control connection are discarded.
async fn control_closed(tcp: &TcpStream) {
    let mut scratch = [0u8; 64];
    loop {
        if tcp.readable().await.is_err() {
            return;
        }
        match tcp.try_read(&mut scratch) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
    }
}

// ───────────────────────── outbound side ─────────────────────────

/// Insertion-order-bounded map `resolved dest → target address as the SOCKS
/// client wrote it`. Replies are accepted only from dests we actually sent to
/// (blocks response injection) and carry the client's original address form
/// (possibly a domain) back. Overwrites keep their FIFO position.
struct DestMap {
    inner: HashMap<SocketAddr, TargetAddr>,
    order: VecDeque<SocketAddr>,
}

impl DestMap {
    fn new() -> Self {
        Self {
            inner: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn insert(&mut self, dest: SocketAddr, addr: &TargetAddr) {
        if let Some(existing) = self.inner.get_mut(&dest) {
            if existing != addr {
                *existing = addr.clone();
            }
            return;
        }
        self.inner.insert(dest, addr.clone());
        self.order.push_back(dest);
        if self.order.len() > MAX_UDP_DESTS
            && let Some(oldest) = self.order.pop_front()
        {
            self.inner.remove(&oldest);
        }
    }

    fn get(&self, dest: &SocketAddr) -> Option<&TargetAddr> {
        self.inner.get(dest)
    }
}

/// The target-facing half of a UDP association: one socket per address family
/// (instead of one socket + task per target, which let a single client exhaust
/// the process's file descriptors), a reply source filter, and a small DNS
/// cache so a domain target is not re-resolved for every datagram.
///
/// Shared by the standalone server and the tunnel client (the tunnel's exit).
pub(crate) struct UdpOutbound {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    dests: Mutex<DestMap>,
    dns: Mutex<HashMap<String, (IpAddr, Instant)>>,
    dns_timeout: Duration,
}

impl UdpOutbound {
    /// Bind the outbound sockets. A host without IPv6 (or without IPv4) still
    /// works for the other family; only failing both is an error.
    pub(crate) async fn bind(dns_timeout: Duration) -> io::Result<Self> {
        let v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await;
        let v6 = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await;
        if let (Err(e), Err(_)) = (&v4, &v6) {
            return Err(io::Error::new(e.kind(), format!("UDP outbound bind failed: {e}")));
        }
        Ok(Self {
            v4: v4.ok(),
            v6: v6.ok(),
            dests: Mutex::new(DestMap::new()),
            dns: Mutex::new(HashMap::new()),
            dns_timeout,
        })
    }

    fn socket_for(&self, ip: &IpAddr) -> Option<&UdpSocket> {
        match ip {
            IpAddr::V4(_) => self.v4.as_ref(),
            IpAddr::V6(_) => self.v6.as_ref(),
        }
    }

    /// Resolve `target` to an address of a family we have a socket for.
    async fn resolve(&self, target: &TargetAddr) -> Option<SocketAddr> {
        let (domain, port) = match target {
            // A v4-mapped v6 address must leave through the v4 socket.
            TargetAddr::Ip(addr) => return Some(SocketAddr::new(addr.ip().to_canonical(), addr.port())),
            TargetAddr::Domain(domain, port) => (domain, *port),
        };

        if let Some((ip, at)) = self.dns.lock().unwrap().get(domain.as_str())
            && at.elapsed() < DNS_CACHE_TTL
        {
            return Some(SocketAddr::new(*ip, port));
        }

        let lookup = tokio::net::lookup_host((domain.as_str(), port));
        let ip = match tokio::time::timeout(self.dns_timeout, lookup).await {
            Ok(Ok(addrs)) => addrs
                .map(|a| a.ip().to_canonical())
                .find(|ip| self.socket_for(ip).is_some()),
            Ok(Err(e)) => {
                tracing::debug!(%domain, error = %e, "UDP target resolution failed");
                None
            }
            Err(_) => {
                tracing::debug!(%domain, "UDP target resolution timed out");
                None
            }
        }?;

        let mut cache = self.dns.lock().unwrap();
        if cache.len() >= DNS_CACHE_MAX {
            cache.retain(|_, (_, at)| at.elapsed() < DNS_CACHE_TTL);
            if cache.len() >= DNS_CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert(domain.clone(), (ip, Instant::now()));
        Some(SocketAddr::new(ip, port))
    }

    /// Forward one datagram to `target`. Never fails the association: an
    /// unresolvable target, a missing address family or a send error costs
    /// only this datagram — UDP is lossy by contract.
    pub(crate) async fn send(&self, target: &TargetAddr, payload: &[u8]) {
        let Some(dest) = self.resolve(target).await else {
            return;
        };
        let Some(sock) = self.socket_for(&dest.ip()) else {
            tracing::debug!(%dest, "no UDP socket for this address family, dropping datagram");
            return;
        };
        self.dests.lock().unwrap().insert(dest, target);
        if let Err(e) = sock.send_to(payload, dest).await {
            tracing::debug!(%dest, error = %e, "UDP forward failed");
        }
    }

    /// Receive the next reply from a dest we have sent to. Returns the payload
    /// length and the target address in the form the SOCKS client used.
    pub(crate) async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        async fn readable(sock: Option<&UdpSocket>) -> io::Result<&UdpSocket> {
            match sock {
                Some(s) => s.readable().await.map(|()| s),
                None => std::future::pending().await,
            }
        }

        loop {
            let sock = tokio::select! {
                r = readable(self.v4.as_ref()) => r?,
                r = readable(self.v6.as_ref()) => r?,
            };
            match sock.try_recv_from(buf) {
                Ok((n, src)) => {
                    let src = SocketAddr::new(src.ip().to_canonical(), src.port());
                    if let Some(orig) = self.dests.lock().unwrap().get(&src) {
                        return Ok((n, orig.clone()));
                    }
                    tracing::trace!(%src, "dropping UDP reply from a source we never sent to");
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if is_transient(&e) => {
                    tracing::trace!(error = %e, "transient UDP recv error");
                }
                Err(e) => return Err(e),
            }
        }
    }
}

// ───────────────────────── client-facing side ─────────────────────────

/// The SOCKS-client-facing half: the relay socket the client sends to, the
/// IP it must send from, and its full UDP address once learned.
struct ClientSide {
    sock: UdpSocket,
    peer_ip: IpAddr,
    /// The client's UDP port is unknown until its first datagram arrives.
    learned: Mutex<Option<SocketAddr>>,
}

impl ClientSide {
    fn new(sock: UdpSocket, peer_ip: IpAddr) -> Self {
        Self {
            sock,
            // A dual-stack listener reports a v4 client as `::ffff:a.b.c.d`
            // while its datagrams arrive on a v4 socket as `a.b.c.d`.
            peer_ip: peer_ip.to_canonical(),
            learned: Mutex::new(None),
        }
    }

    /// Receive the next valid datagram from the client: right source IP,
    /// well-formed SOCKS5 UDP header, not fragmented. Returns the header and
    /// the payload's range within `buf`.
    async fn recv(&self, buf: &mut [u8]) -> io::Result<(UdpHeader, Range<usize>)> {
        loop {
            let (n, src) = match self.sock.recv_from(buf).await {
                Ok(v) => v,
                Err(e) if is_transient(&e) => continue,
                Err(e) => return Err(e),
            };
            if src.ip().to_canonical() != self.peer_ip {
                tracing::trace!(%src, peer_ip = %self.peer_ip, "dropping UDP from unexpected source");
                continue;
            }
            *self.learned.lock().unwrap() = Some(src);

            let (header, offset) = match parse_udp_header(&buf[..n]) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, "invalid UDP header");
                    continue;
                }
            };
            if header.frag != 0 {
                tracing::trace!(frag = header.frag, "dropping fragmented UDP");
                continue;
            }
            return Ok((header, offset..n));
        }
    }

    /// Wrap `payload` in a SOCKS5 UDP header (into the reusable `packet`) and
    /// send it to the client. Dropped if the client's address is not known
    /// yet; a send error costs only this datagram.
    async fn send(&self, from: TargetAddr, payload: &[u8], packet: &mut Vec<u8>) {
        let Some(client_addr) = *self.learned.lock().unwrap() else {
            return;
        };
        packet.clear();
        write_udp_header(&UdpHeader { frag: 0, target: from }, packet);
        packet.extend_from_slice(payload);
        if let Err(e) = self.sock.send_to(packet, client_addr).await {
            tracing::debug!(%client_addr, error = %e, "UDP response send failed");
        }
    }
}

// ───────────────────────── relays ─────────────────────────

/// Run a UDP relay for a SOCKS5 UDP ASSOCIATE session (standalone mode).
///
/// 1. Receives datagrams from the client on `relay_socket`, strips the SOCKS5
///    UDP header, resolves the target and forwards the payload.
/// 2. Receives replies from targets and wraps them in SOCKS5 UDP headers.
/// 3. Ends when the TCP control connection closes or the association has been
///    idle for `idle_timeout` (a true inactivity timer).
///
/// Everything runs inside this one future — nothing is spawned — so dropping
/// it releases every socket at once. Fragmented datagrams are dropped per
/// standard practice.
pub async fn relay_udp(
    tcp_control: &TcpStream,
    relay_socket: UdpSocket,
    peer_ip: IpAddr,
    idle_timeout: Duration,
    dns_timeout: Duration,
) -> io::Result<()> {
    let client = ClientSide::new(relay_socket, peer_ip);
    let outbound = UdpOutbound::bind(dns_timeout).await?;
    let activity = UdpActivity::new();

    let client_to_target = async {
        let mut buf = vec![0u8; MAX_UDP_PACKET];
        loop {
            let (header, payload) = client.recv(&mut buf).await?;
            activity.touch(header.target.port());
            outbound.send(&header.target, &buf[payload]).await;
        }
    };
    let target_to_client = async {
        let mut buf = vec![0u8; MAX_UDP_PACKET];
        let mut packet = Vec::new();
        loop {
            let (n, from) = outbound.recv(&mut buf).await?;
            activity.touch(from.port());
            client.send(from, &buf[..n], &mut packet).await;
        }
    };

    tokio::select! {
        _ = control_closed(tcp_control) => Ok(()),
        _ = udp_idle_watcher(&activity, idle_timeout) => {
            tracing::debug!("UDP association idle, closing");
            Ok(())
        }
        r = client_to_target => r,
        r = target_to_client => r,
    }
}

/// Server 端 UDP relay(tunnel 模式):把 SOCKS-client-facing 的 `relay_socket`
/// 與一條承載 UDP frame 的 yamux stream 對接。TCP 控制通道關閉、或閒置達
/// `idle_timeout` 即收工。同樣不 spawn 任何 task。
pub async fn relay_udp_tunneled<S>(
    tcp_control: &TcpStream,
    relay_socket: UdpSocket,
    peer_ip: IpAddr,
    stream: S,
    idle_timeout: Duration,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client = ClientSide::new(relay_socket, peer_ip);
    let (mut sr, mut sw) = tokio::io::split(stream);
    let activity = UdpActivity::new();

    // 方向 A：SOCKS client → tunnel。
    let client_to_tunnel = async {
        let mut buf = vec![0u8; MAX_UDP_PACKET];
        let mut frame = Vec::new();
        loop {
            let (header, payload) = client.recv(&mut buf).await?;
            activity.touch(header.target.port());
            if !encode_udp_frame(&header.target, &buf[payload], &mut frame) {
                tracing::trace!("dropping UDP datagram too large for the tunnel");
                continue;
            }
            sw.write_all(&frame).await?;
        }
    };
    // 方向 B：tunnel → SOCKS client。
    let tunnel_to_client = async {
        let mut frame = Vec::new();
        let mut packet = Vec::new();
        loop {
            let (from, payload) = read_udp_frame(&mut sr, &mut frame).await?;
            activity.touch(from.port());
            client.send(from, &frame[payload], &mut packet).await;
        }
    };

    tokio::select! {
        _ = control_closed(tcp_control) => Ok(()),
        _ = udp_idle_watcher(&activity, idle_timeout) => {
            tracing::debug!("tunnel UDP association idle, closing");
            Ok(())
        }
        r = client_to_tunnel => r,
        r = tunnel_to_client => r,
    }
}

/// Tunnel client 端(出口):把一條承載 UDP frame 的 yamux stream 與真實 UDP
/// 目標對接。閒置達 `idle_timeout` 即收工,避免 UDP socket 與 yamux stream 洩漏。
pub(crate) async fn relay_udp_exit<S>(
    stream: S,
    outbound: UdpOutbound,
    idle_timeout: Duration,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sr, mut sw) = tokio::io::split(stream);
    // 在 bind + reply **之後**才起算 —— 「等 client 第一筆 datagram」不算 idle。
    let clock = IdleClock::new();
    clock.touch();

    let tunnel_to_target = async {
        let mut frame = Vec::new();
        loop {
            let (target, payload) = read_udp_frame(&mut sr, &mut frame).await?;
            // 收到 datagram 本身就算「活動」—— 在 DNS resolve **之前**更新,
            // 慢 DNS 不可吃掉 idle 預算。
            clock.touch();
            outbound.send(&target, &frame[payload]).await;
        }
    };
    let target_to_tunnel = async {
        let mut buf = vec![0u8; MAX_UDP_PACKET];
        let mut frame = Vec::new();
        loop {
            let (n, from) = outbound.recv(&mut buf).await?;
            clock.touch();
            if !encode_udp_frame(&from, &buf[..n], &mut frame) {
                tracing::trace!("dropping UDP reply too large for the tunnel");
                continue;
            }
            sw.write_all(&frame).await?;
        }
    };

    tokio::select! {
        _ = crate::relay::tcp::idle_watcher(&clock, idle_timeout) => {
            tracing::debug!("tunnel UDP flow idle, closing");
            Ok(())
        }
        r = tunnel_to_target => r,
        r = target_to_tunnel => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dest_map_evicts_oldest_when_over_cap() {
        let mut m = DestMap::new();
        for i in 0..MAX_UDP_DESTS {
            let addr: SocketAddr = format!("10.0.0.1:{}", i % 65535 + 1).parse().unwrap();
            m.insert(addr, &TargetAddr::Ip(addr));
        }
        assert_eq!(m.inner.len(), MAX_UDP_DESTS);
        let oldest: SocketAddr = "10.0.0.1:1".parse().unwrap();
        assert!(m.get(&oldest).is_some());

        // One more insert pushes us over the cap and evicts the oldest.
        let new_addr: SocketAddr = "10.0.0.99:9999".parse().unwrap();
        m.insert(new_addr, &TargetAddr::Ip(new_addr));
        assert_eq!(m.inner.len(), MAX_UDP_DESTS);
        assert!(m.get(&oldest).is_none(), "oldest entry should be evicted");
        assert!(m.get(&new_addr).is_some());
    }

    #[test]
    fn dest_map_repeat_insert_keeps_size() {
        let mut m = DestMap::new();
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        for _ in 0..3 {
            m.insert(addr, &TargetAddr::Ip(addr));
        }
        assert_eq!(m.inner.len(), 1);
        assert_eq!(m.order.len(), 1);
    }

    async fn udp_echo() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, src)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&buf[..n], src).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn outbound_many_targets_share_sockets_and_filter_sources() {
        let out = UdpOutbound::bind(Duration::from_secs(1)).await.unwrap();
        let mut buf = vec![0u8; 2048];
        // Many targets, still only the per-family sockets — no fd per target.
        for _ in 0..8 {
            let echo = udp_echo().await;
            out.send(&TargetAddr::Ip(echo), b"ping").await;
            let (n, from) = out.recv(&mut buf).await.unwrap();
            assert_eq!((&buf[..n], from), (&b"ping"[..], TargetAddr::Ip(echo)));
        }

        // A datagram from a source we never sent to must be ignored.
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = out.v4.as_ref().unwrap().local_addr().unwrap().port();
        stranger.send_to(b"inject", ("127.0.0.1", port)).await.unwrap();
        let got = tokio::time::timeout(Duration::from_millis(200), out.recv(&mut buf)).await;
        assert!(got.is_err(), "injected datagram must not be delivered");
    }

    #[tokio::test]
    async fn outbound_send_failure_is_not_fatal() {
        let out = UdpOutbound::bind(Duration::from_millis(200)).await.unwrap();
        // Unresolvable domain and port 0 both cost only the datagram.
        out.send(&TargetAddr::Domain("nonexistent.invalid".into(), 53), b"x").await;
        out.send(&TargetAddr::Ip("127.0.0.1:0".parse().unwrap()), b"x").await;
        let echo = udp_echo().await;
        out.send(&TargetAddr::Ip(echo), b"still-alive").await;
        let mut buf = vec![0u8; 64];
        let (n, _) = out.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"still-alive");
    }

    #[tokio::test]
    async fn client_side_accepts_v4_mapped_peer() {
        // B2 regression: dual-stack listeners report `::ffff:127.0.0.1`.
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let side = ClientSide::new(relay, mapped);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut pkt = Vec::new();
        let target = TargetAddr::Ip("9.9.9.9:53".parse().unwrap());
        write_udp_header(&UdpHeader { frag: 0, target: target.clone() }, &mut pkt);
        pkt.extend_from_slice(b"q");
        client.send_to(&pkt, relay_addr).await.unwrap();

        let mut buf = vec![0u8; 256];
        let (header, payload) =
            tokio::time::timeout(Duration::from_secs(2), side.recv(&mut buf))
                .await
                .expect("datagram from v4-mapped peer was dropped")
                .unwrap();
        assert_eq!((header.target, &buf[payload]), (target, &b"q"[..]));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_watcher_is_inactivity_not_wall_clock() {
        let activity = UdpActivity::new();
        let idle = Duration::from_secs(10);
        let watcher = udp_idle_watcher(&activity, idle);
        tokio::pin!(watcher);
        // Non-DNS traffic every 4s for 40s — 4× the idle timeout.
        for _ in 0..10 {
            activity.touch(4000);
            tokio::select! {
                _ = &mut watcher => panic!("active association was cut"),
                _ = tokio::time::sleep(Duration::from_secs(4)) => {}
            }
        }
        // Then silence → fires within `idle`.
        tokio::time::timeout(idle + Duration::from_secs(1), watcher)
            .await
            .expect("idle association was not closed");
    }
}

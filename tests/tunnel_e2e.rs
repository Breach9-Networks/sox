//! End-to-end integration tests for the yamux-multiplexed tunnel.
//!
//! Each test stands up a real tunnel server + client in-process and drives
//! SOCKS5 traffic through them over loopback.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

const SECRET: &str = "e2e-test-secret";

// ───────────────────────── harness ─────────────────────────

/// Bind two listeners at once so the returned ports are guaranteed distinct.
async fn two_free_ports() -> (u16, u16) {
    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    (
        l1.local_addr().unwrap().port(),
        l2.local_addr().unwrap().port(),
    )
}

/// Spawn a TCP echo server; returns its address.
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Spawn a UDP echo server; returns its address.
async fn spawn_udp_echo() -> SocketAddr {
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

/// Spawn a TCP server that accepts connections and never reads — a black hole
/// that backs up whatever stream feeds it.
async fn spawn_blackhole() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock); // hold the connection open, never read
        }
    });
    addr
}

fn start_server(socks_port: u16, tunnel_port: u16, cancel: CancellationToken) {
    let config = sox::config::Config {
        listen_addr: format!("127.0.0.1:{socks_port}").parse().unwrap(),
        ..sox::config::Config::default()
    };
    let tunnel_addr = format!("127.0.0.1:{tunnel_port}");
    tokio::spawn(async move {
        let _ = sox::server::run_server(config, tunnel_addr, SECRET.to_string(), cancel).await;
    });
}

fn start_client(
    tunnel_port: u16,
    sessions: u16,
    max_streams: usize,
    recv_window_mb: usize,
    cancel: CancellationToken,
) {
    start_client_as("e2e-client", SECRET, tunnel_port, sessions, max_streams, recv_window_mb, cancel);
}

fn start_client_as(
    client_id: &str,
    secret: &str,
    tunnel_port: u16,
    sessions: u16,
    max_streams: usize,
    recv_window_mb: usize,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let cfg = sox::client::ClientConfig {
        server_addr: format!("127.0.0.1:{tunnel_port}"),
        secret: secret.to_string(),
        client_id: client_id.into(),
        tunnel_sessions: sessions,
        max_streams,
        recv_window_mb,
        reconnect_interval: Duration::from_millis(200),
        reconnect_max: Duration::from_secs(2),
        connect_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(300),
        dns_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(10),
    };
    tokio::spawn(sox::client::run_client(cfg, cancel))
}

fn start_standalone(socks_port: u16, cancel: CancellationToken) {
    start_standalone_with(socks_port, sox::config::Config::default(), cancel);
}

fn start_standalone_with(socks_port: u16, config: sox::config::Config, cancel: CancellationToken) {
    let config = sox::config::Config {
        listen_addr: format!("127.0.0.1:{socks_port}").parse().unwrap(),
        ..config
    };
    tokio::spawn(async move {
        let _ = sox::server::run_standalone(config, cancel).await;
    });
}

/// Start a standalone proxy with `config`; returns its address and cancel token.
async fn spawn_standalone(config: sox::config::Config) -> (SocketAddr, CancellationToken) {
    let (socks_port, _) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let cancel = CancellationToken::new();
    start_standalone_with(socks_port, config, cancel.clone());
    wait_for_listener(proxy).await;
    (proxy, cancel)
}

fn start_standalone_with_auth(socks_port: u16, user: &str, pass: &str, cancel: CancellationToken) {
    let config = sox::config::Config {
        listen_addr: format!("127.0.0.1:{socks_port}").parse().unwrap(),
        auth: sox::config::AuthConfig::Password(vec![(user.to_string(), pass.to_string())]),
        ..sox::config::Config::default()
    };
    tokio::spawn(async move {
        let _ = sox::server::run_standalone(config, cancel).await;
    });
}

/// Wait until something is accepting TCP connections at `addr`.
async fn wait_for_listener(addr: SocketAddr) {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("listener at {addr} never came up");
}

/// Stand up a full server + client tunnel; returns the SOCKS proxy address
/// and a cancel token that shuts both down.
async fn spawn_tunnel(
    sessions: u16,
    max_streams: usize,
    recv_window_mb: usize,
) -> (SocketAddr, CancellationToken) {
    let (socks_port, tunnel_port) = two_free_ports().await;
    let cancel = CancellationToken::new();
    start_server(socks_port, tunnel_port, cancel.clone());
    start_client(tunnel_port, sessions, max_streams, recv_window_mb, cancel.clone());
    let proxy = format!("127.0.0.1:{socks_port}").parse().unwrap();
    (proxy, cancel)
}

/// Perform a SOCKS5 no-auth handshake + CONNECT. Returns the relay-ready stream,
/// or an error if the proxy is not reachable / the CONNECT failed.
async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(std::io::Error::other("unexpected SOCKS5 greeting"));
    }
    let ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => panic!("tests use IPv4"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await?;
    let mut reply = [0u8; 10]; // IPv4 bound-address reply
    s.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 CONNECT failed, status {:#x}",
            reply[1]
        )));
    }
    Ok(s)
}

/// Retry `socks5_connect` until it succeeds — absorbs server-bind and
/// client-registration latency.
async fn retry_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    for _ in 0..50 {
        if let Ok(s) = socks5_connect(proxy, target).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("tunnel did not become ready within 5s");
}

/// Run a SOCKS5 UDP ASSOCIATE through `proxy`, send `payload` to `target` via
/// the relay socket, and return the echoed datagram (SOCKS5 UDP header still
/// attached) if one comes back.
async fn udp_associate_echo(
    proxy: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let mut ctrl = TcpStream::connect(proxy).await.ok()?;
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
    let mut greeting = [0u8; 2];
    ctrl.read_exact(&mut greeting).await.ok()?;
    if greeting != [0x05, 0x00] {
        return None;
    }
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .ok()?;
    let mut reply = [0u8; 10];
    ctrl.read_exact(&mut reply).await.ok()?;
    if reply[1] != 0x00 {
        return None;
    }
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay_addr: SocketAddr = format!("127.0.0.1:{relay_port}").parse().ok()?;

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let target_ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => return None,
    };
    let mut packet = vec![0x00, 0x00, 0x00, 0x01];
    packet.extend_from_slice(&target_ip);
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);

    let mut result = None;
    for _ in 0..30 {
        client_udp.send_to(&packet, relay_addr).await.ok()?;
        let mut buf = [0u8; 2048];
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(300), client_udp.recv_from(&mut buf)).await
        {
            result = Some(buf[..n].to_vec());
            break;
        }
    }
    drop(ctrl); // hold the control connection open until the exchange is done
    result
}

// ───────────────────────── Task 18: end-to-end TCP ─────────────────────────

#[tokio::test]
async fn socks5_connect_through_tunnel_echoes() {
    let echo = spawn_tcp_echo().await;
    let (proxy, cancel) = spawn_tunnel(2, 64, 16).await;

    let mut conn = retry_connect(proxy, echo).await;
    conn.write_all(b"roundtrip").await.unwrap();
    let mut buf = [0u8; 9];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"roundtrip");

    cancel.cancel();
}

// ───────────────────────── Task 19: stream isolation ─────────────────────────

#[tokio::test]
async fn slow_stream_does_not_block_cotenant() {
    let echo = spawn_tcp_echo().await;
    let blackhole = spawn_blackhole().await;
    // One session forces flow A and flow B to be co-tenants on the same yamux session.
    let (proxy, cancel) = spawn_tunnel(1, 8, 2).await;

    // Confirm the tunnel is ready.
    drop(retry_connect(proxy, echo).await);

    // Flow A: blast 16 MiB at a black hole — this stalls once the per-stream
    // flow-control window and socket buffers fill.
    let mut conn_a = socks5_connect(proxy, blackhole).await.unwrap();
    let a_task = tokio::spawn(async move {
        let blast = vec![0u8; 16 * 1024 * 1024];
        let _ = conn_a.write_all(&blast).await; // expected to stall
        tokio::time::sleep(Duration::from_secs(30)).await; // keep conn_a alive
    });

    // Give flow A a moment to back up.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Flow B (same session) must still complete quickly despite A being stalled.
    let mut conn_b = socks5_connect(proxy, echo).await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(3), async {
        conn_b.write_all(b"isolated").await.unwrap();
        let mut buf = [0u8; 8];
        conn_b.read_exact(&mut buf).await.unwrap();
        buf
    })
    .await;

    a_task.abort();
    cancel.cancel();

    let buf = outcome.expect("co-tenant stream B stalled while A was slow — isolation failed");
    assert_eq!(&buf, b"isolated");
}

// ───────────────────────── Task 20: reconnect + UDP ─────────────────────────

#[tokio::test]
async fn client_reconnects_after_server_restart() {
    let echo = spawn_tcp_echo().await;
    let (socks_port, tunnel_port) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();

    // Server #1 + a client that outlives the restart.
    let server1 = CancellationToken::new();
    let client = CancellationToken::new();
    start_server(socks_port, tunnel_port, server1.clone());
    start_client(tunnel_port, 2, 64, 16, client.clone());

    {
        let mut c = retry_connect(proxy, echo).await;
        c.write_all(b"before").await.unwrap();
        let mut buf = [0u8; 6];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"before");
    }

    // Kill server #1, let the ports settle, restart on the same ports.
    server1.cancel();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let server2 = CancellationToken::new();
    start_server(socks_port, tunnel_port, server2.clone());

    // The client should reconnect via backoff; a fresh CONNECT must work.
    let mut c = retry_connect(proxy, echo).await;
    c.write_all(b"after").await.unwrap();
    let mut buf = [0u8; 5];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"after");

    server2.cancel();
    client.cancel();
}

#[tokio::test]
async fn socks5_udp_associate_through_tunnel() {
    let tcp_echo = spawn_tcp_echo().await;
    let udp_echo = spawn_udp_echo().await;
    let (proxy, cancel) = spawn_tunnel(2, 64, 16).await;

    // Confirm tunnel readiness with a TCP probe first.
    drop(retry_connect(proxy, tcp_echo).await);

    let echoed = udp_associate_echo(proxy, udp_echo, b"udp-hello").await;
    cancel.cancel();

    let resp = echoed.expect("no UDP echo received through tunnel");
    assert!(resp.ends_with(b"udp-hello"), "UDP echo payload mismatch: {resp:?}");
}

#[tokio::test]
async fn socks5_udp_associate_standalone() {
    let udp_echo = spawn_udp_echo().await;
    let (socks_port, _) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let cancel = CancellationToken::new();
    start_standalone(socks_port, cancel.clone());
    wait_for_listener(proxy).await;

    let echoed = udp_associate_echo(proxy, udp_echo, b"standalone-udp").await;
    cancel.cancel();

    let resp = echoed.expect("no UDP echo received in standalone mode");
    assert!(
        resp.ends_with(b"standalone-udp"),
        "UDP echo payload mismatch: {resp:?}"
    );
}

/// A SOCKS5 CONNECT request that arrives split across two TCP segments must
/// still be parsed correctly (the server reads until the request is complete).
#[tokio::test]
async fn socks5_command_request_arriving_fragmented() {
    let echo = spawn_tcp_echo().await;
    let (socks_port, _) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let cancel = CancellationToken::new();
    start_standalone(socks_port, cancel.clone());
    wait_for_listener(proxy).await;

    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    // CONNECT request, deliberately split across two TCP segments.
    let ip = match echo.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => panic!("ipv4"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&echo.port().to_be_bytes());
    s.write_all(&req[..4]).await.unwrap();
    s.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    s.write_all(&req[4..]).await.unwrap();

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "fragmented CONNECT request should still succeed");

    s.write_all(b"frag").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"frag");

    cancel.cancel();
}

/// A relay already in progress when shutdown is signalled must be drained to
/// completion, not cut instantly.
#[tokio::test]
async fn shutdown_drains_in_flight_relay() {
    // Target: on connect, wait a beat, then send a payload and close. The
    // payload is sent *after* shutdown is signalled below.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_millis(800)).await;
            let _ = sock.write_all(b"survived-shutdown").await;
            let _ = sock.shutdown().await;
        }
    });

    let (socks_port, _) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let cancel = CancellationToken::new();
    start_standalone(socks_port, cancel.clone());
    wait_for_listener(proxy).await;

    // Establish the relay, then signal shutdown while the target is still
    // sleeping — the payload has not been sent yet.
    let mut conn = socks5_connect(proxy, target).await.unwrap();
    cancel.cancel();

    // The in-flight relay must still deliver the payload.
    let got = tokio::time::timeout(Duration::from_secs(10), async {
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.unwrap();
        buf
    })
    .await
    .expect("relay did not finish after shutdown");

    assert_eq!(&got, b"survived-shutdown", "in-flight relay was cut by shutdown");
}

/// A UDP ASSOCIATE that only carries DNS traffic (datagrams to port 53) is
/// closed early once idle, instead of being held for the full idle timeout.
#[tokio::test]
async fn udp_dns_association_closes_early() {
    let (socks_port, _) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let cancel = CancellationToken::new();
    start_standalone(socks_port, cancel.clone());
    wait_for_listener(proxy).await;

    let mut ctrl = TcpStream::connect(proxy).await.unwrap();
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    ctrl.read_exact(&mut greeting).await.unwrap();
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    ctrl.read_exact(&mut reply).await.unwrap();
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay_addr: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();

    // One datagram destined for port 53 (0x0035) — marks it as a DNS flow.
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut pkt = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x35];
    pkt.extend_from_slice(b"dns-query");
    client_udp.send_to(&pkt, relay_addr).await.unwrap();

    // The DNS-only association should be closed by the server once idle —
    // observed as EOF (or reset) on the control connection.
    let observed = tokio::time::timeout(Duration::from_secs(8), async {
        let mut buf = [0u8; 1];
        ctrl.read(&mut buf).await
    })
    .await;
    cancel.cancel();

    match observed {
        Ok(Ok(0)) | Ok(Err(_)) => {} // server closed the idle DNS association
        Ok(Ok(n)) => panic!("unexpected {n} bytes on the control connection"),
        Err(_) => panic!("DNS-only UDP association was not closed early"),
    }
}

/// A UDP ASSOCIATE carrying non-DNS traffic is NOT closed early.
#[tokio::test]
async fn udp_non_dns_association_stays_open() {
    let (socks_port, _) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let cancel = CancellationToken::new();
    start_standalone(socks_port, cancel.clone());
    wait_for_listener(proxy).await;

    let mut ctrl = TcpStream::connect(proxy).await.unwrap();
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    ctrl.read_exact(&mut greeting).await.unwrap();
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    ctrl.read_exact(&mut reply).await.unwrap();
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay_addr: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();

    // A datagram destined for a non-DNS port (0x3039 = 12345).
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut pkt = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x30, 0x39];
    pkt.extend_from_slice(b"not-dns");
    client_udp.send_to(&pkt, relay_addr).await.unwrap();

    let observed = tokio::time::timeout(Duration::from_secs(8), async {
        let mut buf = [0u8; 1];
        ctrl.read(&mut buf).await
    })
    .await;
    cancel.cancel();

    assert!(
        observed.is_err(),
        "non-DNS UDP association should not be closed early"
    );
}

/// A RFC 1929 username/password request that arrives split across two TCP
/// segments must still be parsed correctly.
#[tokio::test]
async fn socks5_userpass_request_arriving_fragmented() {
    let echo = spawn_tcp_echo().await;
    let (socks_port, _) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let cancel = CancellationToken::new();
    start_standalone_with_auth(socks_port, "alice", "secret", cancel.clone());
    wait_for_listener(proxy).await;

    let mut s = TcpStream::connect(proxy).await.unwrap();
    // Greeting offering the username/password method.
    s.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x02], "server should select username/password");

    // RFC 1929 request [ver=1, ulen=5, "alice", plen=6, "secret"], fragmented.
    let mut auth = vec![0x01, 0x05];
    auth.extend_from_slice(b"alice");
    auth.push(0x06);
    auth.extend_from_slice(b"secret");
    s.write_all(&auth[..3]).await.unwrap();
    s.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    s.write_all(&auth[3..]).await.unwrap();

    let mut auth_reply = [0u8; 2];
    s.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [0x01, 0x00], "fragmented auth should still succeed");

    // Continue with a normal CONNECT.
    let ip = match echo.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => panic!("ipv4"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&echo.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00);

    cancel.cancel();
}

// ───────────────────────── Round 3 regressions ─────────────────────────

/// A12: a SOCKS4a request dribbling in one fragment at a time must still be
/// served. `localhost` may resolve to `::1` first while the echo server only
/// listens on 127.0.0.1 — the dialer has to fall through to the next address.
#[tokio::test]
async fn socks4a_request_arriving_fragmented() {
    let echo = spawn_tcp_echo().await;
    let (proxy, cancel) = spawn_standalone(sox::config::Config::default()).await;

    let mut s = TcpStream::connect(proxy).await.unwrap();
    let port = echo.port().to_be_bytes();
    let fragments: [&[u8]; 5] = [
        &[0x04, 0x01, port[0], port[1]],
        &[0, 0, 0, 1], // 0.0.0.x → SOCKS4a, a domain follows the user id
        b"some-user",
        &[0x00],
        b"localhost\0",
    ];
    for fragment in fragments {
        s.write_all(fragment).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    let mut reply = [0u8; 8];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x5a, "SOCKS4a request was not granted");

    s.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
    cancel.cancel();
}

/// A12: bytes a client pipelines right behind its CONNECT request belong to
/// the relay — the handshake must not swallow them.
#[tokio::test]
async fn socks5_payload_pipelined_behind_request_is_not_lost() {
    let echo = spawn_tcp_echo().await;
    let (proxy, cancel) = spawn_standalone(sox::config::Config::default()).await;

    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await.unwrap();

    let std::net::IpAddr::V4(ip) = echo.ip() else { panic!("tests use IPv4") };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&echo.port().to_be_bytes());
    req.extend_from_slice(b"early-bytes"); // same segment as the request
    s.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00);

    let mut got = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut got))
        .await
        .expect("pipelined payload was swallowed by the handshake")
        .unwrap();
    assert_eq!(&got, b"early-bytes");
    cancel.cancel();
}

/// A12: the handshake timeout is one budget for the whole negotiation, not a
/// fresh one per phase.
#[tokio::test]
async fn handshake_timeout_covers_all_phases_together() {
    let (proxy, cancel) = spawn_standalone(sox::config::Config {
        handshake_timeout: Duration::from_millis(600),
        ..sox::config::Config::default()
    })
    .await;

    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await.unwrap();

    // Each phase on its own stays under 600ms; together they do not.
    tokio::time::sleep(Duration::from_millis(400)).await;
    s.write_all(&[0x05, 0x01, 0x00, 0x01]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let mut buf = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(1), s.read(&mut buf)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "slow client should have been cut off at the shared deadline, got {closed:?}"
    );
    cancel.cancel();
}

/// A4: `idle_timeout` on a UDP association is an inactivity timer. An
/// association that stays busy for several times the timeout must survive,
/// and one that goes quiet must then be closed.
#[tokio::test]
async fn udp_association_idle_timeout_is_inactivity_not_wall_clock() {
    let echo = spawn_udp_echo().await;
    let (proxy, cancel) = spawn_standalone(sox::config::Config {
        idle_timeout: Duration::from_secs(1),
        ..sox::config::Config::default()
    })
    .await;

    let mut ctrl = TcpStream::connect(proxy).await.unwrap();
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    ctrl.read_exact(&mut greeting).await.unwrap();
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut reply = [0u8; 10];
    ctrl.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00);
    assert_eq!(&reply[4..8], &[127, 0, 0, 1], "BND.ADDR must be reachable, not 0.0.0.0");
    let relay: SocketAddr =
        format!("127.0.0.1:{}", u16::from_be_bytes([reply[8], reply[9]])).parse().unwrap();

    let std::net::IpAddr::V4(ip) = echo.ip() else { panic!("tests use IPv4") };
    let mut packet = vec![0x00, 0x00, 0x00, 0x01];
    packet.extend_from_slice(&ip.octets());
    packet.extend_from_slice(&echo.port().to_be_bytes());
    packet.extend_from_slice(b"tick");

    // Busy for 3s = 3× the idle timeout.
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 64];
    for round in 0..10 {
        udp.send_to(&packet, relay).await.unwrap();
        tokio::time::timeout(Duration::from_millis(900), udp.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("active association was cut (round {round})"))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Quiet → the proxy ends the association by closing the control connection.
    let closed = tokio::time::timeout(Duration::from_secs(4), ctrl.read(&mut buf)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "idle association was never closed, got {closed:?}"
    );
    cancel.cancel();
}

/// A5: shutting the tunnel *client* down must drain relays in flight on its
/// sessions, not cut them.
#[tokio::test]
async fn client_shutdown_drains_in_flight_tunnel_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(800)).await;
                let _ = sock.write_all(b"survived-client-shutdown").await;
                let _ = sock.shutdown().await;
            });
        }
    });

    let (socks_port, tunnel_port) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let server_cancel = CancellationToken::new();
    let client_cancel = CancellationToken::new();
    start_server(socks_port, tunnel_port, server_cancel.clone());
    let client =
        start_client_as("drain", SECRET, tunnel_port, 1, 256, 256, client_cancel.clone());

    let mut conn = retry_connect(proxy, target).await;
    client_cancel.cancel(); // the payload has not been sent yet

    let got = tokio::time::timeout(Duration::from_secs(10), async {
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.unwrap();
        buf
    })
    .await
    .expect("relay did not finish after client shutdown");
    assert_eq!(&got, b"survived-client-shutdown", "in-flight relay was cut");

    // …and once drained, the client actually stops.
    tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("client did not stop after draining")
        .unwrap();
    server_cancel.cancel();
}

/// A tunnel client that does not know the PSK must never become a route.
#[tokio::test]
async fn client_with_wrong_secret_is_not_registered() {
    let echo = spawn_tcp_echo().await;
    let (socks_port, tunnel_port) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let cancel = CancellationToken::new();
    start_server(socks_port, tunnel_port, cancel.clone());
    start_client_as("intruder", "not-the-secret", tunnel_port, 2, 256, 256, cancel.clone());
    wait_for_listener(proxy).await;

    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        socks5_connect(proxy, echo).await.is_err(),
        "a client with the wrong PSK was accepted as a tunnel route"
    );
    cancel.cancel();
}

/// A6: with two tunnel clients registered, losing one must not lose service.
#[tokio::test]
async fn requests_fail_over_when_a_tunnel_client_goes_away() {
    let echo = spawn_tcp_echo().await;
    let (socks_port, tunnel_port) = two_free_ports().await;
    let proxy: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let cancel = CancellationToken::new();
    let cancel_a = CancellationToken::new();
    start_server(socks_port, tunnel_port, cancel.clone());
    let client_a = start_client_as("client-a", SECRET, tunnel_port, 2, 256, 256, cancel_a.clone());
    start_client_as("client-b", SECRET, tunnel_port, 2, 256, 256, cancel.clone());

    drop(retry_connect(proxy, echo).await);
    tokio::time::sleep(Duration::from_millis(500)).await; // let both register

    cancel_a.cancel();
    client_a.await.unwrap();

    for i in 0..10 {
        let mut s = socks5_connect(proxy, echo)
            .await
            .unwrap_or_else(|e| panic!("request {i} failed after client-a left: {e}"));
        s.write_all(b"ok").await.unwrap();
        let mut got = [0u8; 2];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ok");
    }
    cancel.cancel();
}

// ───────────────────────── slow / manual (run with --ignored) ─────────────────────────

/// A7 safety net: the read watchdog (45s) must never kill a *healthy* idle
/// session — the 10s heartbeat keeps ping/pong flowing. Idle for longer than
/// the watchdog, then check the session was never re-established.
///
/// Slow (≈55s) and installs a global tracing subscriber, so it is `#[ignore]`d:
/// `cargo test --test tunnel_e2e idle_tunnel -- --ignored`
#[tokio::test]
#[ignore]
async fn idle_tunnel_session_survives_the_read_watchdog() {
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let logs = Capture::default();
    let writer = logs.clone();
    tracing_subscriber::fmt()
        .with_env_filter("sox=debug")
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();

    let echo = spawn_tcp_echo().await;
    let (proxy, cancel) = spawn_tunnel(2, 256, 256).await;
    drop(retry_connect(proxy, echo).await);

    tokio::time::sleep(Duration::from_secs(55)).await;

    let mut s = socks5_connect(proxy, echo).await.expect("idle tunnel stopped serving");
    s.write_all(b"still-here").await.unwrap();
    let mut got = [0u8; 10];
    s.read_exact(&mut got).await.unwrap();

    let text = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    let established = text.matches("tunnel session established").count();
    assert_eq!(established, 2, "sessions were re-established while idle:\n{text}");
    assert!(!text.contains("read-idle"), "watchdog fired on a healthy session:\n{text}");
    cancel.cancel();
}

/// Push `total` bytes through `proxy` to a sink and report throughput.
async fn bench_upload(label: &str, proxy: SocketAddr, total: usize) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink = listener.local_addr().unwrap();
    let received = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 256 * 1024];
        let mut n = 0usize;
        loop {
            match sock.read(&mut buf).await.unwrap() {
                0 => return n,
                k => n += k,
            }
        }
    });

    let mut conn = retry_connect(proxy, sink).await;
    let chunk = vec![0xA5u8; 256 * 1024];
    let start = std::time::Instant::now();
    let mut sent = 0;
    while sent < total {
        conn.write_all(&chunk).await.unwrap();
        sent += chunk.len();
    }
    conn.shutdown().await.unwrap();
    assert_eq!(received.await.unwrap(), sent);
    let secs = start.elapsed().as_secs_f64();
    println!(
        "BENCH {label}: {:.0} MiB in {secs:.2}s = {:.0} MiB/s ({:.2} Gbps)",
        sent as f64 / 1048576.0,
        sent as f64 / 1048576.0 / secs,
        sent as f64 * 8.0 / 1e9 / secs,
    );
}

/// `cargo test --release --test tunnel_e2e bench_ -- --ignored --nocapture --test-threads=1`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_tunnel_upload() {
    let (proxy, cancel) = spawn_tunnel(1, 256, 256).await;
    for round in 0..3 {
        bench_upload(&format!("tunnel round {round}"), proxy, 2 << 30).await;
    }
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_standalone_upload() {
    let (proxy, cancel) = spawn_standalone(sox::config::Config::default()).await;
    for round in 0..3 {
        bench_upload(&format!("standalone round {round}"), proxy, 4 << 30).await;
    }
    cancel.cancel();
}

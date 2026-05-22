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
    let cfg = sox::client::ClientConfig {
        server_addr: format!("127.0.0.1:{tunnel_port}"),
        secret: SECRET.to_string(),
        client_id: "e2e-client".into(),
        tunnel_sessions: sessions,
        max_streams,
        recv_window_mb,
        reconnect_interval: Duration::from_millis(200),
        reconnect_max: Duration::from_secs(2),
    };
    tokio::spawn(sox::client::run_client(cfg, cancel));
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

    // SOCKS5 UDP ASSOCIATE handshake.
    let mut ctrl = TcpStream::connect(proxy).await.unwrap();
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    ctrl.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    // UDP ASSOCIATE request (cmd 0x03), client UDP addr 0.0.0.0:0.
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    ctrl.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "UDP ASSOCIATE should succeed");
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay_addr: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();

    // Send a UDP datagram with a SOCKS5 UDP header pointing at the UDP echo server.
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_ip = match udp_echo.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => panic!("ipv4"),
    };
    let mut packet = vec![0x00, 0x00, 0x00, 0x01]; // rsv, frag, atyp=IPv4
    packet.extend_from_slice(&echo_ip);
    packet.extend_from_slice(&udp_echo.port().to_be_bytes());
    packet.extend_from_slice(b"udp-hello");

    // The relay learns the client addr from the first packet; retry a few times
    // in case the tunnel UDP stream is still being set up.
    let mut got = None;
    for _ in 0..30 {
        client_udp.send_to(&packet, relay_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        match tokio::time::timeout(Duration::from_millis(300), client_udp.recv_from(&mut buf)).await
        {
            Ok(Ok((n, _))) => {
                got = Some(buf[..n].to_vec());
                break;
            }
            _ => continue,
        }
    }

    cancel.cancel();

    let resp = got.expect("no UDP echo received through tunnel");
    // Response carries a SOCKS5 UDP header; the payload is the trailing bytes.
    assert!(
        resp.ends_with(b"udp-hello"),
        "UDP echo payload mismatch: {resp:?}"
    );
}

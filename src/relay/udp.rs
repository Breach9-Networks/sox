use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use crate::protocol::addr::TargetAddr;
use crate::protocol::socks5::udp::{parse_udp_header, write_udp_header, UdpHeader};
use crate::tunnel::protocol::UdpDatagram;

/// Run a UDP relay for a SOCKS5 UDP ASSOCIATE session.
///
/// The relay:
/// 1. Receives UDP datagrams from the client on `relay_socket`
/// 2. Strips the SOCKS5 UDP header, resolves the target, and forwards the payload
/// 3. Receives responses from targets and wraps them in SOCKS5 UDP headers
/// 4. Monitors the TCP control stream — when it closes, the relay shuts down
///
/// Fragmented datagrams (frag != 0) are dropped per standard practice.
pub async fn relay_udp(
    tcp_control: TcpStream,
    relay_socket: UdpSocket,
    peer_ip: IpAddr,
    cancel: CancellationToken,
) -> io::Result<()> {
    let relay_socket = std::sync::Arc::new(relay_socket);

    // Map: target SocketAddr -> dedicated UdpSocket for that target
    let target_sockets: std::sync::Arc<tokio::sync::Mutex<HashMap<SocketAddr, std::sync::Arc<UdpSocket>>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // The client's UDP address — its port is not known until the first
    // datagram arrives, so it is learned dynamically and shared with the
    // reverse relays.
    let learned_client: Arc<std::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(None));

    // Task 1: Monitor TCP control stream for closure
    let cancel_tcp = cancel.clone();
    let tcp_monitor = tokio::spawn(async move {
        let mut buf = [0u8; 1];
        // When TCP stream closes or errors, cancel everything
        let _ = tcp_control.readable().await;
        // Try to read — EOF means client disconnected
        match tcp_control.try_read(&mut buf) {
            Ok(0) | Err(_) => {}
            Ok(_) => {
                // Unexpected data on control stream, ignore
            }
        }
        cancel_tcp.cancel();
    });

    // Task 2: Client → Target relay
    let relay_c2t = relay_socket.clone();
    let targets_c2t = target_sockets.clone();
    let cancel_c2t = cancel.clone();
    let relay_fwd = relay_socket.clone();
    let targets_fwd = target_sockets.clone();
    let learned_c2t = learned_client.clone();

    let client_to_target = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                biased;
                _ = cancel_c2t.cancelled() => break,
                result = relay_c2t.recv_from(&mut buf) => {
                    let (n, src) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(error = %e, "UDP recv error");
                            break;
                        }
                    };

                    // Accept packets from the original client's IP; learn its
                    // full address (including port) from the first one seen.
                    if src.ip() != peer_ip {
                        tracing::trace!(%src, %peer_ip, "dropping UDP from unexpected source");
                        continue;
                    }
                    *learned_c2t.lock().unwrap() = Some(src);

                    // Parse SOCKS5 UDP header
                    let (header, payload_offset) = match parse_udp_header(&buf[..n]) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(error = %e, "invalid UDP header");
                            continue;
                        }
                    };

                    // Drop fragmented packets
                    if header.frag != 0 {
                        tracing::trace!(frag = header.frag, "dropping fragmented UDP");
                        continue;
                    }

                    let payload = &buf[payload_offset..n];

                    // Resolve target
                    let target_addr = match resolve_udp_target(&header.target).await {
                        Ok(addr) => addr,
                        Err(e) => {
                            tracing::debug!(target = %header.target, error = %e, "UDP target resolution failed");
                            continue;
                        }
                    };

                    // Get or create a socket for this target
                    let target_socket = {
                        let mut targets = targets_c2t.lock().await;
                        if let Some(sock) = targets.get(&target_addr) {
                            sock.clone()
                        } else {
                            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                                Ok(s) => std::sync::Arc::new(s),
                                Err(e) => {
                                    tracing::debug!(error = %e, "failed to bind UDP socket for target");
                                    continue;
                                }
                            };
                            targets.insert(target_addr, sock.clone());

                            // Spawn reverse relay for this target
                            let relay_back = relay_fwd.clone();
                            let sock_back = sock.clone();
                            let cancel_back = cancel_c2t.clone();
                            let learned_back = learned_c2t.clone();
                            let target_for_header = header.target.clone();

                            tokio::spawn(async move {
                                target_to_client(
                                    sock_back,
                                    relay_back,
                                    learned_back,
                                    target_for_header,
                                    cancel_back,
                                )
                                .await;
                            });

                            sock
                        }
                    };

                    // Forward payload to target
                    if let Err(e) = target_socket.send_to(payload, target_addr).await {
                        tracing::debug!(%target_addr, error = %e, "UDP forward failed");
                    }
                }
            }
        }
    });

    // Wait for cancellation or completion
    let _ = tokio::join!(tcp_monitor, client_to_target);

    // Clean up target sockets
    let mut targets = targets_fwd.lock().await;
    targets.clear();

    Ok(())
}

/// Reverse direction: Target → Client
async fn target_to_client(
    target_socket: std::sync::Arc<UdpSocket>,
    relay_socket: std::sync::Arc<UdpSocket>,
    learned_client: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    target_addr: TargetAddr,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = target_socket.recv_from(&mut buf) => {
                let (n, _src) = match result {
                    Ok(v) => v,
                    Err(_) => break,
                };

                // The client address is known only after its first packet.
                let Some(client_addr) = *learned_client.lock().unwrap() else {
                    continue;
                };

                // Wrap response in SOCKS5 UDP header
                let header = UdpHeader {
                    frag: 0,
                    target: target_addr.clone(),
                };
                let mut packet = Vec::with_capacity(10 + n);
                write_udp_header(&header, &mut packet);
                packet.extend_from_slice(&buf[..n]);

                // Send back to client
                if let Err(e) = relay_socket.send_to(&packet, client_addr).await {
                    tracing::debug!(%client_addr, error = %e, "UDP response send failed");
                    break;
                }
            }
        }
    }
}

/// Resolve a TargetAddr to SocketAddr for UDP forwarding.
pub async fn resolve_udp_target(target: &TargetAddr) -> io::Result<SocketAddr> {
    match target {
        TargetAddr::Ip(addr) => Ok(*addr),
        TargetAddr::Domain(domain, port) => {
            let addr_str = format!("{domain}:{port}");
            tokio::net::lookup_host(&addr_str)
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "DNS resolution returned no addresses")
                })
        }
    }
}

// ───────────────────────── UDP over tunnel ─────────────────────────

/// 從 stream 精確讀出一則 framed `UdpDatagram`（`[len:u16][body]`，不超讀）。
pub async fn read_udp_datagram<S>(s: &mut S) -> io::Result<UdpDatagram>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    s.read_exact(&mut len_buf).await?;
    let body_len = u16::from_be_bytes(len_buf) as usize;
    let mut frame = vec![0u8; 2 + body_len];
    frame[..2].copy_from_slice(&len_buf);
    s.read_exact(&mut frame[2..]).await?;
    match UdpDatagram::decode(&frame) {
        Ok(Some((dat, _))) => Ok(dat),
        Ok(None) => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete UDP datagram",
        )),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}

/// Server 端 UDP relay：把 SOCKS-client-facing 的 `relay_socket` 與一條
/// 承載 `UdpDatagram` 的 yamux stream 對接。TCP 控制通道關閉即收工。
pub async fn relay_udp_tunneled<S>(
    tcp_control: TcpStream,
    relay_socket: UdpSocket,
    peer_ip: IpAddr,
    stream: S,
    cancel: CancellationToken,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let sock = Arc::new(relay_socket);
    let (sr, sw) = tokio::io::split(stream);
    // 從首個封包學到的 SOCKS client UDP 位址（兩個方向共用）。
    let client_addr: Arc<std::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(None));

    // TCP 控制通道關閉 → 取消整個 relay。
    let cancel_tcp = cancel.clone();
    let tcp_monitor = tokio::spawn(async move {
        let mut b = [0u8; 1];
        let _ = tcp_control.readable().await;
        let _ = tcp_control.try_read(&mut b);
        cancel_tcp.cancel();
    });

    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = udp_c2t(sock.clone(), peer_ip, client_addr.clone(), sw) => {}
        _ = udp_t2c(sock, client_addr, sr) => {}
    }
    tcp_monitor.abort();
    Ok(())
}

/// 方向 A：SOCKS client → tunnel。
async fn udp_c2t<W>(
    sock: Arc<UdpSocket>,
    peer_ip: IpAddr,
    client_addr: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    mut sw: W,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        if src.ip() != peer_ip {
            continue; // 只收原 client IP 的封包
        }
        *client_addr.lock().unwrap() = Some(src);
        let (header, off) = match parse_udp_header(&buf[..n]) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if header.frag != 0 {
            continue; // 不支援分片
        }
        let dat = UdpDatagram {
            addr: header.target,
            payload: buf[off..n].to_vec(),
        };
        sw.write_all(&dat.encode()).await?;
    }
}

/// 方向 B：tunnel → SOCKS client。
async fn udp_t2c<R>(
    sock: Arc<UdpSocket>,
    client_addr: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    mut sr: R,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let dat = read_udp_datagram(&mut sr).await?;
        let dest = match *client_addr.lock().unwrap() {
            Some(a) => a,
            None => continue, // 還沒看過 client 封包，無處可回
        };
        let header = UdpHeader { frag: 0, target: dat.addr };
        let mut packet = Vec::with_capacity(22 + dat.payload.len());
        write_udp_header(&header, &mut packet);
        packet.extend_from_slice(&dat.payload);
        sock.send_to(&packet, dest).await?;
    }
}

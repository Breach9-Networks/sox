use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use crate::protocol::addr::TargetAddr;
use crate::protocol::socks5::udp::{parse_udp_header, write_udp_header, UdpHeader};

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
    client_addr: SocketAddr,
    cancel: CancellationToken,
) -> io::Result<()> {
    let relay_socket = std::sync::Arc::new(relay_socket);

    // Map: target SocketAddr -> dedicated UdpSocket for that target
    let target_sockets: std::sync::Arc<tokio::sync::Mutex<HashMap<SocketAddr, std::sync::Arc<UdpSocket>>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new()));

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

                    // Only accept packets from the original client
                    if src != client_addr {
                        tracing::trace!(%src, %client_addr, "dropping UDP from unexpected source");
                        continue;
                    }

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
                            let target_for_header = header.target.clone();

                            tokio::spawn(async move {
                                target_to_client(
                                    sock_back,
                                    relay_back,
                                    client_addr,
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
    client_addr: SocketAddr,
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
async fn resolve_udp_target(target: &TargetAddr) -> io::Result<SocketAddr> {
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

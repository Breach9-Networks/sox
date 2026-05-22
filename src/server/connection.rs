use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::error::{ProtocolError, ServerError};
use crate::protocol::addr::TargetAddr;
use crate::protocol::detect::{SocksVersion, detect_version};
use crate::protocol::socks4::{
    Socks4Command, Socks4Reply, parse_socks4_request, write_socks4_reply,
};
use crate::protocol::socks5::command::parse_command_request;
use crate::protocol::socks5::handshake::{
    parse_method_request, parse_userpass_request, write_method_response, write_userpass_response,
};
use crate::protocol::socks5::reply::write_command_reply;
use crate::protocol::socks5::{AuthMethod, ReplyCode, Socks5Command};
use crate::relay::tcp::{relay_bidirectional, relay_tcp_live};
use crate::relay::udp::{relay_udp, relay_udp_tunneled};
use crate::server::ServerContext;

/// Handle a SOCKS connection — detects version (4/5) then dispatches.
/// Handle a SOCKS connection. Returns the authenticated username (if any)
/// so the caller can track user lifecycle in extended metrics.
pub async fn handle_connection(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    ctx: &ServerContext,
) -> (Option<String>, Result<(), ServerError>) {
    let config = &ctx.config;

    // Read first byte to detect SOCKS version
    let first_byte = match tokio::time::timeout(config.handshake_timeout, async {
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;
        Ok::<u8, std::io::Error>(buf[0])
    })
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return (None, Err(ServerError::Io(e))),
        Err(_) => return (None, Err(ServerError::Timeout)),
    };

    match detect_version(first_byte) {
        Some(SocksVersion::V5) => handle_socks5(stream, peer_addr, ctx, first_byte).await,
        Some(SocksVersion::V4) => (None, handle_socks4(stream, peer_addr, ctx).await),
        None => (
            None,
            Err(ServerError::Protocol(ProtocolError::InvalidVersion(first_byte))),
        ),
    }
}

/// Handle a SOCKS5 connection. Returns (authenticated_username, result).
async fn handle_socks5(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    ctx: &ServerContext,
    first_byte: u8,
) -> (Option<String>, Result<(), ServerError>) {
    let mut authed_user: Option<String> = None;
    let result = handle_socks5_inner(stream, peer_addr, ctx, first_byte, &mut authed_user).await;
    (authed_user, result)
}

async fn handle_socks5_inner(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    ctx: &ServerContext,
    first_byte: u8,
    authed_user: &mut Option<String>,
) -> Result<(), ServerError> {
    let config = &ctx.config;

    // Read remaining method negotiation bytes
    // We already have first_byte = 0x05, now read the rest
    let methods = tokio::time::timeout(config.handshake_timeout, async {
        let mut header = [0u8; 1];
        stream.read_exact(&mut header).await?;
        let nmethods = header[0] as usize;

        let mut method_buf = vec![0u8; nmethods];
        stream.read_exact(&mut method_buf).await?;

        // Reconstruct full buffer for parsing
        let mut full = Vec::with_capacity(2 + nmethods);
        full.push(first_byte);
        full.push(header[0]);
        full.extend_from_slice(&method_buf);

        parse_method_request(&full).map_err(ServerError::Protocol)
    })
    .await
    .map_err(|_| ServerError::Timeout)??;

    // Select auth method based on server config
    let requires_auth = ctx.auth.is_some();

    let selected = if requires_auth {
        if methods.contains(&AuthMethod::UsernamePassword) {
            AuthMethod::UsernamePassword
        } else {
            let mut reply = Vec::new();
            write_method_response(AuthMethod::NoAcceptable, &mut reply);
            stream.write_all(&reply).await?;
            return Err(ServerError::Protocol(ProtocolError::NoAcceptableMethod));
        }
    } else if methods.contains(&AuthMethod::None) {
        AuthMethod::None
    } else {
        let mut reply = Vec::new();
        write_method_response(AuthMethod::NoAcceptable, &mut reply);
        stream.write_all(&reply).await?;
        return Err(ServerError::Protocol(ProtocolError::NoAcceptableMethod));
    };

    let mut reply = Vec::new();
    write_method_response(selected, &mut reply);
    stream.write_all(&reply).await?;

    // Username/password subnegotiation (RFC 1929)
    if selected == AuthMethod::UsernamePassword {
        let auth_result = tokio::time::timeout(config.handshake_timeout, async {
            let mut buf = [0u8; 513];
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(ServerError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "client closed during auth",
                )));
            }
            parse_userpass_request(&buf[..n]).map_err(ServerError::Protocol)
        })
        .await
        .map_err(|_| ServerError::Timeout)??;

        let (username, password) = auth_result;
        let provider = ctx.auth.as_ref().unwrap();
        let authenticated = provider.authenticate(&username, &password);

        let mut reply = Vec::new();
        write_userpass_response(authenticated, &mut reply);
        stream.write_all(&reply).await?;

        if !authenticated {
            tracing::debug!(%peer_addr, %username, "authentication failed");
            return Err(ServerError::Protocol(ProtocolError::NoAcceptableMethod));
        }

        *authed_user = Some(username.clone());
        tracing::debug!(%peer_addr, %username, "authenticated");
    }

    // Command request
    let cmd_request = tokio::time::timeout(config.handshake_timeout, async {
        let mut buf = [0u8; 262];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed during command",
            )));
        }
        let (req, _) = parse_command_request(&buf[..n]).map_err(ServerError::Protocol)?;
        Ok(req)
    })
    .await
    .map_err(|_| ServerError::Timeout)??;

    tracing::debug!(
        %peer_addr,
        command = ?cmd_request.command,
        target = %cmd_request.target,
        "SOCKS5 request"
    );

    match cmd_request.command {
        Socks5Command::Connect => {
            handle_connect(stream, peer_addr, &cmd_request.target, ctx).await
        }
        Socks5Command::UdpAssociate => {
            handle_udp_associate(stream, peer_addr, ctx).await
        }
        Socks5Command::Bind => {
            let mut reply = Vec::new();
            write_command_reply(
                ReplyCode::CommandNotSupported,
                &TargetAddr::unspecified(),
                &mut reply,
            );
            stream.write_all(&reply).await?;
            Err(ServerError::CommandNotSupported)
        }
    }
}

/// Handle a SOCKS4/4a connection. Version byte (0x04) has already been consumed.
async fn handle_socks4(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    ctx: &ServerContext,
) -> Result<(), ServerError> {
    let config = &ctx.config;

    // Read the rest of the SOCKS4 request
    let request = tokio::time::timeout(config.handshake_timeout, async {
        // SOCKS4 requests are variable length, read a generous chunk
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed during SOCKS4 request",
            )));
        }
        let (req, _) = parse_socks4_request(&buf[..n]).map_err(ServerError::Protocol)?;
        Ok(req)
    })
    .await
    .map_err(|_| ServerError::Timeout)??;

    tracing::debug!(
        %peer_addr,
        command = ?request.command,
        target = %request.target,
        user_id = %request.user_id,
        "SOCKS4 request"
    );

    match request.command {
        Socks4Command::Connect => {
            handle_socks4_connect(stream, peer_addr, &request.target, ctx).await
        }
        Socks4Command::Bind => {
            let mut reply = Vec::new();
            write_socks4_reply(Socks4Reply::Rejected, None, &mut reply);
            stream.write_all(&reply).await?;
            Err(ServerError::CommandNotSupported)
        }
    }
}

/// Handle SOCKS4 CONNECT.
async fn handle_socks4_connect(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    target: &TargetAddr,
    ctx: &ServerContext,
) -> Result<(), ServerError> {
    let config = &ctx.config;
    let target_addr = resolve_target(target, config).await?;

    let mut target_stream =
        match tokio::time::timeout(config.connect_timeout, TcpStream::connect(target_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let mut reply = Vec::new();
                write_socks4_reply(Socks4Reply::Rejected, None, &mut reply);
                stream.write_all(&reply).await?;
                return Err(ServerError::Io(e));
            }
            Err(_) => {
                let mut reply = Vec::new();
                write_socks4_reply(Socks4Reply::Rejected, None, &mut reply);
                stream.write_all(&reply).await?;
                return Err(ServerError::Timeout);
            }
        };

    configure_target_socket(&target_stream, config)?;

    // SOCKS4 reply with bound address
    let bind_v4 = target_stream
        .local_addr()
        .ok()
        .and_then(|a| match a {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

    let mut reply = Vec::new();
    write_socks4_reply(Socks4Reply::Granted, Some(bind_v4), &mut reply);
    stream.write_all(&reply).await?;

    tracing::debug!(
        %peer_addr,
        %target,
        "SOCKS4 CONNECT established, starting relay"
    );

    let relay_result = tokio::time::timeout(
        config.idle_timeout,
        relay_tcp_live(
            stream,
            &mut target_stream,
            Some(&ctx.metrics.bytes_client_to_target),
            Some(&ctx.metrics.bytes_target_to_client),
        ),
    )
    .await;

    let (c2s, s2c) = match relay_result {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            tracing::debug!(%peer_addr, %target, error = %e, "relay error");
            return Err(ServerError::Io(e));
        }
        Err(_) => {
            tracing::debug!(%peer_addr, %target, "relay idle timeout");
            return Err(ServerError::Timeout);
        }
    };

    tracing::debug!(%peer_addr, %target, c2s, s2c, "SOCKS4 relay finished");

    Ok(())
}

/// Handle SOCKS5 CONNECT command.
/// In standalone mode: connects directly. In tunnel mode: routes through a tunnel client.
async fn handle_connect(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    target: &TargetAddr,
    ctx: &ServerContext,
) -> Result<(), ServerError> {
    // Tunnel mode: route through a tunnel client
    if let Some(router) = &ctx.router {
        return handle_connect_via_tunnel(stream, peer_addr, target, ctx, router).await;
    }

    // Standalone mode: connect directly
    let config = &ctx.config;
    let target_addr = resolve_target(target, config).await?;

    let mut target_stream =
        match tokio::time::timeout(config.connect_timeout, TcpStream::connect(target_addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                let code = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => ReplyCode::ConnectionRefused,
                    std::io::ErrorKind::AddrNotAvailable => ReplyCode::HostUnreachable,
                    _ => ReplyCode::GeneralFailure,
                };
                let mut reply = Vec::new();
                write_command_reply(code, &TargetAddr::unspecified(), &mut reply);
                stream.write_all(&reply).await?;
                return Err(ServerError::Io(e));
            }
            Err(_) => {
                let mut reply = Vec::new();
                write_command_reply(
                    ReplyCode::TtlExpired,
                    &TargetAddr::unspecified(),
                    &mut reply,
                );
                stream.write_all(&reply).await?;
                return Err(ServerError::Timeout);
            }
        };

    configure_target_socket(&target_stream, config)?;

    let bind_addr = match target_stream.local_addr() {
        Ok(addr) => TargetAddr::Ip(addr),
        Err(_) => TargetAddr::unspecified(),
    };
    let mut reply = Vec::new();
    write_command_reply(ReplyCode::Succeeded, &bind_addr, &mut reply);
    stream.write_all(&reply).await?;

    tracing::debug!(
        %peer_addr, %target, bind = %bind_addr,
        "CONNECT established, starting relay"
    );

    let relay_result = tokio::time::timeout(
        config.idle_timeout,
        relay_tcp_live(
            stream,
            &mut target_stream,
            Some(&ctx.metrics.bytes_client_to_target),
            Some(&ctx.metrics.bytes_target_to_client),
        ),
    )
    .await;

    let (c2s, s2c) = match relay_result {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            tracing::debug!(%peer_addr, %target, error = %e, "relay error");
            return Err(ServerError::Io(e));
        }
        Err(_) => {
            tracing::debug!(%peer_addr, %target, "relay idle timeout");
            return Err(ServerError::Timeout);
        }
    };

    tracing::debug!(%peer_addr, %target, c2s, s2c, "relay finished");

    Ok(())
}

/// Handle SOCKS5 CONNECT via a tunnel client (yamux multiplexed).
async fn handle_connect_via_tunnel(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    target: &TargetAddr,
    ctx: &ServerContext,
    router: &std::sync::Arc<crate::tunnel::router::Router>,
) -> Result<(), ServerError> {
    use crate::tunnel::protocol::{StreamOpen, StreamReply};
    use std::sync::atomic::{AtomicBool, Ordering as AtomOrd};
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    // Rate-limit "no tunnel clients" warning: log once on transition, not per-request
    static NO_CLIENTS_LOGGED: AtomicBool = AtomicBool::new(false);

    let config = &ctx.config;
    let target_str = target.to_string();

    // Open a fresh yamux stream on one of the tunnel client's sessions.
    let tunnel = match router.open_stream(None).await {
        Some(t) => {
            if NO_CLIENTS_LOGGED.swap(false, AtomOrd::Relaxed) {
                tracing::info!("tunnel client available again");
            }
            t
        }
        None => {
            if !NO_CLIENTS_LOGGED.swap(true, AtomOrd::Relaxed) {
                tracing::warn!("no tunnel clients available (suppressing further warnings)");
            }
            let mut reply = Vec::new();
            write_command_reply(
                ReplyCode::GeneralFailure,
                &TargetAddr::unspecified(),
                &mut reply,
            );
            stream.write_all(&reply).await?;
            return Err(ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "no tunnel clients available",
            )));
        }
    };

    let crate::tunnel::router::TunnelStream { stream: yamux_stream, tx_bytes, rx_bytes } = tunnel;
    let mut tunnel_io = yamux_stream.compat();

    tracing::debug!(%peer_addr, %target, "routing CONNECT through tunnel");

    // Write the StreamOpen preamble, then read the client's StreamReply.
    let preamble = StreamOpen::Tcp { target: target_str }.encode();
    tunnel_io.write_all(&preamble).await?;

    let reply: StreamReply =
        match tokio::time::timeout(config.connect_timeout, read_stream_reply(&mut tunnel_io)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(ServerError::Io(e)),
            Err(_) => return Err(ServerError::Timeout),
        };

    if reply.status != 0 {
        tracing::debug!(%peer_addr, %target, reason = %reply.message, "tunnel client connect failed");
        let mut buf = Vec::new();
        write_command_reply(
            ReplyCode::from_u8(reply.status),
            &TargetAddr::unspecified(),
            &mut buf,
        );
        stream.write_all(&buf).await?;
        return Err(ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            reply.message,
        )));
    }

    // Success — reply to the SOCKS client, then relay.
    let mut buf = Vec::new();
    write_command_reply(ReplyCode::Succeeded, &TargetAddr::unspecified(), &mut buf);
    stream.write_all(&buf).await?;

    tracing::debug!(%peer_addr, %target, "tunnel CONNECT established, starting relay");

    // "tx" = SOCKS client -> target ; "rx" = target -> SOCKS client.
    let relay_result = tokio::time::timeout(
        config.idle_timeout,
        relay_bidirectional(
            stream,
            &mut tunnel_io,
            Some(tx_bytes.as_ref()),
            Some(rx_bytes.as_ref()),
        ),
    )
    .await;

    let (c2s, s2c) = match relay_result {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            tracing::debug!(%peer_addr, %target, error = %e, "tunnel relay error");
            return Err(ServerError::Io(e));
        }
        Err(_) => {
            tracing::debug!(%peer_addr, %target, "tunnel relay idle timeout");
            return Err(ServerError::Timeout);
        }
    };

    ctx.metrics.bytes_client_to_target.fetch_add(c2s, AtomOrd::Relaxed);
    ctx.metrics.bytes_target_to_client.fetch_add(s2c, AtomOrd::Relaxed);

    tracing::debug!(%peer_addr, %target, c2s, s2c, "tunnel relay finished");
    Ok(())
}

/// Read a `StreamReply` preamble exactly off a tunnel stream (no over-read).
async fn read_stream_reply<S>(s: &mut S) -> std::io::Result<crate::tunnel::protocol::StreamReply>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut head = [0u8; 3];
    s.read_exact(&mut head).await?;
    let msg_len = u16::from_be_bytes([head[1], head[2]]) as usize;
    let mut msg = vec![0u8; msg_len];
    s.read_exact(&mut msg).await?;
    Ok(crate::tunnel::protocol::StreamReply {
        status: head[0],
        message: String::from_utf8_lossy(&msg).into_owned(),
    })
}

/// Handle SOCKS5 UDP ASSOCIATE command.
async fn handle_udp_associate(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    ctx: &ServerContext,
) -> Result<(), ServerError> {
    // Bind a UDP relay socket for the SOCKS client to send datagrams to.
    let relay_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let relay_addr = relay_socket.local_addr()?;

    tracing::debug!(%peer_addr, relay = %relay_addr, "UDP ASSOCIATE relay bound");

    // Reply with the relay socket address.
    let bind_addr = TargetAddr::Ip(relay_addr);
    let mut reply = Vec::new();
    write_command_reply(ReplyCode::Succeeded, &bind_addr, &mut reply);
    stream.write_all(&reply).await?;

    // When the TCP control stream closes, the UDP relay must stop.
    let cancel = CancellationToken::new();

    // Duplicate the TCP stream FD so the relay can monitor it for closure
    // while the original stays valid.
    let tcp_control = {
        let sock_ref = SockRef::from(&*stream);
        let dup_socket = sock_ref.try_clone()?;
        TcpStream::from_std(std::net::TcpStream::from(dup_socket))?
    };

    // Tunnel mode: route UDP through a tunnel client.
    if let Some(router) = &ctx.router {
        return handle_udp_associate_via_tunnel(
            peer_addr, relay_socket, tcp_control, ctx, router, cancel,
        )
        .await;
    }

    // Standalone mode: relay directly from this server.
    let client_udp_addr = SocketAddr::new(peer_addr.ip(), 0);
    let relay_result = tokio::time::timeout(
        ctx.config.idle_timeout,
        relay_udp(tcp_control, relay_socket, client_udp_addr, cancel),
    )
    .await;

    match relay_result {
        Ok(Ok(())) => {
            tracing::debug!(%peer_addr, "UDP ASSOCIATE relay finished");
            Ok(())
        }
        Ok(Err(e)) => Err(ServerError::Io(e)),
        Err(_) => Err(ServerError::Timeout),
    }
}

/// Route a UDP ASSOCIATE session through a tunnel client over a yamux stream.
async fn handle_udp_associate_via_tunnel(
    peer_addr: SocketAddr,
    relay_socket: UdpSocket,
    tcp_control: TcpStream,
    ctx: &ServerContext,
    router: &std::sync::Arc<crate::tunnel::router::Router>,
    cancel: CancellationToken,
) -> Result<(), ServerError> {
    use crate::tunnel::protocol::StreamOpen;
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    let tunnel = router.open_stream(None).await.ok_or_else(|| {
        ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "no tunnel clients available",
        ))
    })?;
    let mut tunnel_io = tunnel.stream.compat();

    // Open a UDP stream: write the preamble, await the client's reply.
    tunnel_io.write_all(&StreamOpen::Udp.encode()).await?;
    let reply = match tokio::time::timeout(
        ctx.config.connect_timeout,
        read_stream_reply(&mut tunnel_io),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(ServerError::Io(e)),
        Err(_) => return Err(ServerError::Timeout),
    };
    if reply.status != 0 {
        return Err(ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            reply.message,
        )));
    }

    tracing::debug!(%peer_addr, "UDP ASSOCIATE routed through tunnel");

    let relay_result = tokio::time::timeout(
        ctx.config.idle_timeout,
        relay_udp_tunneled(tcp_control, relay_socket, peer_addr.ip(), tunnel_io, cancel),
    )
    .await;

    match relay_result {
        Ok(Ok(())) => {
            tracing::debug!(%peer_addr, "tunnel UDP ASSOCIATE finished");
            Ok(())
        }
        Ok(Err(e)) => Err(ServerError::Io(e)),
        Err(_) => Err(ServerError::Timeout),
    }
}

/// Configure target socket: NODELAY + keepalive.
fn configure_target_socket(stream: &TcpStream, config: &Config) -> Result<(), std::io::Error> {
    let sock_ref = SockRef::from(stream);
    sock_ref.set_nodelay(true)?;

    let keepalive = socket2::TcpKeepalive::new()
        .with_time(config.tcp_keepalive_idle)
        .with_interval(config.tcp_keepalive_interval);

    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    let keepalive = keepalive.with_retries(config.tcp_keepalive_probes);

    sock_ref.set_tcp_keepalive(&keepalive)?;
    Ok(())
}

/// Resolve a TargetAddr to a SocketAddr via DNS if needed.
async fn resolve_target(target: &TargetAddr, config: &Config) -> Result<SocketAddr, ServerError> {
    match target {
        TargetAddr::Ip(addr) => Ok(*addr),
        TargetAddr::Domain(domain, port) => {
            let addr_str = format!("{domain}:{port}");
            let resolved = tokio::time::timeout(
                config.dns_timeout,
                tokio::net::lookup_host(&addr_str),
            )
            .await
            .map_err(|_| {
                ServerError::DnsResolution(
                    domain.clone(),
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS timeout"),
                )
            })?
            .map_err(|e| ServerError::DnsResolution(domain.clone(), e))?
            .next()
            .ok_or_else(|| {
                ServerError::DnsResolution(
                    domain.clone(),
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no addresses found",
                    ),
                )
            })?;

            tracing::trace!(domain = %domain, resolved = %resolved, "DNS resolved");
            Ok(resolved)
        }
    }
}

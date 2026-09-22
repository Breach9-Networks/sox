use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

use crate::config::Config;
use crate::error::{ProtocolError, ServerError};
use crate::net;
use crate::protocol::addr::TargetAddr;
use crate::protocol::detect::{SocksVersion, detect_version};
use crate::protocol::socks4::{
    Socks4Command, Socks4Reply, Socks4Request, parse_socks4_request, write_socks4_reply,
};
use crate::protocol::socks5::command::{CommandRequest, parse_command_request};
use crate::protocol::socks5::handshake::{
    parse_method_request, parse_userpass_request, write_method_response, write_userpass_response,
};
use crate::protocol::socks5::reply::write_command_reply;
use crate::protocol::socks5::{AuthMethod, ReplyCode, Socks5Command};
use crate::relay::tcp::{relay_bidirectional, relay_tcp_live};
use crate::relay::udp::{relay_udp, relay_udp_tunneled};
use crate::server::ServerContext;
use crate::server::extended_metrics::UserSessionGuard;
use crate::tunnel::protocol::{StreamOpen, StreamReply};
use crate::tunnel::router::{Router, TunnelStream};

/// Longest NUL-terminated field (user id, SOCKS4a domain) accepted in a
/// SOCKS4 request.
const SOCKS4_MAX_FIELD: usize = 255;

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// A fully negotiated SOCKS request, ready to be served.
enum Negotiated<'a> {
    V5 {
        request: CommandRequest,
        /// Keeps the authenticated user counted as active for the whole
        /// connection, not just the handshake.
        _user: Option<UserSessionGuard<'a>>,
    },
    V4(Socks4Request),
}

/// Handle a SOCKS connection — negotiates (SOCKS4/4a/5), then serves the
/// request.
///
/// The whole negotiation — version byte, method selection, authentication and
/// the command request — shares **one** `handshake_timeout` deadline. A
/// timeout per phase would hand a slow-loris client several times the budget.
pub async fn handle_connection(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    ctx: &ServerContext,
) -> Result<(), ServerError> {
    let deadline = Instant::now() + ctx.config.handshake_timeout;
    let negotiated = tokio::time::timeout_at(deadline, negotiate(stream, peer_addr, ctx))
        .await
        .map_err(|_| ServerError::Timeout)??;

    match negotiated {
        Negotiated::V5 { request, _user } => {
            tracing::debug!(
                %peer_addr,
                command = ?request.command,
                target = %request.target,
                "SOCKS5 request"
            );
            match request.command {
                Socks5Command::Connect => {
                    handle_connect(stream, peer_addr, &request.target, ctx).await
                }
                Socks5Command::UdpAssociate => handle_udp_associate(stream, peer_addr, ctx).await,
                Socks5Command::Bind => {
                    reply_socks5_failure(stream, ReplyCode::CommandNotSupported).await;
                    Err(ServerError::CommandNotSupported)
                }
            }
        }
        Negotiated::V4(request) => {
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
    }
}

/// Detect the SOCKS version and run that version's negotiation.
///
/// Every read is **exact** — sized from the protocol's own length fields, or
/// up to a NUL terminator. Nothing past the request is consumed, so a client
/// that pipelines payload right behind its request loses no bytes; and a
/// request split across TCP segments is simply read in several steps.
async fn negotiate<'a>(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    ctx: &'a ServerContext,
) -> Result<Negotiated<'a>, ServerError> {
    let version = stream.read_u8().await?;
    match detect_version(version) {
        Some(SocksVersion::V5) => negotiate_socks5(stream, peer_addr, ctx, version).await,
        Some(SocksVersion::V4) => Ok(Negotiated::V4(read_socks4_request(stream).await?)),
        None => Err(ServerError::Protocol(ProtocolError::InvalidVersion(version))),
    }
}

async fn negotiate_socks5<'a>(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    ctx: &'a ServerContext,
    version: u8,
) -> Result<Negotiated<'a>, ServerError> {
    // Method negotiation: [version, nmethods, methods…] — version already read.
    let mut greeting = [0u8; 2 + 255];
    greeting[0] = version;
    greeting[1] = stream.read_u8().await?;
    let end = 2 + greeting[1] as usize;
    stream.read_exact(&mut greeting[2..end]).await?;
    let methods = parse_method_request(&greeting[..end])?;

    // Select auth method based on server config
    let wanted = match ctx.auth {
        Some(_) => AuthMethod::UsernamePassword,
        None => AuthMethod::None,
    };
    let selected = if methods.contains(&wanted) {
        wanted
    } else {
        AuthMethod::NoAcceptable
    };
    let mut reply = Vec::new();
    write_method_response(selected, &mut reply);
    stream.write_all(&reply).await?;
    if selected == AuthMethod::NoAcceptable {
        return Err(ServerError::Protocol(ProtocolError::NoAcceptableMethod));
    }

    // Username/password subnegotiation (RFC 1929):
    // [version, ulen, uname…, plen, passwd…]
    let mut user_guard = None;
    if let Some(provider) = &ctx.auth {
        let mut auth = [0u8; 3 + 255 + 255];
        stream.read_exact(&mut auth[..2]).await?;
        let plen_at = 2 + auth[1] as usize;
        stream.read_exact(&mut auth[2..=plen_at]).await?;
        let end = plen_at + 1 + auth[plen_at] as usize;
        stream.read_exact(&mut auth[plen_at + 1..end]).await?;
        let (username, password) = parse_userpass_request(&auth[..end])?;

        let authenticated = provider.authenticate(&username, &password);
        let mut reply = Vec::new();
        write_userpass_response(authenticated, &mut reply);
        stream.write_all(&reply).await?;

        if !authenticated {
            tracing::debug!(%peer_addr, %username, "authentication failed");
            bump(&ctx.extended_metrics.errors_auth_rejected);
            return Err(ServerError::Protocol(ProtocolError::NoAcceptableMethod));
        }
        tracing::debug!(%peer_addr, %username, "authenticated");
        user_guard = Some(ctx.extended_metrics.user_session(&username));
    }

    // Command request: [version, cmd, rsv, atyp, addr…, port(2)]
    let mut cmd = [0u8; 4 + 1 + 255 + 2];
    stream.read_exact(&mut cmd[..4]).await?;
    let end = match cmd[3] {
        0x01 => 4 + 4 + 2,
        0x04 => 4 + 16 + 2,
        0x03 => {
            cmd[4] = stream.read_u8().await?;
            5 + cmd[4] as usize + 2
        }
        other => return Err(ServerError::Protocol(ProtocolError::InvalidAddressType(other))),
    };
    let already = if cmd[3] == 0x03 { 5 } else { 4 };
    stream.read_exact(&mut cmd[already..end]).await?;
    let (request, _) = parse_command_request(&cmd[..end])?;

    Ok(Negotiated::V5 { request, _user: user_guard })
}

/// Read a SOCKS4/4a request. The version byte (0x04) has already been consumed.
///
/// Format: `[cmd, port(2), ip(4), userid… NUL]`, plus `[domain… NUL]` for
/// SOCKS4a (ip = 0.0.0.x, x != 0).
async fn read_socks4_request(stream: &mut TcpStream) -> Result<Socks4Request, ServerError> {
    let mut buf = vec![0u8; 7];
    stream.read_exact(&mut buf).await?;
    let is_socks4a = buf[3..6] == [0, 0, 0] && buf[6] != 0;

    read_through_nul(stream, &mut buf).await?; // user id
    if is_socks4a {
        read_through_nul(stream, &mut buf).await?; // domain
    }
    let (request, _) = parse_socks4_request(&buf)?;
    Ok(request)
}

/// Append bytes from `stream` to `out` up to and including the next NUL —
/// and not one byte further. `peek` shows what has arrived; exactly the part
/// up to the terminator is then consumed, so this costs two syscalls per TCP
/// segment rather than one per byte.
async fn read_through_nul(stream: &mut TcpStream, out: &mut Vec<u8>) -> std::io::Result<()> {
    let mut window = [0u8; SOCKS4_MAX_FIELD + 1];
    let mut field_len = 0;
    loop {
        let room = SOCKS4_MAX_FIELD + 1 - field_len;
        if room == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS4 field too long",
            ));
        }
        let peeked = stream.peek(&mut window[..room]).await?;
        if peeked == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        let nul = window[..peeked].iter().position(|&b| b == 0);
        let take = nul.map_or(peeked, |i| i + 1);
        stream.read_exact(&mut window[..take]).await?;
        out.extend_from_slice(&window[..take]);
        field_len += take;
        if nul.is_some() {
            return Ok(());
        }
    }
}

/// Resolve and dial a CONNECT target (standalone mode), with keepalive set.
async fn dial(target: &TargetAddr, ctx: &ServerContext) -> Result<TcpStream, ServerError> {
    let config = &ctx.config;
    let addrs = match resolve_target(target, config).await {
        Ok(addrs) => addrs,
        Err(e) => {
            bump(&ctx.extended_metrics.errors_dns_timeout);
            return Err(e);
        }
    };
    match net::connect_any(&addrs, config.connect_timeout).await {
        Ok(stream) => {
            net::configure_stream(&stream, &config.keepalive())?;
            Ok(stream)
        }
        Err(e) => {
            bump(&ctx.extended_metrics.errors_connection_failed);
            Err(if e.kind() == std::io::ErrorKind::TimedOut {
                ServerError::Timeout
            } else {
                ServerError::Io(e)
            })
        }
    }
}

/// Relay between the SOCKS client and a directly-dialed target.
///
/// `idle_timeout` is enforced inside the relay as a true inactivity timer,
/// not a wall-clock cap — an actively transferring connection is not cut.
/// Live counters mean bytes are already in the global metrics; the returned
/// counts are only used for the log line.
async fn relay_direct(
    stream: &mut TcpStream,
    target_stream: &mut TcpStream,
    peer_addr: SocketAddr,
    target: &TargetAddr,
    ctx: &ServerContext,
) -> Result<(), ServerError> {
    let (c2s, s2c, outcome) = relay_tcp_live(
        stream,
        target_stream,
        &[&ctx.metrics.bytes_client_to_target],
        &[&ctx.metrics.bytes_target_to_client],
        Some(ctx.config.idle_timeout),
    )
    .await;

    if let Err(e) = outcome {
        bump(&ctx.extended_metrics.errors_relay);
        tracing::debug!(%peer_addr, %target, c2s, s2c, error = %e, "relay error");
        return Err(ServerError::Io(e));
    }
    tracing::debug!(%peer_addr, %target, c2s, s2c, "relay finished");
    Ok(())
}

/// Handle SOCKS4 CONNECT.
async fn handle_socks4_connect(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    target: &TargetAddr,
    ctx: &ServerContext,
) -> Result<(), ServerError> {
    let mut target_stream = match dial(target, ctx).await {
        Ok(s) => s,
        Err(e) => {
            let mut reply = Vec::new();
            write_socks4_reply(Socks4Reply::Rejected, None, &mut reply);
            let _ = stream.write_all(&reply).await;
            return Err(e);
        }
    };

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

    tracing::debug!(%peer_addr, %target, "SOCKS4 CONNECT established, starting relay");
    relay_direct(stream, &mut target_stream, peer_addr, target, ctx).await
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
    let mut target_stream = match dial(target, ctx).await {
        Ok(s) => s,
        Err(e) => {
            reply_socks5_failure(stream, e.to_reply_code()).await;
            return Err(e);
        }
    };

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
    relay_direct(stream, &mut target_stream, peer_addr, target, ctx).await
}

// ───────────────────────── tunnel mode ─────────────────────────

type TunnelIo = tokio_util::compat::Compat<yamux::Stream>;

/// How much longer than `connect_timeout` the server waits for the tunnel
/// client's `StreamReply`. The client spends up to `connect_timeout` dialing
/// and then *reports* a timeout itself; without slack the two timers race and
/// the client's more specific reply code is lost.
const TUNNEL_REPLY_SLACK: std::time::Duration = std::time::Duration::from_secs(2);

/// Attempts at opening a tunnel flow. A session can die between "stream
/// opened" and "reply received"; nothing has been sent to the target yet, so
/// trying once more on another session is safe.
const TUNNEL_OPEN_ATTEMPTS: usize = 2;

/// An opened tunnel flow: the stream, the owning client's live byte counters
/// and the client's (successful or not) reply to our `StreamOpen`.
struct TunnelFlow {
    io: TunnelIo,
    tx_bytes: std::sync::Arc<AtomicU64>,
    rx_bytes: std::sync::Arc<AtomicU64>,
    reply: StreamReply,
}

/// Open a yamux stream to a tunnel client, send `open`, await its reply.
/// Every step is time-bounded — a wedged session must not hang the SOCKS
/// client. On failure returns the SOCKS5 reply code to fail the client with.
async fn open_tunnel_flow(
    router: &Router,
    open: &StreamOpen,
    config: &Config,
) -> Result<TunnelFlow, (ReplyCode, ServerError)> {
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    let preamble = open.encode();
    let mut last_err = None;

    for _ in 0..TUNNEL_OPEN_ATTEMPTS {
        let Some(TunnelStream { stream, tx_bytes, rx_bytes }) =
            router.open_stream(None, config.connect_timeout).await
        else {
            break;
        };
        let mut io = stream.compat();

        let exchange = async {
            io.write_all(&preamble).await?;
            StreamReply::read_from(&mut io).await
        };
        match tokio::time::timeout(config.connect_timeout + TUNNEL_REPLY_SLACK, exchange).await {
            Ok(Ok(reply)) => return Ok(TunnelFlow { io, tx_bytes, rx_bytes, reply }),
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "tunnel stream died before its reply, retrying");
                last_err = Some((ReplyCode::GeneralFailure, ServerError::Io(e)));
            }
            // The client had its full dial budget — do not double it.
            Err(_) => return Err((ReplyCode::TtlExpired, ServerError::Timeout)),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        log_no_tunnel_clients();
        (
            ReplyCode::GeneralFailure,
            ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "no tunnel clients available",
            )),
        )
    }))
}

/// Rate-limit the "no tunnel clients" warning: log once on transition, not per
/// request.
static NO_CLIENTS_LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn log_no_tunnel_clients() {
    if !NO_CLIENTS_LOGGED.swap(true, Ordering::Relaxed) {
        tracing::warn!("no tunnel clients available (suppressing further warnings)");
    }
}

fn log_tunnel_clients_back() {
    if NO_CLIENTS_LOGGED.swap(false, Ordering::Relaxed) {
        tracing::info!("tunnel client available again");
    }
}

/// Open a tunnel flow for `open` and turn anything but a successful reply
/// into a SOCKS5 failure reply — the client is still blocked waiting for one.
async fn open_tunnel_flow_or_reply(
    stream: &mut TcpStream,
    open: &StreamOpen,
    ctx: &ServerContext,
    router: &Router,
) -> Result<TunnelFlow, ServerError> {
    let flow = match open_tunnel_flow(router, open, &ctx.config).await {
        Ok(flow) => flow,
        Err((code, e)) => {
            bump(&ctx.extended_metrics.errors_connection_failed);
            reply_socks5_failure(stream, code).await;
            return Err(e);
        }
    };
    log_tunnel_clients_back();

    if flow.reply.status != 0 {
        bump(&ctx.extended_metrics.errors_connection_failed);
        reply_socks5_failure(stream, ReplyCode::from_u8(flow.reply.status)).await;
        return Err(ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            flow.reply.message,
        )));
    }
    Ok(flow)
}

/// Handle SOCKS5 CONNECT via a tunnel client (yamux multiplexed).
async fn handle_connect_via_tunnel(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    target: &TargetAddr,
    ctx: &ServerContext,
    router: &Router,
) -> Result<(), ServerError> {
    tracing::debug!(%peer_addr, %target, "routing CONNECT through tunnel");

    let open = StreamOpen::Tcp { target: target.to_string() };
    let mut flow = open_tunnel_flow_or_reply(stream, &open, ctx, router).await?;

    // Success — reply to the SOCKS client, then relay.
    let mut buf = Vec::new();
    write_command_reply(ReplyCode::Succeeded, &TargetAddr::unspecified(), &mut buf);
    stream.write_all(&buf).await?;

    tracing::debug!(%peer_addr, %target, "tunnel CONNECT established, starting relay");

    // "tx" = SOCKS client -> target ; "rx" = target -> SOCKS client. Both the
    // per-client and the global counters are bumped live, so the dashboard's
    // traffic chart moves during a long transfer, not only when it ends.
    let (c2s, s2c, outcome) = relay_bidirectional(
        stream,
        &mut flow.io,
        &[&ctx.metrics.bytes_client_to_target, &flow.tx_bytes],
        &[&ctx.metrics.bytes_target_to_client, &flow.rx_bytes],
        Some(ctx.config.idle_timeout),
    )
    .await;

    if let Err(e) = outcome {
        bump(&ctx.extended_metrics.errors_relay);
        tracing::debug!(%peer_addr, %target, c2s, s2c, error = %e, "tunnel relay error");
        return Err(ServerError::Io(e));
    }
    tracing::debug!(%peer_addr, %target, c2s, s2c, "tunnel relay finished");
    Ok(())
}

/// Send a SOCKS5 command reply carrying `code` to the client, ignoring any
/// write error. Used on error paths so the client fails fast with a proper
/// reply code instead of waiting on a silently-closed socket.
async fn reply_socks5_failure(stream: &mut TcpStream, code: ReplyCode) {
    let mut buf = Vec::new();
    write_command_reply(code, &TargetAddr::unspecified(), &mut buf);
    let _ = stream.write_all(&buf).await;
}

// ───────────────────────── UDP ASSOCIATE ─────────────────────────

/// Handle SOCKS5 UDP ASSOCIATE command.
///
/// **Reply ordering invariant:** in tunnel mode, the SOCKS5 success reply is
/// deferred until the tunnel UDP stream is opened — otherwise the client
/// gets a working-looking relay_addr but datagrams sent there are silently
/// dropped (e.g., when no tunnel client is available). Standalone mode can
/// reply immediately because the relay is local and always usable once
/// bind succeeds.
///
/// The association lives as long as the TCP control connection (RFC 1928),
/// bounded by `idle_timeout` as a true inactivity timer. The relay borrows
/// the control stream and spawns nothing, so returning from here releases
/// every socket of the association.
async fn handle_udp_associate(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    ctx: &ServerContext,
) -> Result<(), ServerError> {
    // Bind the relay socket on the address the client reached us at: same
    // address family as the client, and a BND.ADDR it can actually send to
    // (0.0.0.0 is not one). A dual-stack listener reports a v4 client's local
    // address as v4-mapped — canonicalize so such a client gets a v4 socket.
    let local_ip = stream.local_addr()?.ip().to_canonical();
    let relay_socket = UdpSocket::bind((local_ip, 0)).await?;
    let relay_addr = relay_socket.local_addr()?;
    let bind_addr = TargetAddr::Ip(relay_addr);

    tracing::debug!(%peer_addr, relay = %relay_addr, "UDP ASSOCIATE relay bound");

    let idle_timeout = ctx.config.idle_timeout;
    let outcome = match &ctx.router {
        // Tunnel mode: open the tunnel UDP stream FIRST, then reply.
        Some(router) => {
            let flow = open_tunnel_flow_or_reply(stream, &StreamOpen::Udp, ctx, router).await?;
            let mut reply = Vec::new();
            write_command_reply(ReplyCode::Succeeded, &bind_addr, &mut reply);
            stream.write_all(&reply).await?;
            tracing::debug!(%peer_addr, "UDP ASSOCIATE routed through tunnel");

            relay_udp_tunneled(stream, relay_socket, peer_addr.ip(), flow.io, idle_timeout).await
        }
        // Standalone mode: relay is local, safe to reply immediately.
        None => {
            let mut reply = Vec::new();
            write_command_reply(ReplyCode::Succeeded, &bind_addr, &mut reply);
            stream.write_all(&reply).await?;

            let dns_timeout = ctx.config.dns_timeout;
            relay_udp(stream, relay_socket, peer_addr.ip(), idle_timeout, dns_timeout).await
        }
    };

    tracing::debug!(%peer_addr, "UDP ASSOCIATE finished");
    outcome.map_err(|e| {
        bump(&ctx.extended_metrics.errors_relay);
        ServerError::Io(e)
    })
}

/// Resolve a TargetAddr to every address it maps to, via DNS if needed.
async fn resolve_target(
    target: &TargetAddr,
    config: &Config,
) -> Result<Vec<SocketAddr>, ServerError> {
    match target {
        TargetAddr::Ip(addr) => Ok(vec![*addr]),
        TargetAddr::Domain(domain, port) => {
            let addrs = net::resolve(domain, *port, config.dns_timeout)
                .await
                .map_err(|e| ServerError::DnsResolution(domain.clone(), e))?;
            tracing::trace!(domain = %domain, ?addrs, "DNS resolved");
            Ok(addrs)
        }
    }
}

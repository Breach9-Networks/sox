use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

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
use crate::protocol::tls::{client_hello_server_name, read_client_hello};
use crate::relay::tcp::{relay_bidirectional, relay_tcp_live};
use crate::relay::udp::{relay_udp, relay_udp_tunneled};
use crate::server::ServerContext;
use crate::server::extended_metrics::UserSessionGuard;
use crate::tunnel::protocol::{StreamOpen, StreamReply};
use crate::tunnel::router::{Router, TunnelStream};
use crate::upstream::{HttpUpstream, UpstreamUdp};

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
                    handle_connect(stream, peer_addr, &request.target, ctx, Dialect::V5).await
                }
                Socks5Command::UdpAssociate => handle_udp_associate(stream, peer_addr, ctx).await,
                Socks5Command::Bind => {
                    Dialect::V5.fail(stream, ReplyCode::CommandNotSupported).await;
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
                    handle_connect(stream, peer_addr, &request.target, ctx, Dialect::V4).await
                }
                Socks4Command::Bind => {
                    Dialect::V4.fail(stream, ReplyCode::CommandNotSupported).await;
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
        Some(SocksVersion::V4) => {
            let request = read_socks4_request(stream).await?;
            // SOCKS4 carries no password: with credentials configured, serving
            // it would bypass them.
            if ctx.auth.is_some() {
                tracing::debug!(%peer_addr, "SOCKS4 refused: authentication is required");
                bump(&ctx.extended_metrics.errors_auth_rejected);
                Dialect::V4.fail(stream, ReplyCode::ConnectionNotAllowed).await;
                return Err(ServerError::Protocol(ProtocolError::NoAcceptableMethod));
            }
            Ok(Negotiated::V4(request))
        }
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
/// and not one byte further.
async fn read_through_nul(stream: &mut TcpStream, out: &mut Vec<u8>) -> std::io::Result<()> {
    net::read_field(stream, out, SOCKS4_MAX_FIELD + 1, |field| {
        field.iter().position(|&b| b == 0).map(|i| i + 1)
    })
    .await
}

/// Resolve and dial a CONNECT target (standalone mode), with keepalive set —
/// or tunnel to it through the upstream HTTP proxy when one is configured.
async fn dial(target: &TargetAddr, ctx: &ServerContext) -> Result<TcpStream, ServerError> {
    let config = &ctx.config;
    if let Some(upstream) = &config.upstream {
        let result = upstream.connect(target, config).await;
        if let Err(e) = &result {
            bump(&ctx.extended_metrics.errors_connection_failed);
            tracing::debug!(%target, %upstream, error = %e, "upstream CONNECT failed");
        }
        log_upstream_health(upstream, &result);
        return result;
    }
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

/// Something that is logged once when it goes down and once when it comes
/// back, not once per request.
struct TransitionLog(AtomicBool);

impl TransitionLog {
    const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Whether this call took it down. Loads first: the common case is "no
    /// change", and a load does not bounce the cache line between cores.
    fn went_down(&self) -> bool {
        !self.0.load(Ordering::Relaxed) && !self.0.swap(true, Ordering::Relaxed)
    }

    /// Whether this call brought it back.
    fn came_back(&self) -> bool {
        self.0.load(Ordering::Relaxed) && self.0.swap(false, Ordering::Relaxed)
    }
}

static UPSTREAM_DOWN: TransitionLog = TransitionLog::new();

/// Warn once when CONNECTs start failing because of the proxy itself — that
/// fails every connection — and note when it answers again. Target-side
/// failures (timeouts, unreachable) say nothing about the proxy.
fn log_upstream_health(upstream: &HttpUpstream, result: &Result<TcpStream, ServerError>) {
    match result {
        Err(e) if e.is_upstream_fault() => {
            if UPSTREAM_DOWN.went_down() {
                tracing::warn!(%upstream, error = %e, "upstream proxy failing (suppressing further warnings)");
            }
        }
        Ok(_) | Err(ServerError::UpstreamRejected(_)) => {
            if UPSTREAM_DOWN.came_back() {
                tracing::info!(%upstream, "upstream proxy answering again");
            }
        }
        Err(_) => {}
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

/// Which SOCKS version's reply a CONNECT client is waiting for.
#[derive(Clone, Copy)]
enum Dialect {
    V4,
    V5,
}

impl Dialect {
    /// The success reply, naming `bind` where the version can express it.
    fn success(self, bind: Option<SocketAddr>) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Dialect::V4 => {
                let bind = match bind {
                    Some(SocketAddr::V4(v4)) => Some(v4),
                    _ => None,
                };
                write_socks4_reply(Socks4Reply::Granted, bind, &mut out);
            }
            Dialect::V5 => {
                let bind = bind.map_or_else(TargetAddr::unspecified, TargetAddr::Ip);
                write_command_reply(ReplyCode::Succeeded, &bind, &mut out);
            }
        }
        out
    }

    /// Fail the client with `code` (SOCKS4 only knows "rejected"), ignoring
    /// any write error — so it fails fast instead of waiting on a closed socket.
    async fn fail(self, stream: &mut TcpStream, code: ReplyCode) {
        let mut out = Vec::new();
        match self {
            Dialect::V4 => write_socks4_reply(Socks4Reply::Rejected, None, &mut out),
            Dialect::V5 => write_command_reply(code, &TargetAddr::unspecified(), &mut out),
        }
        let _ = stream.write_all(&out).await;
    }
}

/// Whether this CONNECT goes through [`connect_named_by_sni`]: an upstream
/// proxy with `upstream_sni`, and a target that is only an IP — which an
/// intercepting upstream cannot match against a host-based scope or mint a
/// certificate for.
fn names_by_sni(target: &TargetAddr, config: &Config) -> bool {
    config.upstream_sni && config.upstream.is_some() && matches!(target, TargetAddr::Ip(_))
}

/// How long an IP-only CONNECT waits for the client's ClientHello under
/// `upstream_sni`. Server-speaks-first protocols (SSH, SMTP) send nothing
/// until greeted, so each such connection pays this before the IP is used.
const SNI_WAIT: Duration = Duration::from_secs(2);

/// CONNECT through the upstream by the host name in the client's SNI.
///
/// The SNI only arrives after the SOCKS handshake, so the client is told
/// "success" before the upstream is dialed. The cost: a failed upstream
/// CONNECT can no longer be a SOCKS error reply — the client sees the
/// connection close. Without a usable SNI the IP is CONNECTed as before.
async fn connect_named_by_sni(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    target: &TargetAddr,
    ctx: &ServerContext,
    dialect: Dialect,
) -> Result<(), ServerError> {
    stream.write_all(&dialect.success(None)).await?;
    let hello = read_client_hello(stream, SNI_WAIT).await?;
    let named = client_hello_server_name(&hello).map(|host| TargetAddr::Domain(host, target.port()));
    let upstream_target = named.as_ref().unwrap_or(target);
    tracing::debug!(%peer_addr, %target, via = %upstream_target, "CONNECT named by SNI");

    let mut target_stream = match dial(upstream_target, ctx).await {
        // The proxy could not reach the name (its DNS differs from the
        // client's, a pinned or split-horizon address). Nothing has been
        // sent yet, so the address the client actually asked for still can.
        Err(e @ ServerError::UpstreamRejected(_))
            if named.is_some() && e.to_reply_code() == ReplyCode::HostUnreachable =>
        {
            tracing::debug!(%peer_addr, %target, "upstream cannot reach the SNI name, using the IP");
            dial(target, ctx).await?
        }
        result => result?,
    };
    target_stream.write_all(&hello).await?;
    ctx.metrics
        .bytes_client_to_target
        .fetch_add(hello.len() as u64, Ordering::Relaxed);
    drop(hello);
    relay_direct(stream, &mut target_stream, peer_addr, upstream_target, ctx).await
}

/// Handle a SOCKS4 or SOCKS5 CONNECT: through a tunnel client in tunnel mode,
/// otherwise dialed from here — directly or via the upstream proxy.
async fn handle_connect(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    target: &TargetAddr,
    ctx: &ServerContext,
    dialect: Dialect,
) -> Result<(), ServerError> {
    if let Some(router) = &ctx.router {
        return handle_connect_via_tunnel(stream, peer_addr, target, ctx, router, dialect).await;
    }

    if names_by_sni(target, &ctx.config) {
        return connect_named_by_sni(stream, peer_addr, target, ctx, dialect).await;
    }

    let mut target_stream = match dial(target, ctx).await {
        Ok(s) => s,
        Err(e) => {
            dialect.fail(stream, e.to_reply_code()).await;
            return Err(e);
        }
    };

    let bind = target_stream.local_addr().ok();
    stream.write_all(&dialect.success(bind)).await?;

    tracing::debug!(%peer_addr, %target, ?bind, "CONNECT established, starting relay");
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

static NO_TUNNEL_CLIENTS: TransitionLog = TransitionLog::new();

fn log_no_tunnel_clients() {
    if NO_TUNNEL_CLIENTS.went_down() {
        tracing::warn!("no tunnel clients available (suppressing further warnings)");
    }
}

fn log_tunnel_clients_back() {
    if NO_TUNNEL_CLIENTS.came_back() {
        tracing::info!("tunnel client available again");
    }
}

/// Open a tunnel flow for `open` and turn anything but a successful reply
/// into a failure reply — the client is still blocked waiting for one.
async fn open_tunnel_flow_or_reply(
    stream: &mut TcpStream,
    open: &StreamOpen,
    ctx: &ServerContext,
    router: &Router,
    dialect: Dialect,
) -> Result<TunnelFlow, ServerError> {
    let flow = match open_tunnel_flow(router, open, &ctx.config).await {
        Ok(flow) => flow,
        Err((code, e)) => {
            bump(&ctx.extended_metrics.errors_connection_failed);
            dialect.fail(stream, code).await;
            return Err(e);
        }
    };
    log_tunnel_clients_back();

    if flow.reply.status != 0 {
        bump(&ctx.extended_metrics.errors_connection_failed);
        dialect.fail(stream, ReplyCode::from_u8(flow.reply.status)).await;
        return Err(ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            flow.reply.message,
        )));
    }
    Ok(flow)
}

/// Handle a CONNECT via a tunnel client (yamux multiplexed).
async fn handle_connect_via_tunnel(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    target: &TargetAddr,
    ctx: &ServerContext,
    router: &Router,
    dialect: Dialect,
) -> Result<(), ServerError> {
    tracing::debug!(%peer_addr, %target, "routing CONNECT through tunnel");

    let open = StreamOpen::Tcp { target: target.to_string() };
    let mut flow = open_tunnel_flow_or_reply(stream, &open, ctx, router, dialect).await?;

    // Success — reply to the SOCKS client, then relay.
    stream.write_all(&dialect.success(None)).await?;

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
    // UDP cannot ride an HTTP CONNECT: unless told to bypass the upstream,
    // refuse it so every flow stays on the (intercepting) proxy.
    if ctx.config.upstream.is_some() && ctx.config.upstream_udp == UpstreamUdp::Reject {
        Dialect::V5.fail(stream, ReplyCode::CommandNotSupported).await;
        return Err(ServerError::CommandNotSupported);
    }

    // Bind the relay socket on the address the client reached us at: same
    // address family as the client, and a BND.ADDR it can actually send to
    // (0.0.0.0 is not one). A dual-stack listener reports a v4 client's local
    // address as v4-mapped — canonicalize so such a client gets a v4 socket.
    let local_ip = stream.local_addr()?.ip().to_canonical();
    let relay_socket = UdpSocket::bind((local_ip, 0)).await?;
    let relay_addr = relay_socket.local_addr()?;
    let success = Dialect::V5.success(Some(relay_addr));

    tracing::debug!(%peer_addr, relay = %relay_addr, "UDP ASSOCIATE relay bound");

    let idle_timeout = ctx.config.idle_timeout;
    let outcome = match &ctx.router {
        // Tunnel mode: open the tunnel UDP stream FIRST, then reply.
        Some(router) => {
            let flow = open_tunnel_flow_or_reply(stream, &StreamOpen::Udp, ctx, router, Dialect::V5).await?;
            stream.write_all(&success).await?;
            tracing::debug!(%peer_addr, "UDP ASSOCIATE routed through tunnel");

            relay_udp_tunneled(stream, relay_socket, peer_addr.ip(), flow.io, idle_timeout).await
        }
        // Standalone mode: relay is local, safe to reply immediately.
        None => {
            stream.write_all(&success).await?;

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

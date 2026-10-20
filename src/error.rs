use std::net::SocketAddr;

use thiserror::Error;

use crate::protocol::socks5::ReplyCode;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("incomplete data: need at least {needed} bytes, got {got}")]
    Incomplete { needed: usize, got: usize },

    #[error("invalid SOCKS version: {0:#x}")]
    InvalidVersion(u8),

    #[error("invalid auth method: {0:#x}")]
    InvalidAuthMethod(u8),

    #[error("invalid command: {0:#x}")]
    InvalidCommand(u8),

    #[error("invalid address type: {0:#x}")]
    InvalidAddressType(u8),

    #[error("no acceptable auth method")]
    NoAcceptableMethod,

    #[error("invalid username/password auth version: {0:#x}")]
    InvalidAuthVersion(u8),

    #[error("empty domain name")]
    EmptyDomain,
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("connection refused by target {0}")]
    ConnectionRefused(SocketAddr),

    #[error("dns resolution failed for {0}: {1}")]
    DnsResolution(String, std::io::Error),

    #[error("command not supported")]
    CommandNotSupported,

    #[error("connection timed out")]
    Timeout,

    #[error("connection limit reached")]
    ConnectionLimit,

    #[error("upstream proxy refused CONNECT with HTTP {0}")]
    UpstreamRejected(u16),

    /// The upstream proxy itself could not be reached — nothing is known
    /// about the target.
    #[error("upstream proxy unreachable: {0}")]
    UpstreamUnavailable(std::io::Error),
}

impl ServerError {
    pub fn to_reply_code(&self) -> ReplyCode {
        match self {
            ServerError::Io(e) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused => ReplyCode::ConnectionRefused,
                std::io::ErrorKind::AddrNotAvailable => ReplyCode::HostUnreachable,
                _ => ReplyCode::GeneralFailure,
            },
            ServerError::Protocol(_) => ReplyCode::GeneralFailure,
            ServerError::ConnectionRefused(_) => ReplyCode::ConnectionRefused,
            ServerError::DnsResolution(_, _) => ReplyCode::HostUnreachable,
            ServerError::CommandNotSupported => ReplyCode::CommandNotSupported,
            ServerError::Timeout => ReplyCode::TtlExpired,
            ServerError::ConnectionLimit => ReplyCode::ConnectionNotAllowed,
            ServerError::UpstreamRejected(status) => upstream_status_reply_code(*status),
            // Not "refused"/"unreachable": those would blame the target.
            ServerError::UpstreamUnavailable(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                ReplyCode::TtlExpired
            }
            ServerError::UpstreamUnavailable(_) => ReplyCode::GeneralFailure,
        }
    }

    /// Whether this is the upstream proxy's own failure — unreachable, or
    /// refusing CONNECT or credential-less use outright — which fails every
    /// connection, not just this target's.
    pub fn is_upstream_fault(&self) -> bool {
        matches!(
            self,
            ServerError::UpstreamUnavailable(_) | ServerError::UpstreamRejected(401 | 405 | 407 | 501)
        )
    }
}

/// The SOCKS5 reply for a non-2xx answer to the upstream proxy's `CONNECT`.
///
/// The SOCKS client only sees this one byte, so it decides whether the phone /
/// app reports "host unreachable", "refused", "not allowed" or a generic error.
/// Proxies disagree on which status means "could not reach the target" (Squid
/// sends 503, mitmproxy and tinyproxy 502, some 404), so all of those map to
/// `HostUnreachable` — the proxy never says *why* the dial failed.
fn upstream_status_reply_code(status: u16) -> ReplyCode {
    match status {
        // Policy: the proxy, or the network in front of it, will not let us
        // through. 407/511 included — sox sends no proxy credentials.
        401 | 403 | 407 | 429 | 451 | 511 => ReplyCode::ConnectionNotAllowed,
        // The proxy reached nothing at that address.
        404 | 410 | 502 | 503 => ReplyCode::HostUnreachable,
        // The proxy or the target ran out of time.
        408 | 504 | 522 | 524 => ReplyCode::TtlExpired,
        // The proxy does not do CONNECT at all.
        405 | 501 => ReplyCode::CommandNotSupported,
        // A target the proxy cannot parse (hostname too long, bad authority).
        400 | 414 => ReplyCode::AddressTypeNotSupported,
        // Everything else — 1xx/3xx (meaningless for CONNECT), other 4xx/5xx.
        _ => ReplyCode::GeneralFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_statuses_map_to_specific_replies() {
        let code = |s| ServerError::UpstreamRejected(s).to_reply_code();
        assert_eq!(code(407), ReplyCode::ConnectionNotAllowed);
        assert_eq!(code(403), ReplyCode::ConnectionNotAllowed);
        assert_eq!(code(502), ReplyCode::HostUnreachable);
        assert_eq!(code(503), ReplyCode::HostUnreachable);
        assert_eq!(code(504), ReplyCode::TtlExpired);
        assert_eq!(code(405), ReplyCode::CommandNotSupported);
        assert_eq!(code(400), ReplyCode::AddressTypeNotSupported);
        assert_eq!(code(500), ReplyCode::GeneralFailure);
        assert_eq!(code(302), ReplyCode::GeneralFailure);
    }
}

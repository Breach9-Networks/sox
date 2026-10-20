//! Upstream HTTP proxy: standalone CONNECTs are tunneled through an HTTP
//! proxy's `CONNECT` method instead of being dialed directly — e.g. a phone
//! that only speaks SOCKS feeding an intercepting proxy such as Burp.

use std::fmt;
use std::io;

use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::config::Config;
use crate::error::ServerError;
use crate::net;
use crate::protocol::addr::{TargetAddr, is_valid_hostname};

/// Longest response head (status line + headers) accepted from the upstream.
const MAX_RESPONSE_HEAD: usize = 8 * 1024;

/// An upstream HTTP proxy, `host:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUpstream {
    host: String,
    port: u16,
}

/// What a UDP ASSOCIATE does while an upstream proxy is configured. UDP cannot
/// ride an HTTP `CONNECT`, so it either is refused or bypasses the upstream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamUdp {
    /// Refuse UDP: every flow stays on the upstream, and QUIC clients fall
    /// back to TCP — what an intercepting proxy wants.
    #[default]
    Reject,
    /// Relay UDP directly, bypassing the upstream.
    Direct,
}

impl fmt::Display for UpstreamUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Reject => "reject",
            Self::Direct => "direct",
        })
    }
}

impl HttpUpstream {
    /// Parse `[http://]host:port`. The port is required — there is no
    /// sensible default between 80 and Burp's 8080. Credentials, paths and
    /// other schemes are rejected rather than silently ignored.
    pub fn parse(s: &str) -> Result<Self, String> {
        // Never echo a password back into a terminal or service journal.
        let shown = match s.rsplit_once('@') {
            Some((_, host)) => format!("…@{host}"),
            None => s.to_string(),
        };
        let err = |why: &str| format!("invalid upstream proxy '{shown}': {why}");
        let rest = match s.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,
            Some((scheme, _)) => return Err(err(&format!("scheme '{scheme}' unsupported, only http://"))),
            None => s,
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.contains('@') {
            return Err(err("credentials are not supported"));
        }
        if authority.contains('/') {
            return Err(err("a path is not allowed"));
        }
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| err("expected host:port"))?;
        let port: u16 = port
            .parse()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| err("invalid port"))?;
        let host = match host.strip_prefix('[') {
            Some(bracketed) => bracketed.strip_suffix(']').ok_or_else(|| err("unclosed '['"))?,
            None if host.contains(':') => return Err(err("IPv6 addresses need brackets")),
            None => host,
        };
        if host.is_empty() {
            return Err(err("empty host"));
        }
        Ok(Self { host: host.to_string(), port })
    }

    /// Open a tunnel to `target` through the upstream. Dialing the upstream
    /// and its `CONNECT` exchange share one `connect_timeout` deadline.
    pub async fn connect(
        &self,
        target: &TargetAddr,
        config: &Config,
    ) -> Result<TcpStream, ServerError> {
        let authority = connect_authority(target)?;
        let deadline = Instant::now() + config.connect_timeout;
        let mut stream = self.dial(config, deadline).await?;

        let exchange = async {
            let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
            stream.write_all(request.as_bytes()).await?;
            parse_status(&read_response_head(&mut stream).await?)
        };
        // Past this point the proxy is up: a timeout is the target's dial.
        match tokio::time::timeout_at(deadline, exchange).await {
            Ok(Ok(200..=299)) => Ok(stream),
            Ok(Ok(status)) => Err(ServerError::UpstreamRejected(status)),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(ServerError::Timeout),
        }
    }

    /// Reach the proxy itself, within what is left of `deadline`. A failure
    /// here says nothing about the target, so it is `UpstreamUnavailable` —
    /// never a refused or unreachable target.
    async fn dial(&self, config: &Config, deadline: Instant) -> Result<TcpStream, ServerError> {
        let reach = async {
            let addrs = net::resolve(&self.host, self.port, config.dns_timeout).await?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS used up the connect timeout"));
            }
            net::connect_any(&addrs, remaining).await
        };
        let stream = reach.await.map_err(ServerError::UpstreamUnavailable)?;
        net::configure_stream(&stream, &config.keepalive())?;
        Ok(stream)
    }
}

impl fmt::Display for HttpUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "http://[{}]:{}", self.host, self.port)
        } else {
            write!(f, "http://{}:{}", self.host, self.port)
        }
    }
}

/// The `CONNECT` request target. A domain is forwarded as the client sent it
/// so the upstream sees the real hostname; it is checked first because a
/// SOCKS domain is arbitrary bytes — a CR/LF in it would inject headers into
/// the request. (`SocketAddr` brackets IPv6.)
fn connect_authority(target: &TargetAddr) -> Result<String, ServerError> {
    if let TargetAddr::Domain(domain, _) = target
        && !is_valid_hostname(domain.as_bytes())
    {
        return Err(ServerError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target domain is not a valid hostname",
        )));
    }
    Ok(target.to_string())
}

/// Read the response head up to and including the blank line — and not one
/// byte further: whatever follows already belongs to the tunnel.
async fn read_response_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    net::read_field(stream, &mut head, MAX_RESPONSE_HEAD, head_len).await?;
    Ok(head)
}

/// Length of the head — through its blank line, `\n\n` or `\n\r\n` — once
/// it is complete. A bare-LF blank line counts (RFC 9112 §2.2 lets
/// recipients accept it).
fn head_len(buf: &[u8]) -> Option<usize> {
    (0..buf.len()).find_map(|i| match &buf[i..] {
        [b'\n', b'\n', ..] => Some(i + 2),
        [b'\n', b'\r', b'\n', ..] => Some(i + 3),
        _ => None,
    })
}

/// Status code from an `HTTP/1.x NNN reason` status line. Only the version
/// and code must be ASCII; the reason phrase may be in any charset.
fn parse_status(head: &[u8]) -> io::Result<u16> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "malformed upstream status line");
    let line = head.split(|&b| b == b'\r' || b == b'\n').next().ok_or_else(invalid)?;
    let mut parts = line.splitn(3, |&b| b == b' ');
    match (parts.next(), parts.next()) {
        (Some(version), Some(code))
            if version.starts_with(b"HTTP/1.") && code.len() == 3 && code.iter().all(u8::is_ascii_digit) =>
        {
            Ok(code.iter().fold(0, |n, &d| n * 10 + u16::from(d - b'0')))
        }
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn parse_accepts_host_port_forms() {
        let p = |s| HttpUpstream::parse(s).unwrap();
        assert_eq!(p("http://127.0.0.1:8080"), HttpUpstream { host: "127.0.0.1".into(), port: 8080 });
        assert_eq!(p("127.0.0.1:8080/"), HttpUpstream { host: "127.0.0.1".into(), port: 8080 });
        assert_eq!(p("http://[::1]:8080"), HttpUpstream { host: "::1".into(), port: 8080 });
        assert_eq!(p("http://[::1]:8080").to_string(), "http://[::1]:8080");
        assert_eq!(p("burp.local:8080").to_string(), "http://burp.local:8080");
        assert_eq!(p("HTTP://127.0.0.1:8080"), p("127.0.0.1:8080"));
    }

    #[test]
    fn parse_error_does_not_echo_credentials() {
        let e = HttpUpstream::parse("http://burp:S3cret@127.0.0.1:8080").unwrap_err();
        assert!(!e.contains("S3cret"), "{e}");
    }

    #[test]
    fn parse_rejects_what_it_cannot_honor() {
        for bad in [
            "https://127.0.0.1:8080",
            "socks5://127.0.0.1:1080",
            "http://u:p@127.0.0.1:8080",
            "http://127.0.0.1:8080/path",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://::1:8080",
            "http://[::1:8080",
            "http://:8080",
        ] {
            assert!(HttpUpstream::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn authority_rejects_header_injection() {
        let evil = TargetAddr::Domain("a.com\r\nX-Evil: 1".into(), 443);
        assert!(connect_authority(&evil).is_err());
        let v6 = TargetAddr::Ip("[::1]:443".parse().unwrap());
        assert_eq!(connect_authority(&v6).unwrap(), "[::1]:443");
        assert!(connect_authority(&TargetAddr::Domain("a:1@b".into(), 443)).is_err());
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_status(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap(), 200);
        assert_eq!(parse_status(b"HTTP/1.0 407\r\n\r\n").unwrap(), 407);
        assert_eq!(parse_status(b"HTTP/1.1 200 \xb3\x73\xbd\x75\n\n").unwrap(), 200);
        assert!(parse_status(b"SSH-2.0-OpenSSH\r\n\r\n").is_err());
        assert!(parse_status(b"HTTP/1.1 2x0 OK\r\n\r\n").is_err());
    }

    #[test]
    fn head_ends_at_crlf_or_bare_lf_blank_line() {
        assert_eq!(head_len(b"HTTP/1.1 200 OK\r\n\r\nX"), Some(19));
        assert_eq!(head_len(b"HTTP/1.1 200 OK\n\nX"), Some(17));
        assert_eq!(head_len(b"HTTP/1.1 200 OK\r\nVia: x\r\n"), None);
    }

    /// The head ends at the blank line even when the tunnel's first bytes
    /// arrive in the same segment, and those bytes are left unread.
    #[tokio::test]
    async fn response_head_leaves_tunnel_bytes_unread() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nVia: x\r").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            s.write_all(b"\n\r\nTUNNEL").await.unwrap();
        });
        let mut s = TcpStream::connect(addr).await.unwrap();
        let head = read_response_head(&mut s).await.unwrap();
        assert_eq!(head, b"HTTP/1.1 200 OK\r\nVia: x\r\n\r\n");
        let mut rest = [0u8; 6];
        s.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"TUNNEL");
    }
}

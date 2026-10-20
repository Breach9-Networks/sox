use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::error::ProtocolError;
use crate::protocol::addr::TargetAddr;

/// SOCKS4 protocol version byte.
pub const SOCKS4_VERSION: u8 = 0x04;

/// SOCKS4 command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks4Command {
    Connect = 0x01,
    Bind = 0x02,
}

/// SOCKS4 reply codes.
#[derive(Debug, Clone, Copy)]
pub enum Socks4Reply {
    Granted = 0x5A,
    Rejected = 0x5B,
}

/// A parsed SOCKS4/4a request.
#[derive(Debug, Clone)]
pub struct Socks4Request {
    pub command: Socks4Command,
    pub target: TargetAddr,
    pub user_id: String,
}

/// Parse a SOCKS4/4a request.
///
/// Format: [version(1), cmd(1), port(2), ip(4), userid(variable, null-terminated)]
/// For SOCKS4a: if IP is 0.0.0.x (x != 0), a domain follows after the null-terminated userid.
///
/// Note: the version byte (0x04) has already been read by the version detector.
/// `buf` starts AFTER the version byte.
pub fn parse_socks4_request(buf: &[u8]) -> Result<(Socks4Request, usize), ProtocolError> {
    // Need at least: cmd(1) + port(2) + ip(4) + null(1) = 8
    if buf.len() < 8 {
        return Err(ProtocolError::Incomplete {
            needed: 8,
            got: buf.len(),
        });
    }

    let command = match buf[0] {
        0x01 => Socks4Command::Connect,
        0x02 => Socks4Command::Bind,
        other => return Err(ProtocolError::InvalidCommand(other)),
    };

    let port = u16::from_be_bytes([buf[1], buf[2]]);
    let ip = Ipv4Addr::new(buf[3], buf[4], buf[5], buf[6]);

    // Find null terminator for userid (starts at offset 7)
    let userid_end = buf[7..]
        .iter()
        .position(|&b| b == 0)
        .ok_or(ProtocolError::Incomplete {
            needed: buf.len() + 1,
            got: buf.len(),
        })?;

    let user_id = String::from_utf8_lossy(&buf[7..7 + userid_end]).into_owned();
    let mut consumed = 7 + userid_end + 1; // +1 for null byte

    // SOCKS4a: if IP is 0.0.0.x where x != 0, domain name follows
    let is_socks4a =
        buf[3] == 0 && buf[4] == 0 && buf[5] == 0 && buf[6] != 0;

    let target = if is_socks4a {
        // Read domain name (null-terminated)
        let remaining = &buf[consumed..];
        let domain_end = remaining
            .iter()
            .position(|&b| b == 0)
            .ok_or(ProtocolError::Incomplete {
                needed: consumed + 1,
                got: buf.len(),
            })?;

        let domain =
            String::from_utf8_lossy(&remaining[..domain_end]).into_owned();
        consumed += domain_end + 1; // +1 for null byte

        if domain.is_empty() {
            return Err(ProtocolError::EmptyDomain);
        }

        TargetAddr::from_host(domain, port)
    } else {
        TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    };

    Ok((
        Socks4Request {
            command,
            target,
            user_id,
        },
        consumed,
    ))
}

/// Write a SOCKS4 reply.
///
/// Format: [null(1), status(1), port(2), ip(4)]
pub fn write_socks4_reply(reply: Socks4Reply, bind_addr: Option<SocketAddrV4>, out: &mut Vec<u8>) {
    out.push(0x00); // null byte (version in reply is 0)
    out.push(reply as u8);

    match bind_addr {
        Some(addr) => {
            out.extend_from_slice(&addr.port().to_be_bytes());
            out.extend_from_slice(&addr.ip().octets());
        }
        None => {
            out.extend_from_slice(&[0u8; 6]); // port=0, ip=0.0.0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_socks4_connect() {
        // cmd=CONNECT, port=80, ip=127.0.0.1, userid="", null
        let buf = [0x01, 0x00, 0x50, 127, 0, 0, 1, 0x00];
        let (req, _) = parse_socks4_request(&buf).unwrap();
        assert_eq!(req.command, Socks4Command::Connect);
        assert_eq!(req.target.to_string(), "127.0.0.1:80");
        assert_eq!(req.user_id, "");
    }

    #[test]
    fn parse_socks4_with_userid() {
        // cmd=CONNECT, port=80, ip=10.0.0.1, userid="fred", null
        let buf = [0x01, 0x00, 0x50, 10, 0, 0, 1, b'f', b'r', b'e', b'd', 0x00];
        let (req, _) = parse_socks4_request(&buf).unwrap();
        assert_eq!(req.user_id, "fred");
    }

    #[test]
    fn parse_socks4a_domain() {
        // cmd=CONNECT, port=80, ip=0.0.0.1 (socks4a marker), userid="", null, domain, null
        let mut buf = vec![0x01, 0x00, 0x50, 0, 0, 0, 1, 0x00];
        buf.extend_from_slice(b"example.com\0");
        let (req, _) = parse_socks4_request(&buf).unwrap();
        assert_eq!(req.command, Socks4Command::Connect);
        assert_eq!(req.target.to_string(), "example.com:80");
    }

    #[test]
    fn write_granted_reply() {
        let mut out = Vec::new();
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1080);
        write_socks4_reply(Socks4Reply::Granted, Some(addr), &mut out);
        assert_eq!(out, vec![0x00, 0x5A, 0x04, 0x38, 10, 0, 0, 1]);
    }

    #[test]
    fn write_rejected_reply() {
        let mut out = Vec::new();
        write_socks4_reply(Socks4Reply::Rejected, None, &mut out);
        assert_eq!(out, vec![0x00, 0x5B, 0, 0, 0, 0, 0, 0]);
    }
}

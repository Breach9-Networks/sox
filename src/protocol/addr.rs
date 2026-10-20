use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::error::ProtocolError;

/// Address type constants used in SOCKS5 protocol.
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// Target address for SOCKS requests. Covers IPv4, IPv6, and domain names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    /// Parse a target address from a SOCKS5 buffer starting at the address type byte.
    /// Returns the parsed address and the number of bytes consumed.
    pub fn parse_socks5(buf: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if buf.is_empty() {
            return Err(ProtocolError::Incomplete { needed: 1, got: 0 });
        }

        match buf[0] {
            ATYP_IPV4 => {
                // 1 (atyp) + 4 (ipv4) + 2 (port) = 7
                if buf.len() < 7 {
                    return Err(ProtocolError::Incomplete {
                        needed: 7,
                        got: buf.len(),
                    });
                }
                let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((
                    TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port))),
                    7,
                ))
            }
            ATYP_DOMAIN => {
                if buf.len() < 2 {
                    return Err(ProtocolError::Incomplete {
                        needed: 2,
                        got: buf.len(),
                    });
                }
                let domain_len = buf[1] as usize;
                if domain_len == 0 {
                    return Err(ProtocolError::EmptyDomain);
                }
                // 1 (atyp) + 1 (len) + domain_len + 2 (port)
                let total = 2 + domain_len + 2;
                if buf.len() < total {
                    return Err(ProtocolError::Incomplete {
                        needed: total,
                        got: buf.len(),
                    });
                }
                let domain =
                    String::from_utf8_lossy(&buf[2..2 + domain_len]).into_owned();
                let port =
                    u16::from_be_bytes([buf[2 + domain_len], buf[3 + domain_len]]);
                Ok((TargetAddr::from_host(domain, port), total))
            }
            ATYP_IPV6 => {
                // 1 (atyp) + 16 (ipv6) + 2 (port) = 19
                if buf.len() < 19 {
                    return Err(ProtocolError::Incomplete {
                        needed: 19,
                        got: buf.len(),
                    });
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((
                    TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))),
                    19,
                ))
            }
            other => Err(ProtocolError::InvalidAddressType(other)),
        }
    }

    /// Write this address in SOCKS5 format into the provided buffer.
    pub fn write_socks5(&self, buf: &mut Vec<u8>) {
        match self {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            TargetAddr::Domain(domain, port) => {
                debug_assert!(domain.len() <= 255, "domain name exceeds 255 bytes");
                buf.push(ATYP_DOMAIN);
                buf.push(domain.len().min(255) as u8);
                buf.extend_from_slice(&domain.as_bytes()[..domain.len().min(255)]);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// Return the unbound address (0.0.0.0:0) as a TargetAddr.
    pub fn unspecified() -> Self {
        TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            0,
        )))
    }

    /// The port component of this address.
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }

    /// A host sent as a name. An IP literal becomes `Ip` — Chromium sends
    /// every host as a domain — so nothing downstream resolves it, or formats
    /// an IPv6 address without brackets.
    pub fn from_host(host: String, port: u16) -> Self {
        match host.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
            Err(_) => TargetAddr::Domain(host, port),
        }
    }
}

/// Whether `name` is something a DNS name can contain (`_` included, as in
/// service names), 1–255 bytes. Anything else — CR/LF, spaces, `:` or `@` —
/// must never reach an HTTP request line.
pub fn is_valid_hostname(name: &[u8]) -> bool {
    (1..=255).contains(&name.len())
        && name.iter().all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(addr) => write!(f, "{addr}"),
            TargetAddr::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literal_hosts_become_ip() {
        let v6 = TargetAddr::from_host("2001:db8::1".into(), 443);
        assert_eq!(v6, TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap()));
        assert_eq!(v6.to_string(), "[2001:db8::1]:443");
        assert_eq!(
            TargetAddr::from_host("example.com".into(), 443),
            TargetAddr::Domain("example.com".into(), 443)
        );
    }

    #[test]
    fn hostname_charset() {
        assert!(is_valid_hostname(b"my_svc.corp-1.example"));
        for bad in [&b"a.com\r\nX: 1"[..], b"a.com:443", b"u@h", b"a b", b"", &[b'a'; 256]] {
            assert!(!is_valid_hostname(bad), "{bad:?}");
        }
    }

    #[test]
    fn test_parse_ipv4() {
        // atyp=0x01, ip=192.168.1.1, port=8080
        let buf = [0x01, 192, 168, 1, 1, 0x1F, 0x90];
        let (addr, consumed) = TargetAddr::parse_socks5(&buf).unwrap();
        assert_eq!(consumed, 7);
        match addr {
            TargetAddr::Ip(sa) => {
                assert_eq!(sa.to_string(), "192.168.1.1:8080");
            }
            _ => panic!("expected Ip variant"),
        }
    }

    #[test]
    fn test_parse_ipv6() {
        let mut buf = vec![0x04]; // ATYP_IPV6
        // ::1 in 16 bytes
        let mut octets = [0u8; 16];
        octets[15] = 1;
        buf.extend_from_slice(&octets);
        buf.extend_from_slice(&443u16.to_be_bytes()); // port 443
        let (addr, consumed) = TargetAddr::parse_socks5(&buf).unwrap();
        assert_eq!(consumed, 19);
        match addr {
            TargetAddr::Ip(sa) => {
                assert!(sa.is_ipv6());
                assert_eq!(sa.port(), 443);
            }
            _ => panic!("expected Ip variant"),
        }
    }

    #[test]
    fn test_parse_domain() {
        let domain = b"example.com";
        let mut buf = vec![0x03, domain.len() as u8];
        buf.extend_from_slice(domain);
        buf.extend_from_slice(&80u16.to_be_bytes());
        let (addr, consumed) = TargetAddr::parse_socks5(&buf).unwrap();
        assert_eq!(consumed, 2 + domain.len() + 2);
        match addr {
            TargetAddr::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 80);
            }
            _ => panic!("expected Domain variant"),
        }
    }

    #[test]
    fn test_roundtrip_write_parse() {
        let cases = vec![
            TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 1),
                3128,
            ))),
            TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                9000,
                0,
                0,
            ))),
            TargetAddr::Domain("test.example.org".into(), 443),
        ];
        for original in &cases {
            let mut buf = Vec::new();
            original.write_socks5(&mut buf);
            let (parsed, consumed) = TargetAddr::parse_socks5(&buf).unwrap();
            assert_eq!(&parsed, original);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_unspecified() {
        let addr = TargetAddr::unspecified();
        match addr {
            TargetAddr::Ip(sa) => {
                assert_eq!(sa.to_string(), "0.0.0.0:0");
            }
            _ => panic!("expected Ip variant"),
        }
    }
}

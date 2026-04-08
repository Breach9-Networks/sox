use crate::error::ProtocolError;
use crate::protocol::addr::TargetAddr;

/// A parsed SOCKS5 UDP relay header (RFC 1928, section 7).
#[derive(Debug, Clone)]
pub struct UdpHeader {
    /// Fragment number. 0 = standalone, >0 = fragment sequence.
    pub frag: u8,
    /// Target address.
    pub target: TargetAddr,
}

/// Parse a SOCKS5 UDP relay header.
///
/// Format: [rsv(2), frag(1), atyp(1), addr(variable), port(2), data...]
///
/// Returns the header and the offset where payload data begins.
pub fn parse_udp_header(buf: &[u8]) -> Result<(UdpHeader, usize), ProtocolError> {
    if buf.len() < 4 {
        return Err(ProtocolError::Incomplete {
            needed: 4,
            got: buf.len(),
        });
    }

    // buf[0..2] = RSV (must be 0x0000)
    let frag = buf[2];

    // Address starts at offset 3
    let (target, addr_len) = TargetAddr::parse_socks5(&buf[3..])?;
    let header_len = 3 + addr_len;

    Ok((UdpHeader { frag, target }, header_len))
}

/// Write a SOCKS5 UDP relay header.
///
/// Format: [rsv(2), frag(1), atyp(1), addr(variable), port(2)]
pub fn write_udp_header(header: &UdpHeader, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x00, 0x00]); // RSV
    out.push(header.frag);
    header.target.write_socks5(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn parse_udp_ipv4() {
        // rsv=0000, frag=0, atyp=01, ip=1.2.3.4, port=53
        let buf = [0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35, 0xAA];
        let (header, offset) = parse_udp_header(&buf).unwrap();
        assert_eq!(header.frag, 0);
        assert_eq!(
            header.target,
            TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 2, 3, 4),
                53
            )))
        );
        assert_eq!(offset, 10); // payload starts at byte 10
        assert_eq!(buf[offset], 0xAA); // first payload byte
    }

    #[test]
    fn roundtrip_udp_header() {
        let header = UdpHeader {
            frag: 0,
            target: TargetAddr::Domain("dns.google".into(), 53),
        };
        let mut buf = Vec::new();
        write_udp_header(&header, &mut buf);

        let (parsed, _) = parse_udp_header(&buf).unwrap();
        assert_eq!(parsed.frag, 0);
        assert_eq!(parsed.target, header.target);
    }
}

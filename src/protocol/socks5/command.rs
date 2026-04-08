use crate::error::ProtocolError;
use crate::protocol::addr::TargetAddr;
use crate::protocol::socks5::{Socks5Command, SOCKS5_VERSION};

/// A parsed SOCKS5 command request.
#[derive(Debug, Clone)]
pub struct CommandRequest {
    pub command: Socks5Command,
    pub target: TargetAddr,
}

/// Parse a SOCKS5 command request.
///
/// Format: [version(1), cmd(1), rsv(1), atyp(1), addr(variable), port(2)]
///
/// Returns the parsed request and total bytes consumed.
pub fn parse_command_request(buf: &[u8]) -> Result<(CommandRequest, usize), ProtocolError> {
    if buf.len() < 4 {
        return Err(ProtocolError::Incomplete {
            needed: 4,
            got: buf.len(),
        });
    }

    if buf[0] != SOCKS5_VERSION {
        return Err(ProtocolError::InvalidVersion(buf[0]));
    }

    let command =
        Socks5Command::from_byte(buf[1]).ok_or(ProtocolError::InvalidCommand(buf[1]))?;

    // buf[2] is RSV (reserved), skip it
    // buf[3..] is address type + address + port
    let (target, addr_len) = TargetAddr::parse_socks5(&buf[3..])?;
    let total = 3 + addr_len;

    Ok((CommandRequest { command, target }, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_ipv4() {
        // CONNECT to 127.0.0.1:80
        let buf = [
            0x05, 0x01, 0x00, // ver, cmd=CONNECT, rsv
            0x01, 127, 0, 0, 1, // atyp=IPv4, addr
            0x00, 0x50, // port=80
        ];
        let (req, len) = parse_command_request(&buf).unwrap();
        assert_eq!(req.command, Socks5Command::Connect);
        assert_eq!(req.target.to_string(), "127.0.0.1:80");
        assert_eq!(len, 10);
    }

    #[test]
    fn parse_connect_domain() {
        // CONNECT to example.com:443
        let domain = b"example.com";
        let mut buf = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        buf.extend_from_slice(domain);
        buf.extend_from_slice(&443u16.to_be_bytes());

        let (req, _) = parse_command_request(&buf).unwrap();
        assert_eq!(req.command, Socks5Command::Connect);
        assert_eq!(req.target.to_string(), "example.com:443");
    }
}

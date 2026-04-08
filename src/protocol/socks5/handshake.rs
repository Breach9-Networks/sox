use crate::error::ProtocolError;
use crate::protocol::socks5::{AuthMethod, SOCKS5_VERSION};

/// Parse the client's method selection message.
///
/// Format: [version(1), nmethods(1), methods(nmethods)]
///
/// Returns the list of auth methods the client supports.
pub fn parse_method_request(buf: &[u8]) -> Result<Vec<AuthMethod>, ProtocolError> {
    if buf.len() < 2 {
        return Err(ProtocolError::Incomplete {
            needed: 2,
            got: buf.len(),
        });
    }

    if buf[0] != SOCKS5_VERSION {
        return Err(ProtocolError::InvalidVersion(buf[0]));
    }

    let nmethods = buf[1] as usize;
    let total = 2 + nmethods;

    if buf.len() < total {
        return Err(ProtocolError::Incomplete {
            needed: total,
            got: buf.len(),
        });
    }

    let methods = buf[2..total]
        .iter()
        .filter_map(|&b| AuthMethod::from_byte(b))
        .collect();

    Ok(methods)
}

/// Write the server's method selection response.
///
/// Format: [version(1), method(1)]
pub fn write_method_response(method: AuthMethod, out: &mut Vec<u8>) {
    out.push(SOCKS5_VERSION);
    out.push(method as u8);
}

/// RFC 1929 subnegotiation version.
const USERPASS_VERSION: u8 = 0x01;

/// Parse a RFC 1929 username/password authentication request.
///
/// Format: [version(1), ulen(1), uname(ulen), plen(1), passwd(plen)]
///
/// Returns (username, password).
pub fn parse_userpass_request(buf: &[u8]) -> Result<(String, String), ProtocolError> {
    if buf.len() < 2 {
        return Err(ProtocolError::Incomplete {
            needed: 2,
            got: buf.len(),
        });
    }

    if buf[0] != USERPASS_VERSION {
        return Err(ProtocolError::InvalidAuthVersion(buf[0]));
    }

    let ulen = buf[1] as usize;
    // 1 (ver) + 1 (ulen) + ulen + 1 (plen) = minimum before password
    if buf.len() < 2 + ulen + 1 {
        return Err(ProtocolError::Incomplete {
            needed: 2 + ulen + 1,
            got: buf.len(),
        });
    }

    let username = String::from_utf8_lossy(&buf[2..2 + ulen]).into_owned();
    let plen = buf[2 + ulen] as usize;
    let total = 2 + ulen + 1 + plen;

    if buf.len() < total {
        return Err(ProtocolError::Incomplete {
            needed: total,
            got: buf.len(),
        });
    }

    let password =
        String::from_utf8_lossy(&buf[3 + ulen..3 + ulen + plen]).into_owned();

    Ok((username, password))
}

/// Write a RFC 1929 username/password authentication response.
///
/// Format: [version(1), status(1)]
/// status: 0x00 = success, anything else = failure.
pub fn write_userpass_response(success: bool, out: &mut Vec<u8>) {
    out.push(USERPASS_VERSION);
    out.push(if success { 0x00 } else { 0x01 });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_no_auth_request() {
        let buf = [0x05, 0x01, 0x00];
        let methods = parse_method_request(&buf).unwrap();
        assert_eq!(methods, vec![AuthMethod::None]);
    }

    #[test]
    fn parse_multiple_methods() {
        let buf = [0x05, 0x02, 0x00, 0x02];
        let methods = parse_method_request(&buf).unwrap();
        assert_eq!(methods, vec![AuthMethod::None, AuthMethod::UsernamePassword]);
    }

    #[test]
    fn parse_wrong_version() {
        let buf = [0x04, 0x01, 0x00];
        assert!(matches!(
            parse_method_request(&buf),
            Err(ProtocolError::InvalidVersion(0x04))
        ));
    }

    #[test]
    fn parse_incomplete() {
        let buf = [0x05];
        assert!(matches!(
            parse_method_request(&buf),
            Err(ProtocolError::Incomplete { .. })
        ));
    }

    #[test]
    fn write_method_response_no_auth() {
        let mut out = Vec::new();
        write_method_response(AuthMethod::None, &mut out);
        assert_eq!(out, vec![0x05, 0x00]);
    }

    #[test]
    fn parse_userpass() {
        // version=1, ulen=5, "alice", plen=6, "secret"
        let buf = [
            0x01, 0x05, b'a', b'l', b'i', b'c', b'e', 0x06, b's', b'e', b'c', b'r',
            b'e', b't',
        ];
        let (user, pass) = parse_userpass_request(&buf).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "secret");
    }

    #[test]
    fn parse_userpass_wrong_version() {
        let buf = [0x02, 0x01, b'a', 0x01, b'b'];
        assert!(matches!(
            parse_userpass_request(&buf),
            Err(ProtocolError::InvalidAuthVersion(0x02))
        ));
    }

    #[test]
    fn write_userpass_success() {
        let mut out = Vec::new();
        write_userpass_response(true, &mut out);
        assert_eq!(out, vec![0x01, 0x00]);
    }

    #[test]
    fn write_userpass_failure() {
        let mut out = Vec::new();
        write_userpass_response(false, &mut out);
        assert_eq!(out, vec![0x01, 0x01]);
    }
}

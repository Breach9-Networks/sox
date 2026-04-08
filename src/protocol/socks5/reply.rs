use crate::protocol::addr::TargetAddr;
use crate::protocol::socks5::{ReplyCode, SOCKS5_VERSION};

/// Write a SOCKS5 command reply.
///
/// Format: [version(1), rep(1), rsv(1), atyp(1), bind_addr(variable), bind_port(2)]
pub fn write_command_reply(code: ReplyCode, bind_addr: &TargetAddr, out: &mut Vec<u8>) {
    out.push(SOCKS5_VERSION);
    out.push(code as u8);
    out.push(0x00); // RSV
    bind_addr.write_socks5(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_success_reply() {
        let mut out = Vec::new();
        let bind = TargetAddr::unspecified();
        write_command_reply(ReplyCode::Succeeded, &bind, &mut out);
        // 05 00 00 01 00000000 0000
        assert_eq!(out, vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }
}

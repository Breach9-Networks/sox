/// Detected SOCKS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    V4,
    V5,
}

/// Detect SOCKS version from the first byte.
///
/// - `0x04` → SOCKS4/4a
/// - `0x05` → SOCKS5
pub fn detect_version(first_byte: u8) -> Option<SocksVersion> {
    match first_byte {
        0x04 => Some(SocksVersion::V4),
        0x05 => Some(SocksVersion::V5),
        _ => None,
    }
}

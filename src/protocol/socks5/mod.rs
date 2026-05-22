pub mod command;
pub mod handshake;
pub mod reply;
pub mod udp;

/// SOCKS5 protocol version.
pub const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 authentication methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    None = 0x00,
    UsernamePassword = 0x02,
    NoAcceptable = 0xFF,
}

impl AuthMethod {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(AuthMethod::None),
            0x02 => Some(AuthMethod::UsernamePassword),
            0xFF => Some(AuthMethod::NoAcceptable),
            _ => None,
        }
    }
}

/// SOCKS5 command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl Socks5Command {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Socks5Command::Connect),
            0x02 => Some(Socks5Command::Bind),
            0x03 => Some(Socks5Command::UdpAssociate),
            _ => None,
        }
    }
}

/// SOCKS5 reply codes (RFC 1928).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl ReplyCode {
    /// Map a reply-code byte back to a `ReplyCode` (used by the tunnel
    /// `StreamReply.status` field). Unknown values fall back to GeneralFailure.
    pub fn from_u8(b: u8) -> ReplyCode {
        match b {
            0x00 => ReplyCode::Succeeded,
            0x02 => ReplyCode::ConnectionNotAllowed,
            0x03 => ReplyCode::NetworkUnreachable,
            0x04 => ReplyCode::HostUnreachable,
            0x05 => ReplyCode::ConnectionRefused,
            0x06 => ReplyCode::TtlExpired,
            0x07 => ReplyCode::CommandNotSupported,
            0x08 => ReplyCode::AddressTypeNotSupported,
            _ => ReplyCode::GeneralFailure,
        }
    }

    /// Classify a connect() error into the closest SOCKS5 reply code.
    pub fn for_connect_error(e: &std::io::Error) -> ReplyCode {
        match e.kind() {
            std::io::ErrorKind::ConnectionRefused => ReplyCode::ConnectionRefused,
            std::io::ErrorKind::AddrNotAvailable => ReplyCode::HostUnreachable,
            std::io::ErrorKind::TimedOut => ReplyCode::TtlExpired,
            _ => ReplyCode::GeneralFailure,
        }
    }
}

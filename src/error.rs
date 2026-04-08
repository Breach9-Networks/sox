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
        }
    }
}

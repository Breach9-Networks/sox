//! Tunnel protocol message definitions.
//!
//! Wire format (after Noise encryption):
//! ```text
//! [length: u16 BE][type: u8][payload: N bytes]
//! ```

use crate::error::ServerError;

/// Message types for the tunnel protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Client → Server: register with an ID
    Register = 0x01,
    /// Bidirectional: keepalive heartbeat
    Heartbeat = 0x02,
    /// Server → Client: signal client to open a new data connection
    RequestProxy = 0x03,
    /// Client → Server: data connection is ready
    DataReady = 0x04,
    /// Server → Client (on data conn): proxy this target
    ProxyRequest = 0x05,
    /// Client → Server (on data conn): proxy result
    ProxyReply = 0x06,
    /// Either direction: relay data through tunnel (framed)
    RelayData = 0x10,
    /// Either direction: relay direction finished (half-close signal)
    RelayEnd = 0x11,
    /// Either direction: graceful disconnect
    Disconnect = 0xFF,
}

impl MessageType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Register),
            0x02 => Some(Self::Heartbeat),
            0x03 => Some(Self::RequestProxy),
            0x04 => Some(Self::DataReady),
            0x05 => Some(Self::ProxyRequest),
            0x06 => Some(Self::ProxyReply),
            0x10 => Some(Self::RelayData),
            0x11 => Some(Self::RelayEnd),
            0xFF => Some(Self::Disconnect),
            _ => None,
        }
    }
}

/// Messages exchanged over the tunnel.
#[derive(Debug, Clone)]
pub enum TunnelMessage {
    Register {
        client_id: String,
        pool_size: u16,
    },
    Heartbeat,
    RequestProxy {
        request_id: u64,
    },
    DataReady {
        client_id: String,
    },
    ProxyRequest {
        request_id: u64,
        /// Target address in format "host:port"
        target: String,
    },
    ProxyReply {
        request_id: u64,
        success: bool,
        /// Bound address after connection, or error message
        message: String,
    },
    /// Relay data through the tunnel (framed, no extra length field — Noise frame provides length).
    RelayData {
        data: Vec<u8>,
    },
    /// Signals one relay direction is finished (half-close).
    RelayEnd,
    Disconnect {
        reason: String,
    },
}

impl TunnelMessage {
    /// Serialize message to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let capacity = match self {
            TunnelMessage::Heartbeat | TunnelMessage::RelayEnd => 1,
            TunnelMessage::RequestProxy { .. } => 9,
            TunnelMessage::Register { client_id, .. } => 4 + client_id.len(),
            TunnelMessage::DataReady { client_id } => 2 + client_id.len(),
            TunnelMessage::ProxyRequest { target, .. } => 11 + target.len(),
            TunnelMessage::ProxyReply { message, .. } => 12 + message.len(),
            TunnelMessage::RelayData { data } => 1 + data.len(),
            TunnelMessage::Disconnect { reason } => 3 + reason.len(),
        };
        let mut buf = Vec::with_capacity(capacity);
        match self {
            TunnelMessage::Register { client_id, pool_size } => {
                buf.push(MessageType::Register as u8);
                let id_bytes = client_id.as_bytes();
                buf.push(id_bytes.len() as u8);
                buf.extend_from_slice(id_bytes);
                buf.extend_from_slice(&pool_size.to_be_bytes());
            }
            TunnelMessage::Heartbeat => {
                buf.push(MessageType::Heartbeat as u8);
            }
            TunnelMessage::RequestProxy { request_id } => {
                buf.push(MessageType::RequestProxy as u8);
                buf.extend_from_slice(&request_id.to_be_bytes());
            }
            TunnelMessage::DataReady { client_id } => {
                buf.push(MessageType::DataReady as u8);
                let id_bytes = client_id.as_bytes();
                buf.push(id_bytes.len() as u8);
                buf.extend_from_slice(id_bytes);
            }
            TunnelMessage::ProxyRequest { request_id, target } => {
                buf.push(MessageType::ProxyRequest as u8);
                buf.extend_from_slice(&request_id.to_be_bytes());
                let target_bytes = target.as_bytes();
                buf.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(target_bytes);
            }
            TunnelMessage::ProxyReply { request_id, success, message } => {
                buf.push(MessageType::ProxyReply as u8);
                buf.extend_from_slice(&request_id.to_be_bytes());
                buf.push(if *success { 1 } else { 0 });
                let msg_bytes = message.as_bytes();
                buf.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(msg_bytes);
            }
            TunnelMessage::RelayData { data } => {
                buf.push(MessageType::RelayData as u8);
                buf.extend_from_slice(data);
            }
            TunnelMessage::RelayEnd => {
                buf.push(MessageType::RelayEnd as u8);
            }
            TunnelMessage::Disconnect { reason } => {
                buf.push(MessageType::Disconnect as u8);
                let r = reason.as_bytes();
                buf.extend_from_slice(&(r.len() as u16).to_be_bytes());
                buf.extend_from_slice(r);
            }
        }
        buf
    }

    /// Deserialize message from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ServerError> {
        if buf.is_empty() {
            return Err(ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "empty tunnel message",
            )));
        }

        let msg_type = MessageType::from_byte(buf[0]).ok_or_else(|| {
            ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown tunnel message type: {:#x}", buf[0]),
            ))
        })?;

        let payload = &buf[1..];

        match msg_type {
            MessageType::Register => {
                if payload.is_empty() {
                    return Err(decode_err("Register: missing client_id length"));
                }
                let id_len = payload[0] as usize;
                if payload.len() < 1 + id_len + 2 {
                    return Err(decode_err("Register: incomplete"));
                }
                let client_id =
                    String::from_utf8_lossy(&payload[1..1 + id_len]).into_owned();
                let pool_size = u16::from_be_bytes([
                    payload[1 + id_len],
                    payload[2 + id_len],
                ]);
                Ok(TunnelMessage::Register { client_id, pool_size })
            }
            MessageType::Heartbeat => Ok(TunnelMessage::Heartbeat),
            MessageType::RequestProxy => {
                if payload.len() < 8 {
                    return Err(decode_err("RequestProxy: incomplete"));
                }
                let request_id = u64::from_be_bytes(payload[..8].try_into().unwrap());
                Ok(TunnelMessage::RequestProxy { request_id })
            }
            MessageType::DataReady => {
                if payload.is_empty() {
                    return Err(decode_err("DataReady: missing client_id length"));
                }
                let id_len = payload[0] as usize;
                if payload.len() < 1 + id_len {
                    return Err(decode_err("DataReady: incomplete"));
                }
                let client_id =
                    String::from_utf8_lossy(&payload[1..1 + id_len]).into_owned();
                Ok(TunnelMessage::DataReady { client_id })
            }
            MessageType::ProxyRequest => {
                if payload.len() < 10 {
                    return Err(decode_err("ProxyRequest: incomplete"));
                }
                let request_id = u64::from_be_bytes(payload[..8].try_into().unwrap());
                let target_len =
                    u16::from_be_bytes([payload[8], payload[9]]) as usize;
                if payload.len() < 10 + target_len {
                    return Err(decode_err("ProxyRequest: target incomplete"));
                }
                let target =
                    String::from_utf8_lossy(&payload[10..10 + target_len]).into_owned();
                Ok(TunnelMessage::ProxyRequest { request_id, target })
            }
            MessageType::ProxyReply => {
                if payload.len() < 11 {
                    return Err(decode_err("ProxyReply: incomplete"));
                }
                let request_id = u64::from_be_bytes(payload[..8].try_into().unwrap());
                let success = payload[8] != 0;
                let msg_len =
                    u16::from_be_bytes([payload[9], payload[10]]) as usize;
                if payload.len() < 11 + msg_len {
                    return Err(decode_err("ProxyReply: message incomplete"));
                }
                let message =
                    String::from_utf8_lossy(&payload[11..11 + msg_len]).into_owned();
                Ok(TunnelMessage::ProxyReply {
                    request_id,
                    success,
                    message,
                })
            }
            MessageType::RelayData => {
                Ok(TunnelMessage::RelayData { data: payload.to_vec() })
            }
            MessageType::RelayEnd => {
                Ok(TunnelMessage::RelayEnd)
            }
            MessageType::Disconnect => {
                if payload.len() < 2 {
                    return Err(decode_err("Disconnect: incomplete"));
                }
                let r_len =
                    u16::from_be_bytes([payload[0], payload[1]]) as usize;
                let reason = if payload.len() >= 2 + r_len {
                    String::from_utf8_lossy(&payload[2..2 + r_len]).into_owned()
                } else {
                    String::new()
                };
                Ok(TunnelMessage::Disconnect { reason })
            }
        }
    }
}

fn decode_err(msg: &str) -> ServerError {
    ServerError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        msg,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_register() {
        let msg = TunnelMessage::Register {
            client_id: "node-1".into(),
            pool_size: 10,
        };
        let encoded = msg.encode();
        let decoded = TunnelMessage::decode(&encoded).unwrap();
        match decoded {
            TunnelMessage::Register { client_id, pool_size } => {
                assert_eq!(client_id, "node-1");
                assert_eq!(pool_size, 10);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn roundtrip_proxy_request() {
        let msg = TunnelMessage::ProxyRequest {
            request_id: 42,
            target: "example.com:443".into(),
        };
        let encoded = msg.encode();
        let decoded = TunnelMessage::decode(&encoded).unwrap();
        match decoded {
            TunnelMessage::ProxyRequest { request_id, target } => {
                assert_eq!(request_id, 42);
                assert_eq!(target, "example.com:443");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn roundtrip_heartbeat() {
        let msg = TunnelMessage::Heartbeat;
        let encoded = msg.encode();
        let decoded = TunnelMessage::decode(&encoded).unwrap();
        assert!(matches!(decoded, TunnelMessage::Heartbeat));
    }

    #[test]
    fn test_roundtrip_proxy_reply_success() {
        let msg = TunnelMessage::ProxyReply {
            request_id: 99,
            success: true,
            message: "127.0.0.1:8080".into(),
        };
        let encoded = msg.encode();
        let decoded = TunnelMessage::decode(&encoded).unwrap();
        match decoded {
            TunnelMessage::ProxyReply { request_id, success, message } => {
                assert_eq!(request_id, 99);
                assert!(success);
                assert_eq!(message, "127.0.0.1:8080");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_roundtrip_proxy_reply_failure() {
        let msg = TunnelMessage::ProxyReply {
            request_id: 7,
            success: false,
            message: "connection refused".into(),
        };
        let encoded = msg.encode();
        let decoded = TunnelMessage::decode(&encoded).unwrap();
        match decoded {
            TunnelMessage::ProxyReply { request_id, success, message } => {
                assert_eq!(request_id, 7);
                assert!(!success);
                assert_eq!(message, "connection refused");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_roundtrip_data_ready() {
        let msg = TunnelMessage::DataReady {
            client_id: "tunnel-abc".into(),
        };
        let encoded = msg.encode();
        let decoded = TunnelMessage::decode(&encoded).unwrap();
        match decoded {
            TunnelMessage::DataReady { client_id } => {
                assert_eq!(client_id, "tunnel-abc");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_roundtrip_disconnect() {
        let msg = TunnelMessage::Disconnect {
            reason: "shutting down".into(),
        };
        let encoded = msg.encode();
        let decoded = TunnelMessage::decode(&encoded).unwrap();
        match decoded {
            TunnelMessage::Disconnect { reason } => {
                assert_eq!(reason, "shutting down");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn roundtrip_relay_data() {
        let msg = TunnelMessage::RelayData {
            data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02],
        };
        let encoded = msg.encode();
        assert_eq!(encoded[0], MessageType::RelayData as u8);
        let decoded = TunnelMessage::decode(&encoded).unwrap();
        match decoded {
            TunnelMessage::RelayData { data } => {
                assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn roundtrip_relay_data_empty() {
        let msg = TunnelMessage::RelayData { data: vec![] };
        let encoded = msg.encode();
        let decoded = TunnelMessage::decode(&encoded).unwrap();
        match decoded {
            TunnelMessage::RelayData { data } => assert!(data.is_empty()),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn roundtrip_relay_end() {
        let msg = TunnelMessage::RelayEnd;
        let encoded = msg.encode();
        assert_eq!(encoded, vec![MessageType::RelayEnd as u8]);
        let decoded = TunnelMessage::decode(&encoded).unwrap();
        assert!(matches!(decoded, TunnelMessage::RelayEnd));
    }

    #[test]
    fn test_decode_invalid_type() {
        let buf = [0xAA, 0x00, 0x01];
        let result = TunnelMessage::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_empty() {
        let buf: [u8; 0] = [];
        let result = TunnelMessage::decode(&buf);
        assert!(result.is_err());
    }
}

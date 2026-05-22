//! Tunnel protocol message definitions.
//!
//! Wire format (after Noise encryption):
//! ```text
//! [length: u16 BE][type: u8][payload: N bytes]
//! ```

use crate::error::ServerError;
use crate::protocol::addr::TargetAddr;

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

/// 目前的 tunnel 協定版本。Hello 不符即拒絕。
pub const PROTO_VERSION: u8 = 1;

/// Session 握手訊息（client → server），yamux 之前交換。
#[derive(Debug, Clone)]
pub struct Hello {
    pub proto_version: u8,
    pub session_index: u16,
    pub client_id: String,
}

impl Hello {
    pub fn encode(&self) -> Vec<u8> {
        let id = self.client_id.as_bytes();
        let mut buf = Vec::with_capacity(4 + id.len());
        buf.push(self.proto_version);
        buf.extend_from_slice(&self.session_index.to_be_bytes());
        buf.push(id.len() as u8);
        buf.extend_from_slice(id);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ServerError> {
        if buf.len() < 4 {
            return Err(decode_err("Hello: too short"));
        }
        let id_len = buf[3] as usize;
        if buf.len() < 4 + id_len {
            return Err(decode_err("Hello: client_id incomplete"));
        }
        Ok(Hello {
            proto_version: buf[0],
            session_index: u16::from_be_bytes([buf[1], buf[2]]),
            client_id: String::from_utf8_lossy(&buf[4..4 + id_len]).into_owned(),
        })
    }
}

/// Session 握手回應（server → client）。
#[derive(Debug, Clone)]
pub struct HelloAck {
    pub accepted: bool,
    pub reason: String,
}

impl HelloAck {
    pub fn encode(&self) -> Vec<u8> {
        let r = self.reason.as_bytes();
        let mut buf = Vec::with_capacity(3 + r.len());
        buf.push(self.accepted as u8);
        buf.extend_from_slice(&(r.len() as u16).to_be_bytes());
        buf.extend_from_slice(r);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ServerError> {
        if buf.len() < 3 {
            return Err(decode_err("HelloAck: too short"));
        }
        let r_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if buf.len() < 3 + r_len {
            return Err(decode_err("HelloAck: reason incomplete"));
        }
        Ok(HelloAck {
            accepted: buf[0] != 0,
            reason: String::from_utf8_lossy(&buf[3..3 + r_len]).into_owned(),
        })
    }
}

/// Stream preamble — server 開 yamux stream 後寫的開頭位元組。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamOpen {
    /// 0x01：TCP connect 到 target（"host:port"）。
    Tcp { target: String },
    /// 0x02：UDP associate。
    Udp,
}

impl StreamOpen {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            StreamOpen::Tcp { target } => {
                let t = target.as_bytes();
                let mut buf = Vec::with_capacity(3 + t.len());
                buf.push(0x01);
                buf.extend_from_slice(&(t.len() as u16).to_be_bytes());
                buf.extend_from_slice(t);
                buf
            }
            StreamOpen::Udp => vec![0x02],
        }
    }

    /// 回傳 (訊息, 消費的位元組數)。資料不足時回 Err。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ServerError> {
        match buf.first() {
            Some(0x01) => {
                if buf.len() < 3 {
                    return Err(decode_err("StreamOpen::Tcp: need target_len"));
                }
                let t_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
                if buf.len() < 3 + t_len {
                    return Err(decode_err("StreamOpen::Tcp: target incomplete"));
                }
                let target = String::from_utf8_lossy(&buf[3..3 + t_len]).into_owned();
                Ok((StreamOpen::Tcp { target }, 3 + t_len))
            }
            Some(0x02) => Ok((StreamOpen::Udp, 1)),
            Some(other) => Err(decode_err(&format!("StreamOpen: unknown kind {other:#x}"))),
            None => Err(decode_err("StreamOpen: empty")),
        }
    }
}

/// Stream preamble 回應 — client 回寫的開頭位元組。
#[derive(Debug, Clone)]
pub struct StreamReply {
    /// 0 = ok；非 0 = 錯誤碼（對映 SOCKS5 reply code）。
    pub status: u8,
    /// 成功為 bind addr，失敗為錯誤訊息。
    pub message: String,
}

impl StreamReply {
    pub fn encode(&self) -> Vec<u8> {
        let m = self.message.as_bytes();
        let mut buf = Vec::with_capacity(3 + m.len());
        buf.push(self.status);
        buf.extend_from_slice(&(m.len() as u16).to_be_bytes());
        buf.extend_from_slice(m);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ServerError> {
        if buf.len() < 3 {
            return Err(decode_err("StreamReply: too short"));
        }
        let m_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if buf.len() < 3 + m_len {
            return Err(decode_err("StreamReply: message incomplete"));
        }
        Ok((
            StreamReply {
                status: buf[0],
                message: String::from_utf8_lossy(&buf[3..3 + m_len]).into_owned(),
            },
            3 + m_len,
        ))
    }
}

/// UDP stream 上的單則 datagram：`[len:u16][atyp][addr][port:u16][payload]`。
/// `len` 涵蓋其後全部位元組。addr 沿用 SOCKS5 的 atyp+addr+port 編碼。
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    pub addr: TargetAddr,
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    pub fn encode(&self) -> Vec<u8> {
        let mut addr_bytes = Vec::new();
        self.addr.write_socks5(&mut addr_bytes);
        let body_len = addr_bytes.len() + self.payload.len();
        let mut buf = Vec::with_capacity(2 + body_len);
        buf.extend_from_slice(&(body_len as u16).to_be_bytes());
        buf.extend_from_slice(&addr_bytes);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Ok(None) = 資料不足；Ok(Some((dat, consumed))) = 解出一則；Err = 格式錯誤。
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>, ServerError> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let body_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if buf.len() < 2 + body_len {
            return Ok(None);
        }
        let body = &buf[2..2 + body_len];
        let (addr, addr_len) = TargetAddr::parse_socks5(body)?;
        let payload = body[addr_len..].to_vec();
        Ok(Some((UdpDatagram { addr, payload }, 2 + body_len)))
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
    fn roundtrip_hello() {
        let msg = Hello { proto_version: 1, session_index: 3, client_id: "node-1".into() };
        let decoded = Hello::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.proto_version, 1);
        assert_eq!(decoded.session_index, 3);
        assert_eq!(decoded.client_id, "node-1");
    }

    #[test]
    fn roundtrip_hello_ack() {
        let ok = HelloAck { accepted: true, reason: String::new() };
        let decoded = HelloAck::decode(&ok.encode()).unwrap();
        assert!(decoded.accepted);

        let rej = HelloAck { accepted: false, reason: "version mismatch".into() };
        let decoded = HelloAck::decode(&rej.encode()).unwrap();
        assert!(!decoded.accepted);
        assert_eq!(decoded.reason, "version mismatch");
    }

    #[test]
    fn hello_decode_rejects_truncated() {
        assert!(Hello::decode(&[1, 0]).is_err());
    }

    #[test]
    fn roundtrip_stream_open_tcp() {
        let msg = StreamOpen::Tcp { target: "example.com:443".into() };
        let bytes = msg.encode();
        let (decoded, consumed) = StreamOpen::decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        match decoded {
            StreamOpen::Tcp { target } => assert_eq!(target, "example.com:443"),
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn roundtrip_stream_open_udp() {
        let bytes = StreamOpen::Udp.encode();
        let (decoded, consumed) = StreamOpen::decode(&bytes).unwrap();
        assert_eq!(consumed, 1);
        assert!(matches!(decoded, StreamOpen::Udp));
    }

    #[test]
    fn stream_open_decode_needs_more() {
        // 只給 kind + 半截 target_len → 回報需要更多資料
        assert!(StreamOpen::decode(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn roundtrip_stream_reply() {
        let ok = StreamReply { status: 0, message: "10.0.0.1:5555".into() };
        let encoded = ok.encode();
        let (d, n) = StreamReply::decode(&encoded).unwrap();
        assert_eq!(n, encoded.len());
        assert_eq!(d.status, 0);
        assert_eq!(d.message, "10.0.0.1:5555");
    }

    #[test]
    fn roundtrip_udp_datagram() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        let addr = TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4),
            53,
        )));
        let dat = UdpDatagram { addr: addr.clone(), payload: vec![0xAB; 100] };
        let bytes = dat.encode();
        let (decoded, consumed) = UdpDatagram::decode(&bytes).unwrap().unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.addr, addr);
        assert_eq!(decoded.payload, vec![0xAB; 100]);
    }

    #[test]
    fn udp_datagram_partial_returns_none() {
        // 只給半截 → decode 回 Ok(None) 表示「需要更多資料」
        assert!(matches!(UdpDatagram::decode(&[0x00]), Ok(None)));
    }

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

//! Tunnel 協定訊息定義。
//!
//! 協定分三層：
//! - Session 層：`Hello`/`HelloAck`，在 yamux 之前交換，各裝在一個 Noise message。
//! - Stream preamble 層：`StreamOpen`/`StreamReply`，每條 yamux stream 開頭的位元組。
//! - Payload 層：TCP stream 承載裸位元組；UDP stream 承載 `UdpDatagram`。

use crate::error::ServerError;
use crate::protocol::addr::TargetAddr;

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
    /// 0 = ok；非 0 = SOCKS5 ReplyCode 的位元組值。
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

fn decode_err(msg: &str) -> ServerError {
    ServerError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, msg))
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
        assert!(matches!(UdpDatagram::decode(&[0x00]), Ok(None)));
    }
}

# Tunnel Stream Multiplexing 實作計畫

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 reverse tunnel 從「200 條單一 stream 連線池」改成「少量 yamux session 多工」，支援 >1000 並發 TCP/UDP flow。

**Architecture:** `TCP → NoiseByteStream（Noise 的 AsyncRead/AsyncWrite 形態）→ yamux Session → 多個 yamux stream`。SOCKS server 端開 outbound stream、tunnel client 端接 inbound stream。每個 proxy flow = 一條 yamux stream。

**Tech Stack:** Rust / tokio / `snow`（Noise）/ `yamux`（多工）/ `tokio-util`（compat 轉接）。

**設計來源:** `docs/specs/2026-05-22-tunnel-multiplexing-design.md` — 實作每個 Task 前先讀對應的 spec 章節。

**通用慣例:**
- 每個 Task 走 TDD：先寫失敗測試 → 跑 → 實作 → 跑 → commit。
- 測試指令統一 `cargo test`，型別檢查 `cargo clippy --all-targets`。
- commit message 用 `feat:` / `test:` / `refactor:` / `chore:` 前綴，結尾加 `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`。
- 分支：`feat/tunnel-multiplexing`（已建立）。

---

## Phase 0 — 依賴

### Task 1: 加入 yamux 依賴

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: 加入依賴**

在 `Cargo.toml` 的 `[dependencies]` 區塊加入：

```toml
yamux = "0.13"
```

- [ ] **Step 2: 驗證可編譯**

Run: `cargo build`
Expected: 編譯成功，下載並編譯 `yamux` 及其依賴。

- [ ] **Step 3: 確認 API 假設**

Run: `cargo doc -p yamux --no-deps --open` 或檢視 `~/.cargo/registry/src/.../yamux-0.13.*/src/lib.rs`
確認下列 API 存在（plan 後續依賴它們），若版本 API 不同則記錄在此 Task 下方：
- `yamux::Config` 的 `set_max_num_streams`、`set_max_connection_receive_window`、`set_split_send_size`
- `yamux::Connection::new(io, Config, Mode)`、`Mode::Client`、`Mode::Server`
- `Connection::poll_next_inbound`、`Connection::poll_new_outbound`、`Connection::poll_close`
- `yamux::Stream` 實作 `futures::io::AsyncRead + AsyncWrite`

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add yamux dependency for tunnel multiplexing"
```

---

## Phase 1 — NoiseByteStream

> Spec §4.2。把 Noise transport 從訊息式改成位元組流式。這是整個 feature 的地基。

### Task 2: NoiseByteStream — Noise 的 AsyncRead/AsyncWrite 轉接層

**Files:**
- Create: `src/tunnel/noise_stream.rs`
- Modify: `src/tunnel/mod.rs`（加 `pub mod noise_stream;`）
- Modify: `src/tunnel/noise.rs`（加一個把握手後的 `NoiseStream` 轉成 `NoiseByteStream` 的方法）

- [ ] **Step 1: 宣告模組並寫失敗測試**

在 `src/tunnel/mod.rs` 加 `pub mod noise_stream;`。

建立 `src/tunnel/noise_stream.rs`，先放測試（測試用一對 in-memory duplex 不夠 —— Noise 需要真握手，所以用 loopback TCP）：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::noise::{NoiseStream, derive_psk};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// 建立一對已完成 Noise 握手、已轉成 byte stream 的端點。
    async fn connected_pair() -> (NoiseByteStream, NoiseByteStream) {
        let psk = derive_psk("test-secret");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            NoiseStream::accept(tcp, &psk).await.unwrap().into_byte_stream()
        });
        let client_tcp = TcpStream::connect(addr).await.unwrap();
        let client = NoiseStream::connect(client_tcp, &psk).await.unwrap().into_byte_stream();
        let server = server.await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn roundtrip_small() {
        let (mut a, mut b) = connected_pair().await;
        a.write_all(b"hello world").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0u8; 11];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello world");
    }

    #[tokio::test]
    async fn roundtrip_spanning_chunk_boundary() {
        // 寫入大於單一 Noise message 上限（65519）的資料，
        // 驗證寫入端正確分塊、讀取端正確重組。
        let (mut a, mut b) = connected_pair().await;
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();
        let writer = tokio::spawn(async move {
            a.write_all(&payload).await.unwrap();
            a.flush().await.unwrap();
            a.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, expect);
    }

    #[tokio::test]
    async fn eof_propagates() {
        let (mut a, mut b) = connected_pair().await;
        a.shutdown().await.unwrap();
        drop(a);
        let mut buf = [0u8; 8];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "對端關閉後應讀到 EOF");
    }
}
```

- [ ] **Step 2: 跑測試確認失敗**

Run: `cargo test --lib noise_stream`
Expected: 編譯失敗 —— `NoiseByteStream`、`into_byte_stream` 未定義。

- [ ] **Step 3: 實作 NoiseByteStream**

在 `src/tunnel/noise_stream.rs` 模組頂端寫入：

```rust
//! Noise transport 的 AsyncRead/AsyncWrite 形態。
//!
//! 把已完成握手的 Noise transport 包成透明的加密位元組管道，
//! 供 yamux 在其上做多工。寫入的位元組被切成 <= 65519 bytes 的
//! Noise message（65535 ciphertext 上限扣掉 16 byte AEAD tag），
//! 每則 message 以 `[len: u16 BE][ciphertext]` 上線。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use snow::TransportState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

const NOISE_TAG_LEN: usize = 16;
const NOISE_MAX_CIPHERTEXT: usize = 65535;
const NOISE_MAX_PLAINTEXT: usize = NOISE_MAX_CIPHERTEXT - NOISE_TAG_LEN; // 65519

enum ReadState {
    /// 正在讀 2-byte 長度前綴。
    Len { buf: [u8; 2], filled: usize },
    /// 正在讀 ciphertext 本體。
    Body { buf: Vec<u8>, filled: usize },
    /// 已解密，正把 plaintext 交給呼叫端。
    Drain { pos: usize, len: usize },
    /// 對端已關閉。
    Eof,
}

enum WriteState {
    Idle,
    /// 已加密一則 frame，正寫到底層 TCP。
    /// `consumed` = 此 frame 對應呼叫端 buf 的位元組數。
    Flushing { end: usize, pos: usize, consumed: usize },
}

pub struct NoiseByteStream {
    stream: TcpStream,
    transport: TransportState,
    read_state: ReadState,
    write_state: WriteState,
    /// 解密後的 plaintext（Drain 狀態下被消費）。
    decrypt_buf: Vec<u8>,
    /// `[len:2][ciphertext]`，Flushing 狀態下被消費。
    encrypt_buf: Vec<u8>,
}

impl NoiseByteStream {
    pub fn new(stream: TcpStream, transport: TransportState) -> Self {
        Self {
            stream,
            transport,
            read_state: ReadState::Len { buf: [0; 2], filled: 0 },
            write_state: WriteState::Idle,
            decrypt_buf: vec![0u8; NOISE_MAX_CIPHERTEXT],
            encrypt_buf: vec![0u8; 2 + NOISE_MAX_CIPHERTEXT],
        }
    }
}

impl AsyncRead for NoiseByteStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.read_state {
                ReadState::Eof => return Poll::Ready(Ok(())),
                ReadState::Drain { pos, len } => {
                    let avail = *len - *pos;
                    if avail == 0 {
                        this.read_state = ReadState::Len { buf: [0; 2], filled: 0 };
                        continue;
                    }
                    let n = avail.min(out.remaining());
                    out.put_slice(&this.decrypt_buf[*pos..*pos + n]);
                    *pos += n;
                    return Poll::Ready(Ok(()));
                }
                ReadState::Len { buf, filled } => {
                    let mut tmp = ReadBuf::new(&mut buf[*filled..]);
                    match Pin::new(&mut this.stream).poll_read(cx, &mut tmp) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let got = tmp.filled().len();
                            if got == 0 {
                                this.read_state = ReadState::Eof;
                                return Poll::Ready(Ok(()));
                            }
                            *filled += got;
                            if *filled == 2 {
                                let len = u16::from_be_bytes(*buf) as usize;
                                this.read_state =
                                    ReadState::Body { buf: vec![0u8; len], filled: 0 };
                            }
                        }
                    }
                }
                ReadState::Body { buf, filled } => {
                    if buf.is_empty() {
                        // 空 frame：解密後 plaintext 也空，直接回到 Len。
                        this.read_state = ReadState::Len { buf: [0; 2], filled: 0 };
                        continue;
                    }
                    let mut tmp = ReadBuf::new(&mut buf[*filled..]);
                    match Pin::new(&mut this.stream).poll_read(cx, &mut tmp) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let got = tmp.filled().len();
                            if got == 0 {
                                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                            }
                            *filled += got;
                            if *filled == buf.len() {
                                let n = this
                                    .transport
                                    .read_message(buf, &mut this.decrypt_buf)
                                    .map_err(|e| io::Error::other(format!("noise decrypt: {e}")))?;
                                this.read_state = ReadState::Drain { pos: 0, len: n };
                            }
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for NoiseByteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match &mut this.write_state {
                WriteState::Flushing { end, pos, consumed } => {
                    while *pos < *end {
                        match Pin::new(&mut this.stream)
                            .poll_write(cx, &this.encrypt_buf[*pos..*end])
                        {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                            }
                            Poll::Ready(Ok(n)) => *pos += n,
                        }
                    }
                    let consumed = *consumed;
                    this.write_state = WriteState::Idle;
                    return Poll::Ready(Ok(consumed));
                }
                WriteState::Idle => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    let chunk = buf.len().min(NOISE_MAX_PLAINTEXT);
                    let len = this
                        .transport
                        .write_message(&buf[..chunk], &mut this.encrypt_buf[2..])
                        .map_err(|e| io::Error::other(format!("noise encrypt: {e}")))?;
                    this.encrypt_buf[..2].copy_from_slice(&(len as u16).to_be_bytes());
                    this.write_state = WriteState::Flushing {
                        end: 2 + len,
                        pos: 0,
                        consumed: chunk,
                    };
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.write_state {
                WriteState::Flushing { end, pos, .. } => {
                    while *pos < *end {
                        match Pin::new(&mut this.stream)
                            .poll_write(cx, &this.encrypt_buf[*pos..*end])
                        {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                            }
                            Poll::Ready(Ok(n)) => *pos += n,
                        }
                    }
                    this.write_state = WriteState::Idle;
                }
                WriteState::Idle => return Pin::new(&mut this.stream).poll_flush(cx),
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
```

- [ ] **Step 4: 加 `into_byte_stream` 到 NoiseStream**

在 `src/tunnel/noise.rs` 的 `impl NoiseStream` 內加入（放在 `into_inner` 旁）：

```rust
    /// 消費此 NoiseStream，轉成位元組流形態供 yamux 使用。
    /// 握手後的 transport 狀態與 nonce 計數延續。
    pub fn into_byte_stream(self) -> crate::tunnel::noise_stream::NoiseByteStream {
        crate::tunnel::noise_stream::NoiseByteStream::new(self.stream, self.transport)
    }
```

- [ ] **Step 5: 跑測試確認通過**

Run: `cargo test --lib noise_stream`
Expected: `roundtrip_small`、`roundtrip_spanning_chunk_boundary`、`eof_propagates` 三項 PASS。

- [ ] **Step 6: clippy**

Run: `cargo clippy --all-targets`
Expected: 無 error。

- [ ] **Step 7: Commit**

```bash
git add src/tunnel/noise_stream.rs src/tunnel/mod.rs src/tunnel/noise.rs
git commit -m "feat: NoiseByteStream — AsyncRead/AsyncWrite over Noise transport"
```

---

## Phase 2 — Wire 協定 codec

> Spec §5。把 `protocol.rs` 從訊息式改成「Hello + stream preamble + UDP datagram」三組 codec。先「新增」、舊型別留到 Task 14 一起刪。

### Task 3: Hello / HelloAck codec

**Files:**
- Modify: `src/tunnel/protocol.rs`

- [ ] **Step 1: 寫失敗測試**

在 `src/tunnel/protocol.rs` 的 `#[cfg(test)] mod tests` 內加入：

```rust
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
```

- [ ] **Step 2: 跑測試確認失敗**

Run: `cargo test --lib protocol::tests::roundtrip_hello`
Expected: 編譯失敗 —— `Hello`、`HelloAck` 未定義。

- [ ] **Step 3: 實作**

在 `src/tunnel/protocol.rs` 加入（檔案上方，`MessageType` 之後）。`PROTO_VERSION` 設為 1：

```rust
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
```

- [ ] **Step 4: 跑測試確認通過**

Run: `cargo test --lib protocol`
Expected: 新增三項 PASS（舊測試仍 PASS）。

- [ ] **Step 5: Commit**

```bash
git add src/tunnel/protocol.rs
git commit -m "feat: Hello/HelloAck codec for tunnel session handshake"
```

### Task 4: StreamOpen / StreamReply codec

**Files:**
- Modify: `src/tunnel/protocol.rs`

- [ ] **Step 1: 寫失敗測試**

在 `mod tests` 內加入：

```rust
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
        assert!(matches!(StreamOpen::decode(&[0x01, 0x00]), Err(_)));
    }

    #[test]
    fn roundtrip_stream_reply() {
        let ok = StreamReply { status: 0, message: "10.0.0.1:5555".into() };
        let (d, n) = StreamReply::decode(&ok.encode()).unwrap();
        assert_eq!(n, ok.encode().len());
        assert_eq!(d.status, 0);
        assert_eq!(d.message, "10.0.0.1:5555");
    }
```

- [ ] **Step 2: 跑測試確認失敗**

Run: `cargo test --lib protocol::tests::roundtrip_stream_open_tcp`
Expected: 編譯失敗 —— `StreamOpen`、`StreamReply` 未定義。

- [ ] **Step 3: 實作**

`decode` 回傳 `(訊息, 已消費位元組數)` —— 因為 preamble 是 yamux stream 開頭的位元組，呼叫端要知道 payload 從哪裡開始。在 `src/tunnel/protocol.rs` 加入：

```rust
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
    /// 0 = ok；非 0 = 錯誤碼（對映 SOCKS5 reply code，見 reply_code_to_status）。
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
```

> 註：preamble 走「邊讀邊嘗試 decode」—— 呼叫端從 yamux stream 逐次 read 累積到 buffer，反覆呼叫 `decode` 直到成功（成功才知道消費了幾個 byte、payload 從哪開始）。此模式在 Task 12/13 使用。

- [ ] **Step 4: 跑測試確認通過**

Run: `cargo test --lib protocol`
Expected: 新增四項 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/tunnel/protocol.rs
git commit -m "feat: StreamOpen/StreamReply preamble codec"
```

### Task 5: UDP datagram codec

**Files:**
- Modify: `src/tunnel/protocol.rs`

- [ ] **Step 1: 寫失敗測試**

先檢視 `src/protocol/addr.rs` 的 `TargetAddr`，確認其 `parse`/`write`（或等價）方法名稱。測試（以 `TargetAddr` 實際 API 為準調整）：

```rust
    #[test]
    fn roundtrip_udp_datagram() {
        use crate::protocol::addr::TargetAddr;
        let dat = UdpDatagram {
            addr: TargetAddr::from(("1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap(), 53)),
            payload: vec![0xAB; 100],
        };
        let bytes = dat.encode();
        let (decoded, consumed) = UdpDatagram::decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.payload, vec![0xAB; 100]);
    }

    #[test]
    fn udp_datagram_partial_returns_none() {
        // 只給半截 → decode 回 Ok(None) 表示「需要更多資料」
        assert!(matches!(UdpDatagram::decode(&[0x00]), Ok(None)));
    }
```

> `decode` 對 UDP 用 `Result<Option<(UdpDatagram, usize)>>`：`Ok(None)` = 資料不足、`Ok(Some)` = 解出一則、`Err` = 格式錯誤。因為 stream 上 datagram 連續到達，呼叫端要能區分「還沒到齊」與「壞掉」。對應 Step 1 的測試簽章請改成 `Ok(None)` 判定。

- [ ] **Step 2: 跑測試確認失敗**

Run: `cargo test --lib protocol::tests::roundtrip_udp_datagram`
Expected: 編譯失敗 —— `UdpDatagram` 未定義。

- [ ] **Step 3: 實作**

在 `src/tunnel/protocol.rs` 加入。addr 編碼**重用 `src/protocol/socks5/udp.rs` 既有的 SOCKS5 UDP addr 格式**（atyp + addr + port）—— 實作前讀該檔，沿用同一套 `TargetAddr` 序列化函式以避免重複：

```rust
use crate::protocol::addr::TargetAddr;

/// UDP stream 上的單則 datagram：`[len:u16][atyp][addr][port:u16][payload]`。
/// `len` 涵蓋其後全部位元組。
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    pub addr: TargetAddr,
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    pub fn encode(&self) -> Vec<u8> {
        // addr_bytes：沿用 socks5/udp.rs 的 TargetAddr 序列化（atyp+addr+port）。
        let addr_bytes = encode_target_addr(&self.addr);
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
        let (addr, addr_len) = decode_target_addr(body)?;
        let payload = body[addr_len..].to_vec();
        Ok(Some((UdpDatagram { addr, payload }, 2 + body_len)))
    }
}
```

`encode_target_addr` / `decode_target_addr`：實作時若 `src/protocol/socks5/udp.rs` 已有等價函式則直接 `pub use`／呼叫之；若它是私有的，把序列化邏輯抽成 `src/protocol/addr.rs` 的 `pub fn`（atyp 1=IPv4/4=IPv6/3=domain），兩處共用。**不要複製貼上。**

- [ ] **Step 4: 跑測試確認通過**

Run: `cargo test --lib protocol`
Expected: 新增兩項 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/tunnel/protocol.rs src/protocol/
git commit -m "feat: UDP datagram codec for UDP-over-tunnel"
```

---

## Phase 3 — Session 層

### Task 6: 指數退避 helper

**Files:**
- Create: `src/tunnel/backoff.rs`
- Modify: `src/tunnel/mod.rs`（加 `pub mod backoff;`）

> Spec §8。

- [ ] **Step 1: 寫失敗測試**

建立 `src/tunnel/backoff.rs`，先放測試：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn grows_exponentially_then_caps() {
        let mut b = Backoff::new(Duration::from_secs(5), Duration::from_secs(60));
        let d0 = b.next_delay();
        let d1 = b.next_delay();
        let d2 = b.next_delay();
        // 基數 5s，倍率 1.5：~5、~7.5、~11.25（含 ±20% jitter）
        assert!(d0 >= Duration::from_secs(4) && d0 <= Duration::from_secs(6));
        assert!(d1 > d0);
        assert!(d2 > d1);
        // 連叫多次必定封頂在 60s 上下
        for _ in 0..20 {
            let d = b.next_delay();
            assert!(d <= Duration::from_secs(72)); // 60s + 20% jitter
        }
    }

    #[test]
    fn reset_returns_to_base() {
        let mut b = Backoff::new(Duration::from_secs(5), Duration::from_secs(60));
        for _ in 0..10 { b.next_delay(); }
        b.reset();
        let d = b.next_delay();
        assert!(d <= Duration::from_secs(6));
    }
}
```

- [ ] **Step 2: 跑測試確認失敗**

Run: `cargo test --lib backoff`
Expected: 編譯失敗 —— `Backoff` 未定義。

- [ ] **Step 3: 實作**

```rust
//! 指數退避 + jitter，供 session 重連使用。

use std::time::Duration;

const MULTIPLIER: f64 = 1.5;
const JITTER: f64 = 0.2;

pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self { base, max, attempt: 0 }
    }

    /// 回傳下一次重連前應等待的時間，並遞增 attempt 計數。
    pub fn next_delay(&mut self) -> Duration {
        let raw = self.base.as_secs_f64() * MULTIPLIER.powi(self.attempt as i32);
        let capped = raw.min(self.max.as_secs_f64());
        self.attempt = self.attempt.saturating_add(1);
        // ±20% jitter：用奈秒級時間當廉價亂源，不引入 rand 依賴。
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let frac = (now % 1000) as f64 / 1000.0; // 0.0..1.0
        let jitter_factor = 1.0 - JITTER + frac * (2.0 * JITTER); // 0.8..1.2
        Duration::from_secs_f64(capped * jitter_factor)
    }

    /// session 穩定後呼叫，把 attempt 歸零。
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}
```

- [ ] **Step 4: 跑測試確認通過**

Run: `cargo test --lib backoff`
Expected: 兩項 PASS。

- [ ] **Step 5: 在 mod.rs 宣告並 Commit**

```bash
git add src/tunnel/backoff.rs src/tunnel/mod.rs
git commit -m "feat: exponential backoff helper for session reconnect"
```

### Task 7: 泛型雙向 relay

**Files:**
- Modify: `src/relay/tcp.rs`

> 把 relay 從「`TcpStream` 專用」泛化成「任兩個 `AsyncRead+AsyncWrite`」，讓 SOCKS `TcpStream` 與 yamux `Stream` 能直接對接。`relay_tunneled` 將被取代。

- [ ] **Step 1: 寫失敗測試**

在 `src/relay/tcp.rs` 的測試模組（若無則新建 `#[cfg(test)] mod tests`）加入：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn relay_copies_both_directions() {
        // a_left ↔ a_right 當「一端」，b_left ↔ b_right 當「另一端」
        let (a_left, mut a_outer) = duplex(1024);
        let (b_left, mut b_outer) = duplex(1024);

        let relay = tokio::spawn(async move {
            let mut a = a_left;
            let mut b = b_left;
            relay_bidirectional(&mut a, &mut b, None, None).await
        });

        a_outer.write_all(b"ping").await.unwrap();
        a_outer.shutdown().await.unwrap();
        let mut got = Vec::new();
        b_outer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");

        b_outer.shutdown().await.unwrap();
        let (tx, _rx) = relay.await.unwrap().unwrap();
        assert_eq!(tx, 4);
    }
}
```

- [ ] **Step 2: 跑測試確認失敗**

Run: `cargo test --lib relay::tcp::tests::relay_copies_both_directions`
Expected: 編譯失敗 —— `relay_bidirectional` 未定義。

- [ ] **Step 3: 實作**

在 `src/relay/tcp.rs` 加入泛型版本。它與現有 `relay_tcp_live` 同結構（`join!` 雙向、shared atomic 計數），但泛型化參數。保留現有 `relay_tcp` / `relay_tcp_live`（standalone 直連路徑仍用），`relay_tunneled` 不在此刪（Task 14 刪）。

```rust
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

/// 在任兩個雙向串流間 relay，附 live byte 計數。
/// 回傳 (a→b bytes, b→a bytes)。
///
/// 用 `join!`（非 `try_join!`）讓兩個方向都跑完 —— `try_join!` 會在
/// 一邊出錯時中途取消另一邊，可能留下半寫的 frame。
pub async fn relay_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    live_ab: Option<&AtomicU64>,
    live_ba: Option<&AtomicU64>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let ab_total = Arc::new(AtomicU64::new(0));
    let ba_total = Arc::new(AtomicU64::new(0));
    let ab_c = ab_total.clone();
    let ba_c = ba_total.clone();

    let a_to_b = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = ar.read(&mut buf).await?;
            if n == 0 {
                bw.shutdown().await?;
                break;
            }
            bw.write_all(&buf[..n]).await?;
            ab_c.fetch_add(n as u64, Ordering::Relaxed);
            if let Some(c) = live_ab { c.fetch_add(n as u64, Ordering::Relaxed); }
        }
        Ok::<(), io::Error>(())
    };
    let b_to_a = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = br.read(&mut buf).await?;
            if n == 0 {
                aw.shutdown().await?;
                break;
            }
            aw.write_all(&buf[..n]).await?;
            ba_c.fetch_add(n as u64, Ordering::Relaxed);
            if let Some(c) = live_ba { c.fetch_add(n as u64, Ordering::Relaxed); }
        }
        Ok::<(), io::Error>(())
    };

    let _ = tokio::join!(a_to_b, b_to_a);
    Ok((ab_total.load(Ordering::Relaxed), ba_total.load(Ordering::Relaxed)))
}
```

- [ ] **Step 4: 跑測試確認通過**

Run: `cargo test --lib relay`
Expected: 新測試 PASS，現有 relay 測試仍 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/relay/tcp.rs
git commit -m "feat: generic bidirectional relay over AsyncRead+AsyncWrite"
```

### Task 8: yamux 設定與 Session 型別

**Files:**
- Create: `src/tunnel/session.rs`
- Modify: `src/tunnel/mod.rs`（加 `pub mod session;`）

> 此 Task 建立共用骨架：yamux `Config` 建構、`Session` newtype。client/server 的 driver 在 Task 9 與 Task 11/13 接上。

- [ ] **Step 1: 寫失敗測試**

建立 `src/tunnel/session.rs`：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_respects_window_floor() {
        // recv window 必須 >= 256 KiB * max_num_streams
        let cfg = yamux_config(256, 64);
        // 不會 panic 即代表設定合法；此處僅確保函式可呼叫。
        let _ = cfg;
    }
}
```

- [ ] **Step 2: 跑測試確認失敗**

Run: `cargo test --lib session`
Expected: 編譯失敗 —— `yamux_config` 未定義。

- [ ] **Step 3: 實作 yamux 設定建構**

```rust
//! yamux session 的建立、驅動與（client 端）連線池。

use yamux::{Config, Mode};

/// 依 spec §6 建構 yamux Config。
/// `max_streams` = 每 session stream 上限；`recv_window_mb` = 總接收窗（MiB）。
/// yamux 要求 recv window >= 256 KiB * max_streams —— 呼叫端設定須滿足，
/// 此函式會 clamp 到下限以保證合法。
pub fn yamux_config(max_streams: usize, recv_window_mb: usize) -> Config {
    let mut cfg = Config::default();
    cfg.set_max_num_streams(max_streams);
    let floor = max_streams * 256 * 1024;
    let requested = recv_window_mb * 1024 * 1024;
    cfg.set_max_connection_receive_window(Some(requested.max(floor)));
    cfg
}

pub const SERVER_MODE: Mode = Mode::Server;
pub const CLIENT_MODE: Mode = Mode::Client;
```

> Task 1 Step 3 若發現 `Config` API 名稱不同，此處同步調整。

- [ ] **Step 4: 跑測試 + commit**

Run: `cargo test --lib session` → PASS
Run: `cargo clippy --all-targets` → 無 error

```bash
git add src/tunnel/session.rs src/tunnel/mod.rs
git commit -m "feat: yamux Config builder for tunnel sessions"
```

### Task 9: Client 端 SessionPool

**Files:**
- Modify: `src/tunnel/session.rs`
- Modify: `src/config.rs`（讀 `TunnelConfig` 既有欄位；新欄位在 Task 17 加）

> Client 端：建立 N 條 session，每條 = TCP → Noise 握手 → `Hello`/`HelloAck` → `NoiseByteStream` → yamux `Mode::Client`。driver loop 用 `poll_next_inbound` 接 server 開的 stream，每接到一條就 spawn `handle_inbound_stream`（Task 13 實作；此 Task 先放一個會 reset stream 的 stub）。斷線用 `Backoff` 重連。

實作要點（依此寫，測試在 Task 18/20 的整合測試覆蓋）：

- `pub struct SessionPool { server_addr, client_id, psk, sessions, max_streams, recv_window_mb }`。
- `SessionPool::start(&self, cancel: CancellationToken)`：`for i in 0..sessions { spawn(session_worker(i, ...)) }`。
- `async fn session_worker(index, ...)`：`loop { match run_session(index,...).await { Ok(())=>return（cancelled）, Err(_)=> { sleep(backoff.next_delay()) } } }`；session 穩定存活 >30s 後 `backoff.reset()`（用 `tokio::time::Instant` 記錄 session 建立時間，run_session 回傳前判斷）。
- `async fn run_session(index,...)`：
  1. `TcpStream::connect` + `set_nodelay(true)`。
  2. `NoiseStream::connect(tcp, &psk)`。
  3. 送 `Hello { proto_version: PROTO_VERSION, session_index: index, client_id }`（用 `NoiseStream::send`）。
  4. `recv` 一則，`HelloAck::decode`；`accepted == false` → 回 `Err`（log reason）。
  5. `noise.into_byte_stream()` → `.compat()`（`tokio_util::compat::TokioAsyncReadCompatExt`）。
  6. `yamux::Connection::new(compat_stream, yamux_config(max_streams, recv_window_mb), Mode::Client)`。
  7. driver loop：`futures::future::poll_fn(|cx| conn.poll_next_inbound(cx))`：
     - `Some(Ok(stream))` → `tokio::spawn(handle_inbound_stream(stream, cancel.clone()))`。
     - `Some(Err(e))` → 回 `Err(e)`（觸發重連）。
     - `None` → 回 `Ok(())`（連線正常關閉）。
     - 同時 `select!` 監看 `cancel.cancelled()` → `conn.poll_close` 後回 `Ok(())`。

- [ ] **Step 1: 實作 SessionPool（含上述邏輯）**

> 因依賴 yamux 即時 API 與 Task 13 的 `handle_inbound_stream`，先把 `handle_inbound_stream` 寫成 stub：

```rust
/// Task 13 會以「讀 preamble → dial → relay」取代此 stub。
async fn handle_inbound_stream(
    stream: yamux::Stream,
    _cancel: tokio_util::sync::CancellationToken,
) {
    // stub：尚未實作 → 直接丟棄 stream（等同 reset）。
    drop(stream);
}
```

- [ ] **Step 2: 編譯檢查**

Run: `cargo build`
Expected: 編譯成功（`SessionPool` 尚未被 `client/mod.rs` 呼叫 → 可能有 dead_code 警告，可暫接受）。

- [ ] **Step 3: Commit**

```bash
git add src/tunnel/session.rs
git commit -m "feat: client-side SessionPool with yamux + reconnect backoff"
```

---

## Phase 4 — Server / Router 改寫

> 此階段把 server 與 client 的進入點切到新路徑。為保持可編譯，先改 `Router`（Task 10）→ server driver（Task 11）→ relay 接線（Task 12/13）→ 最後 Task 14 統一切換進入點並刪舊碼。Task 10–13 期間舊碼仍在、可能出現 dead_code 警告，屬正常。

### Task 10: Router 改寫

**Files:**
- Modify: `src/tunnel/router.rs`

> Spec §4.2、§10。`Router` 不再持有待命 `NoiseStream` 池，改持有每個 client 的 N 個「yamux 開 stream 通道」。每條 server 端 yamux session 的 driver task（Task 11）持有 `Connection`，並透過 mpsc 收「開 outbound stream」請求。`Router` 為每個 client 存一組 `Vec<SessionHandle>`，`open_stream` 在其中輪流挑一條送請求。

關鍵型別：

```rust
use tokio::sync::{mpsc, oneshot};

/// 對單一 yamux session driver 的開 stream 控制把手。
#[derive(Clone)]
pub struct SessionHandle {
    /// 送「開 outbound stream」請求給 driver；driver 開好後從 oneshot 回傳。
    pub open_tx: mpsc::Sender<oneshot::Sender<std::io::Result<yamux::Stream>>>,
}
```

要寫的測試（單元層級可測 round-robin 與註冊/反註冊）：

```rust
    #[tokio::test]
    async fn open_stream_round_robins_sessions() {
        let router = Router::new();
        // 用假的 SessionHandle：open_tx 接到請求就回一個固定 marker。
        // 註冊 client「c1」配 3 條 session，連叫 open_stream 6 次，
        // 斷言 6 次請求平均落在 3 條 session 上（各 2 次）。
        // （以實際 SessionHandle 測試實作；此處描述行為契約。）
    }
```

- [ ] **Step 1: 寫 round-robin 與註冊測試**（依上述契約寫出可執行測試 —— 用 `mpsc::channel` 造假 session，driver 端 task 收到請求即計數）
- [ ] **Step 2: 跑測試確認失敗** — `cargo test --lib router`
- [ ] **Step 3: 改寫 `Router`**：
  - `RegisteredClient` 去掉 `data_conns`/`data_conn_tx`，改 `sessions: Vec<SessionHandle>`、`next_session: AtomicUsize`（round-robin 游標）。
  - 刪 `PendingDataConn`、`push_data_conn`、`get_data_conn`、`return_data_conn`。
  - 新增 `register_session(client_id, SessionHandle)`（同一 client 多次呼叫累積 session；client 第一條 session 到達時建立 `RegisteredClient`）。
  - 新增 `async fn open_stream(&self, client_id: Option<&str>) -> Option<yamux::Stream>`：挑 client（指定或任一）→ 取 `next_session` 游標 → 送 oneshot 請求 → await 回傳。某條 session handle 已關閉就跳下一條。
  - 保留 `record_traffic`、`client_snapshots`、`client_ids`、`has_clients`、cumulative counters。
  - `unregister`：改為「移除某條 session」與「client 全部 session 都掉了才移除 client」。
- [ ] **Step 4: 跑測試確認通過** — `cargo test --lib router`
- [ ] **Step 5: Commit** — `git commit -m "refactor: Router holds yamux session handles, open_stream API"`

### Task 11: Server 端 session driver + tunnel_listener 改寫

**Files:**
- Modify: `src/server/tunnel_listener.rs`
- Modify: `src/tunnel/session.rs`（加 server 端 driver）

> server 接受 TCP → Noise 握手 → 收 `Hello` → 回 `HelloAck` → `NoiseByteStream` → yamux `Mode::Server` → spawn server driver task → 用 `Hello.client_id` 把 `SessionHandle` 註冊進 `Router`。

server driver（`src/tunnel/session.rs` 新增 `async fn run_server_session`）：擁有 `Connection<Mode::Server>` 與一個 `mpsc::Receiver<oneshot::Sender<Result<Stream>>>`。loop 中 `select!`：
- 收到開 stream 請求 → `poll_fn(|cx| conn.poll_new_outbound(cx))` → 把結果送回 oneshot。
- **同時必須** `poll_fn(|cx| conn.poll_next_inbound(cx))` 持續驅動連線：`Some(Ok(s))` → 非預期的 inbound stream，drop 掉；`Some(Err(e))` / `None` → session 結束，回收。
- `cancel.cancelled()` → `conn.poll_close`。

實作步驟：
- [ ] **Step 1: 在 `session.rs` 寫 `run_server_session`**（依上述邏輯；建立時回傳 `SessionHandle { open_tx }`）
- [ ] **Step 2: 改寫 `tunnel_listener.rs` 的 accept 處理**：Noise handshake 後改讀 `Hello`（取代現有 `TunnelMessage::decode` 分流）；版本不符回 `HelloAck{accepted:false}` 並關閉；通過則回 `HelloAck{accepted:true}`、轉 `NoiseByteStream`、spawn `run_server_session`、`router.register_session(client_id, handle)`。刪掉 `handle_control_channel` / `handle_data_channel`。
- [ ] **Step 3: 編譯檢查** — `cargo build`（此時 `handle_connect_via_tunnel` 仍呼叫舊 `get_data_conn` → 會編譯失敗；若如此，先在 Task 12 完成後再整體編譯。可暫時 `#[allow(dead_code)]` 或註記，Task 12 緊接著做）
- [ ] **Step 4: Commit** — `git commit -m "refactor: server-side yamux session driver + Hello handshake"`

### Task 12: handle_connect_via_tunnel 改寫（server 端 TCP flow）

**Files:**
- Modify: `src/server/connection.rs`

> 原 `handle_connect_via_tunnel` 用 `get_data_conn` 取 `NoiseStream` → 送 `ProxyRequest` → 收 `ProxyReply` → `relay_tunneled`。改成：

1. `let stream = router.open_stream(client_id).await` → 無可用 client/session 回 SOCKS5 `GeneralFailure`。
2. `stream` 是 `yamux::Stream`（`futures::io`）→ 用 `tokio_util::compat::FuturesAsyncReadCompatExt` 的 `.compat()` 轉回 tokio `AsyncRead+AsyncWrite`。
3. 寫 `StreamOpen::Tcp { target }.encode()` 到 stream。
4. 讀回 `StreamReply`：逐次 `read` 累積 buffer，反覆 `StreamReply::decode` 直到 `Ok`。`status != 0` → 對映成 SOCKS5 reply code 回給 SOCKS client、關閉。
5. `status == 0` → 用 `StreamReply::message` 當 bind addr 寫 SOCKS5 success reply。
6. `relay_bidirectional(&mut socks_tcp, &mut compat_stream, live_tx, live_rx)`。

- [ ] **Step 1: 改寫函式**（依上述 6 步；錯誤碼對映沿用 `ServerError::to_reply_code` 的反向表 —— 在 `protocol.rs` 加 `pub fn status_to_reply_code(u8) -> ReplyCode` 與 `reply_code_to_status`）
- [ ] **Step 2: 編譯檢查** — `cargo build`（Task 11 + 12 完成後 server 端應可編譯）
- [ ] **Step 3: Commit** — `git commit -m "refactor: server SOCKS handler opens yamux stream per proxy flow"`

### Task 13: Client worker 改寫（接 inbound stream → dial → relay）

**Files:**
- Modify: `src/tunnel/session.rs`（把 Task 9 的 `handle_inbound_stream` stub 換成真實作）
- Modify/Delete: `src/client/worker.rs`

> `handle_inbound_stream(stream, cancel)`：
1. `stream.compat()` 轉 tokio trait。
2. 讀 preamble：累積 buffer，反覆 `StreamOpen::decode` 直到 `Ok((open, consumed))`。`consumed` 之後的 byte 是 payload 起點 —— 若 `read` 多讀了，要把超讀部分保留（用一個小 prepend buffer，或精準逐 byte 讀 preamble 避免超讀；建議逐 byte 讀以免處理 leftover）。
3. `StreamOpen::Tcp { target }` → `TcpStream::connect(&target)`：
   - 成功 → 寫 `StreamReply { status: 0, message: bind_addr }` → `relay_bidirectional(&mut stream, &mut target)`。
   - 失敗 → 寫 `StreamReply { status: <err code>, message: e.to_string() }` → 關閉 stream。
4. `StreamOpen::Udp` → 交給 Task 16 的 UDP handler。

- [ ] **Step 1: 實作 `handle_inbound_stream` 的 TCP 路徑**（UDP 路徑 Task 16 補；此 Task 先讓 `StreamOpen::Udp` 回 `StreamReply{status:非0}` 表示尚未支援）
- [ ] **Step 2: 把 `client/worker.rs` 的 `handle_data_connection` 邏輯併入或刪除**（其 dial+relay 職責已移到 `handle_inbound_stream`）
- [ ] **Step 3: 編譯檢查** — `cargo build`
- [ ] **Step 4: Commit** — `git commit -m "refactor: client handles inbound yamux streams (TCP dial + relay)"`

### Task 14: 切換進入點 + 刪除舊碼

**Files:**
- Modify: `src/client/mod.rs`、`src/server/mod.rs`
- Delete: `src/tunnel/pool.rs`
- Modify: `src/tunnel/protocol.rs`、`src/tunnel/noise.rs`、`src/tunnel/mod.rs`

- [ ] **Step 1: client 進入點切換** — `src/client/mod.rs`：移除 control channel + `ConnectionPool` 啟動，改成建立並 `SessionPool::start(...)`。heartbeat 改靠 yamux keepalive（yamux Config 預設啟用；如需調整在此設定）。
- [ ] **Step 2: server 進入點** — 確認 `src/server/mod.rs` 對 `run_tunnel_listener` 的呼叫不需改（介面不變）；若 `Router` 建構/傳遞有變則同步。
- [ ] **Step 3: 刪除 `src/tunnel/pool.rs`**，並從 `src/tunnel/mod.rs` 移除 `pub mod pool;`。
- [ ] **Step 4: 刪除 `protocol.rs` 舊型別** — `MessageType`、`TunnelMessage` 及其全部 `encode`/`decode`/舊測試（`Register`/`Heartbeat`/`RequestProxy`/`DataReady`/`ProxyRequest`/`ProxyReply`/`RelayData`/`RelayEnd`/`Disconnect`）。保留 `decode_err`、`Hello`/`StreamOpen`/`StreamReply`/`UdpDatagram`。
- [ ] **Step 5: 刪除 `noise.rs` 死碼** — `split`、`reunite`、`NoiseSender`、`NoiseReceiver`、`send_frame_half`、`recv_frame_half`（`NoiseStream::send`/`recv` 保留給 Hello 交握；`into_byte_stream` 保留）。
- [ ] **Step 6: 刪除 `relay/tcp.rs` 的 `relay_tunneled`**。
- [ ] **Step 7: 全量編譯 + 測試 + clippy**

Run: `cargo build && cargo test && cargo clippy --all-targets`
Expected: 全綠，無 dead_code 警告。修掉所有殘留 unused import / 未用函式。

- [ ] **Step 8: Commit** — `git commit -m "refactor: switch tunnel to yamux multiplexing, remove pool model"`

---

## Phase 5 — UDP over tunnel

> Spec §5.3。SOCKS5 UDP ASSOCIATE 改走 tunnel：server 收到 UDP 封包 → 經 yamux UDP stream 轉給 client → client 從自己的網路出去。一個 UDP 關聯 = 一條 UDP stream。

### Task 15: Server 端 UDP ASSOCIATE 走 tunnel

**Files:**
- Modify: `src/relay/udp.rs`、`src/server/connection.rs`

> 現行 `handle_udp_associate` 直接在 server bind UDP socket relay。改成 tunnel 模式時：
1. server 仍 bind 一個 UDP socket 給 SOCKS client 發包（SOCKS5 UDP 關聯需要）。
2. `router.open_stream(client_id)` 開一條 yamux stream，寫 `StreamOpen::Udp` preamble，讀 `StreamReply`。
3. 收到 SOCKS client 的 UDP 封包 → 解 SOCKS5 UDP header 取 dst → 編成 `UdpDatagram` 寫進 yamux stream。
4. 從 yamux stream 讀 `UdpDatagram` → 包回 SOCKS5 UDP header → 發回 SOCKS client。
5. standalone（非 tunnel）模式維持原直連行為。

- [ ] **Step 1: 在 `relay/udp.rs` 加 `relay_udp_tunneled`**（server UDP socket ↔ yamux UDP stream，雙向 `UdpDatagram` 編解碼；用 `HashMap` 追蹤 SOCKS client addr）
- [ ] **Step 2: `handle_udp_associate` 依模式分派** —— tunnel 模式走新路徑、standalone 走舊路徑
- [ ] **Step 3: 編譯 + commit** — `git commit -m "feat: route SOCKS5 UDP ASSOCIATE through tunnel"`

### Task 16: Client 端 UDP stream handler

**Files:**
- Modify: `src/tunnel/session.rs`

> `handle_inbound_stream` 的 `StreamOpen::Udp` 路徑：
1. 寫 `StreamReply { status: 0, .. }`。
2. `UdpSocket::bind("0.0.0.0:0")`。
3. 雙向：從 yamux stream 讀 `UdpDatagram` → `socket.send_to(payload, addr)`；`socket.recv_from` → 編 `UdpDatagram`（addr = 來源）→ 寫回 yamux stream。
4. idle timeout 關閉（沿用 config 的 udp idle timeout）。

- [ ] **Step 1: 實作 UDP 路徑**（取代 Task 13 Step 1 的「尚未支援」佔位）
- [ ] **Step 2: 編譯 + commit** — `git commit -m "feat: client-side UDP-over-tunnel stream handler"`

---

## Phase 6 — 設定與整合測試

### Task 17: 設定變更

**Files:**
- Modify: `src/config.rs`、`src/main.rs`、`README.md`（設定範例）

> Spec §9。

- [ ] **Step 1: 寫失敗測試** — 在 `config.rs` 測試模組加：TOML 含 `tunnel.secret` / `tunnel.tunnel_sessions` 時，`apply_to` 後 `Config` 對應欄位有值（涵蓋目前 secret 死欄位 bug）。
- [ ] **Step 2: 跑測試確認失敗** — `cargo test --lib config`
- [ ] **Step 3: 實作** —
  - `TunnelConfig`：移除 `pool_size`，加 `tunnel_sessions: u16`（預設 8）、`max_streams_per_session: usize`（預設 256）、`recv_window_mb: usize`（預設 64）、`reconnect_max: u64`（預設 60）。
  - `FileTunnelConfig`：對應新增；`apply_to()` **真的讀 `tunnel.secret`**（修 bug）與所有新欄位。
  - `main.rs`：CLI 參數同步（`--pool-size` → `--tunnel-sessions`）。
- [ ] **Step 4: 跑測試確認通過** + 更新 `README.md` 設定範例
- [ ] **Step 5: Commit** — `git commit -m "feat: tunnel session config; fix secret never read from TOML"`

### Task 18: 整合測試 — 端到端 TCP

**Files:**
- Create: `tests/tunnel_e2e.rs`

- [ ] **Step 1: 寫測試** — 行程內：起一個 echo TCP server、起 `run_tunnel_listener`、起 `SessionPool`（client）、起 SOCKS server；用 SOCKS5 client 連上、`CONNECT` 到 echo server、送一段資料、斷言原樣收回。

```rust
// tests/tunnel_e2e.rs 骨架
#[tokio::test]
async fn socks5_connect_through_tunnel_echoes() {
    // 1. echo server: 收到什麼回什麼
    // 2. tunnel server (run_tunnel_listener) on 127.0.0.1:0
    // 3. SOCKS server 綁定、Router 共用
    // 4. client SessionPool 連上 tunnel server
    // 5. 等 router.has_clients() 為 true
    // 6. 用裸 socket 走 SOCKS5 握手 + CONNECT echo server
    // 7. 寫 b"roundtrip", 斷言讀回 b"roundtrip"
}
```

- [ ] **Step 2: 跑測試** — `cargo test --test tunnel_e2e`，PASS
- [ ] **Step 3: Commit** — `git commit -m "test: end-to-end SOCKS5 CONNECT through yamux tunnel"`

### Task 19: 整合測試 — stream 隔離 / flow control

**Files:**
- Modify: `tests/tunnel_e2e.rs`

> 驗證整個 feature 的核心：同一 session 上一條慢 stream 不得拖垮另一條。

- [ ] **Step 1: 寫測試** — 同一 client、同一 session 上開兩條 flow：flow A 連到一個「收了資料故意不讀」的 server（或測試端故意慢速 `read`）；flow B 連到 echo server。斷言 flow B 在 flow A 卡住期間仍能於合理時限（如 2s）內完成數十 KB 的 echo。用 `tokio::time::timeout` 包住 flow B，逾時即測試失敗。
- [ ] **Step 2: 跑測試** — `cargo test --test tunnel_e2e isolation`，PASS
- [ ] **Step 3: Commit** — `git commit -m "test: verify slow stream does not block co-tenant stream"`

### Task 20: 整合測試 — session 重連 + UDP e2e

**Files:**
- Modify: `tests/tunnel_e2e.rs`

- [ ] **Step 1: 寫 session 重連測試** — `tunnel_sessions = 2`，建立流量後砍掉 tunnel server 再重起（或砍掉一條 TCP 連線），斷言：受影響 flow 報錯、client 退避後重連、重連後新 `CONNECT` 成功。
- [ ] **Step 2: 寫 UDP e2e 測試** — 起 UDP echo server，SOCKS5 UDP ASSOCIATE 過 tunnel，送 datagram 斷言原樣收回。
- [ ] **Step 3: 跑全部測試** — `cargo test`，全綠
- [ ] **Step 4: clippy + commit** — `cargo clippy --all-targets` 無 error；`git commit -m "test: session reconnect and UDP-over-tunnel end-to-end"`

---

## 完成檢查

- [ ] `cargo test` 全綠（單元 + `tests/tunnel_e2e.rs`）。
- [ ] `cargo clippy --all-targets` 無 error、無 dead_code 警告。
- [ ] `src/tunnel/pool.rs` 已刪除；`protocol.rs` 只剩四組新 codec。
- [ ] 手動冒煙：`cargo run -- server` + `cargo run -- client`，用 `curl --socks5` 過 tunnel 取一個網頁成功。
- [ ] `tasks/todo.md` 補一段 review：實際 shipped 內容、yamux 設定實測值、blast radius 觀察、待辦（如 Noise NN→XX 升級另案）。
- [ ] 開 PR：標題 `feat: yamux stream multiplexing for tunnel`，內文連結本計畫與 spec。

## 自我檢查記錄（writing-plans self-review）

- **Spec 覆蓋**：§4 元件 → Task 2/8/9/11；§5 wire 協定 → Task 3/4/5；§6 yamux 設定 → Task 8；§7 失敗模型 → Task 20；§8 退避 → Task 6/9；§9 設定 → Task 17;§10 刪除清單 → Task 14;§11 測試 → Task 18/19/20。皆有對應。
- **型別一致**：`NoiseByteStream`、`Hello`/`HelloAck`、`StreamOpen`/`StreamReply`、`UdpDatagram`、`Backoff`、`yamux_config`、`SessionHandle`、`SessionPool`、`relay_bidirectional`、`open_stream`、`handle_inbound_stream`、`run_server_session` —— 跨 Task 命名一致。
- **已知待實作期確認項**：yamux 0.13 確切 API 名稱（Task 1 Step 3 驗證）；`TargetAddr` 序列化函式是否可重用（Task 5 Step 3）；preamble 讀取建議逐 byte 以免超讀（Task 13 Step 1）。

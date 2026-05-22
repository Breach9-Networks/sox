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

/// 把握手後的 Noise transport 包成透明加密位元組管道。
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

//! Noise transport 的 AsyncRead/AsyncWrite 形態。
//!
//! 把已完成握手的 Noise transport 包成透明的加密位元組管道，
//! 供 yamux 在其上做多工。寫入的位元組被切成 <= 65519 bytes 的
//! Noise message（65535 ciphertext 上限扣掉 16 byte AEAD tag），
//! 每則 message 以 `[len: u16 BE][ciphertext]` 上線。
//!
//! **寫入端會合併(coalesce)**:yamux 把每個 frame 的 12-byte header 與 body
//! 分成兩次 `poll_write`。若每次 `poll_write` 都各自加密送出,一個 16 KiB
//! 資料 frame 就要 2 次 AEAD、2 次 write syscall,並在線上多 34 bytes。
//! 這裡改為先累積 plaintext,等 `poll_flush`(yamux 每輪寫完都會呼叫)或
//! 累積滿一則 Noise message 才加密送出。
//!
//! **讀取端有緩衝**:一次盡量多讀進 `rbuf`,再從中切出完整 frame,
//! 不再「每則 message 先讀 2 byte 長度、再讀 body」各一次 syscall。
//!
//! **讀取看門狗**:超過 `read_idle` 沒收到任何位元組即回 `TimedOut`。
//! OS keepalive 在「有未 ACK 資料」時不探測(由 RTO 決定,Linux 預設可達
//! ~15 分鐘),半開連線因此可能久久不被發現。session driver 每
//! `HEARTBEAT_INTERVAL` 喚醒 yamux 送 ping,健康的對端必有回程流量;
//! 沒有就代表連線已死。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use snow::TransportState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{Instant, Sleep};

const NOISE_TAG_LEN: usize = 16;
const NOISE_MAX_CIPHERTEXT: usize = 65535;
const NOISE_MAX_PLAINTEXT: usize = NOISE_MAX_CIPHERTEXT - NOISE_TAG_LEN; // 65519
const FRAME_LEN_PREFIX: usize = 2;
/// 一則完整 frame(`[len:2][ciphertext]`)的最大位元組數。
const MAX_FRAME: usize = FRAME_LEN_PREFIX + NOISE_MAX_CIPHERTEXT;

/// 讀取看門狗:lazy deadline —— 只在底層讀取 Pending 時才 poll timer,
/// timer 到期才依 `last_read` 重算,所以高流量下不會每次讀取都重設 timer。
struct ReadWatchdog {
    timeout: Duration,
    last_read: Instant,
    sleep: Pin<Box<Sleep>>,
}

impl ReadWatchdog {
    fn new(timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            timeout,
            last_read: now,
            sleep: Box::pin(tokio::time::sleep_until(now + timeout)),
        }
    }

    /// 底層讀取回 Pending 時呼叫。`Ready` 代表已閒置超過 `timeout`。
    fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if self.sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            let deadline = self.last_read + self.timeout;
            if Instant::now() >= deadline {
                return Poll::Ready(());
            }
            // 期間有讀到資料 —— 把 timer 推到新的 deadline 再 poll 一次以註冊 waker。
            self.sleep.as_mut().reset(deadline);
        }
    }
}

/// 把握手後的 Noise transport 包成透明加密位元組管道。
pub struct NoiseByteStream {
    stream: TcpStream,
    transport: TransportState,

    // ── 讀取端 ──
    /// 尚未解密的線上位元組;有效區間 `rbuf[r_start..r_end]`。
    rbuf: Vec<u8>,
    r_start: usize,
    r_end: usize,
    /// 已解密、待交給呼叫端的 plaintext;有效區間 `decrypt_buf[d_pos..d_len]`。
    decrypt_buf: Vec<u8>,
    d_pos: usize,
    d_len: usize,
    eof: bool,
    watchdog: Option<ReadWatchdog>,

    // ── 寫入端 ──
    /// 已被接受、尚未加密的 plaintext(<= NOISE_MAX_PLAINTEXT)。
    plain: Vec<u8>,
    /// 已加密的 `[len:2][ciphertext]`;待送區間 `out[out_pos..out_end]`。
    out: Vec<u8>,
    out_pos: usize,
    out_end: usize,
}

impl NoiseByteStream {
    pub fn new(stream: TcpStream, transport: TransportState) -> Self {
        Self {
            stream,
            transport,
            rbuf: vec![0u8; MAX_FRAME],
            r_start: 0,
            r_end: 0,
            decrypt_buf: vec![0u8; NOISE_MAX_CIPHERTEXT],
            d_pos: 0,
            d_len: 0,
            eof: false,
            watchdog: None,
            plain: Vec::with_capacity(NOISE_MAX_PLAINTEXT),
            out: vec![0u8; MAX_FRAME],
            out_pos: 0,
            out_end: 0,
        }
    }

    /// 啟用讀取看門狗:超過 `timeout` 沒收到任何位元組,讀取回 `TimedOut`。
    /// 呼叫端必須確保健康連線上對端會定期送資料(見模組說明)。
    pub fn with_read_idle_timeout(mut self, timeout: Duration) -> Self {
        self.watchdog = Some(ReadWatchdog::new(timeout));
        self
    }

    /// 嘗試從 `rbuf` 切出並解密一則完整 frame。`Ok(true)` = `decrypt_buf`
    /// 有新 plaintext;`Ok(false)` = 資料不足,需要再讀。
    fn try_decrypt_frame(&mut self) -> io::Result<bool> {
        loop {
            let avail = self.r_end - self.r_start;
            if avail < FRAME_LEN_PREFIX {
                return Ok(false);
            }
            let len =
                u16::from_be_bytes([self.rbuf[self.r_start], self.rbuf[self.r_start + 1]]) as usize;
            if avail < FRAME_LEN_PREFIX + len {
                return Ok(false);
            }
            let body = self.r_start + FRAME_LEN_PREFIX;
            self.r_start = body + len;
            if len == 0 {
                continue; // 空 frame:無 plaintext,直接看下一則。
            }
            let n = self
                .transport
                .read_message(&self.rbuf[body..body + len], &mut self.decrypt_buf)
                .map_err(|e| io::Error::other(format!("noise decrypt: {e}")))?;
            if n == 0 {
                continue;
            }
            self.d_pos = 0;
            self.d_len = n;
            return Ok(true);
        }
    }

    /// 把 `out` 內待送的 ciphertext 寫完。
    fn poll_drain_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out_end {
            let n = std::task::ready!(
                Pin::new(&mut self.stream).poll_write(cx, &self.out[self.out_pos..self.out_end])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        Poll::Ready(Ok(()))
    }

    /// 把累積的 plaintext 加密成一則 frame 放進 `out`。前提:`out` 已送完。
    fn seal(&mut self) -> io::Result<()> {
        debug_assert_eq!(self.out_pos, self.out_end);
        let len = self
            .transport
            .write_message(&self.plain, &mut self.out[FRAME_LEN_PREFIX..])
            .map_err(|e| io::Error::other(format!("noise encrypt: {e}")))?;
        self.out[..FRAME_LEN_PREFIX].copy_from_slice(&(len as u16).to_be_bytes());
        self.out_pos = 0;
        self.out_end = FRAME_LEN_PREFIX + len;
        self.plain.clear();
        Ok(())
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
            // 1. 有已解密的 plaintext → 交出去。
            if this.d_pos < this.d_len {
                let n = (this.d_len - this.d_pos).min(out.remaining());
                out.put_slice(&this.decrypt_buf[this.d_pos..this.d_pos + n]);
                this.d_pos += n;
                return Poll::Ready(Ok(()));
            }
            // 2. 緩衝區裡已有完整 frame → 解密後回到 1。
            if this.try_decrypt_frame()? {
                continue;
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            // 3. 需要更多線上位元組。剩餘的是不完整 frame —— 搬到開頭騰出空間
            //    (每個位元組最多被搬一次:搬完 r_start 即為 0)。
            if this.r_start > 0 {
                this.rbuf.copy_within(this.r_start..this.r_end, 0);
                this.r_end -= this.r_start;
                this.r_start = 0;
            }
            let mut tmp = ReadBuf::new(&mut this.rbuf[this.r_end..]);
            match Pin::new(&mut this.stream).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(())) => {
                    let got = tmp.filled().len();
                    if got == 0 {
                        if this.r_end > this.r_start {
                            // frame 讀到一半對端就關了。
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.r_end += got;
                    if let Some(w) = this.watchdog.as_mut() {
                        w.last_read = Instant::now();
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if let Some(w) = this.watchdog.as_mut()
                        && w.poll_expired(cx).is_ready()
                    {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "tunnel peer silent past read-idle timeout (half-open connection?)",
                        )));
                    }
                    return Poll::Pending;
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
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // 累積滿一則 message → 先把上一則送完,再把這則加密排入 `out`。
        if this.plain.len() == NOISE_MAX_PLAINTEXT {
            std::task::ready!(this.poll_drain_out(cx))?;
            this.seal()?;
        }
        let n = buf.len().min(NOISE_MAX_PLAINTEXT - this.plain.len());
        this.plain.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            std::task::ready!(this.poll_drain_out(cx))?;
            if this.plain.is_empty() {
                break;
            }
            this.seal()?;
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
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

    #[tokio::test]
    async fn small_writes_coalesce_into_one_frame() {
        // yamux 把 header 與 body 分兩次寫;flush 前的多次小寫入應合併成
        // 一則 Noise message(線上只多一份 2+16 bytes 的額外負擔)。
        let (mut a, mut b) = connected_pair().await;
        a.write_all(&[1u8; 12]).await.unwrap();
        a.write_all(&[2u8; 1000]).await.unwrap();
        assert_eq!(a.plain.len(), 1012, "flush 前應只累積、不送出");
        assert_eq!(a.out_end, 0);
        a.flush().await.unwrap();
        assert_eq!(a.out_end, FRAME_LEN_PREFIX + 1012 + NOISE_TAG_LEN);

        let mut got = vec![0u8; 1012];
        b.read_exact(&mut got).await.unwrap();
        assert!(got[..12].iter().all(|&x| x == 1) && got[12..].iter().all(|&x| x == 2));
    }

    #[tokio::test]
    async fn many_frames_in_one_read_are_all_delivered() {
        // 多則小 frame 可能一次 read 就全部進到 rbuf —— 必須逐則解出,不可遺漏。
        let (mut a, mut b) = connected_pair().await;
        for i in 0..50u8 {
            a.write_all(&[i; 7]).await.unwrap();
            a.flush().await.unwrap();
        }
        let mut got = vec![0u8; 350];
        b.read_exact(&mut got).await.unwrap();
        for i in 0..50usize {
            assert!(got[i * 7..(i + 1) * 7].iter().all(|&x| x == i as u8));
        }
    }

    #[tokio::test]
    async fn read_watchdog_fires_when_peer_is_silent() {
        let (_a, b) = connected_pair().await;
        let mut b = b.with_read_idle_timeout(Duration::from_millis(150));
        let mut buf = [0u8; 8];
        let err = tokio::time::timeout(Duration::from_secs(5), b.read(&mut buf))
            .await
            .expect("watchdog did not fire")
            .expect_err("silent peer must surface as an error");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn read_watchdog_is_reset_by_traffic() {
        let (mut a, b) = connected_pair().await;
        let mut b = b.with_read_idle_timeout(Duration::from_millis(300));
        let writer = tokio::spawn(async move {
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                a.write_all(b"x").await.unwrap();
                a.flush().await.unwrap();
            }
            a
        });
        // 總時長 600ms > timeout 300ms,但每 100ms 有流量 → 不可觸發。
        let mut got = [0u8; 6];
        b.read_exact(&mut got).await.expect("active stream must not time out");
        let _a = writer.await.unwrap();
    }
}

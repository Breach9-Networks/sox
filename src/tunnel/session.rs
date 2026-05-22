//! yamux session 的建立與驅動。
//!
//! - Client 端：`SessionPool` 維護 N 條 session，接 server 開來的 inbound stream。
//! - Server 端：`server_session_driver` 驅動一條 session，依請求開 outbound stream。

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;
use yamux::{Config, Connection, Mode, Stream};

use crate::protocol::addr::TargetAddr;
use crate::protocol::socks5::ReplyCode;
use crate::relay::tcp::relay_bidirectional;
use crate::relay::udp::{read_udp_datagram, resolve_udp_target};
use crate::tunnel::backoff::Backoff;
use crate::tunnel::noise::{derive_psk, NoiseStream};
use crate::tunnel::noise_stream::NoiseByteStream;
use crate::tunnel::protocol::{Hello, HelloAck, StreamOpen, StreamReply, UdpDatagram, PROTO_VERSION};
use crate::tunnel::router::StreamRequest;

/// session 穩定存活超過此時間後，視為「健康」，重連退避歸零。
const STABLE_AFTER: Duration = Duration::from_secs(30);

/// 依 spec §6 建構 yamux Config。
///
/// `max_streams` = 每 session stream 上限；`recv_window_mb` = 總接收窗（MiB）。
/// yamux 要求總接收窗 >= 256 KiB × max_streams —— 此函式會把窗 clamp
/// 到下限以保證設定合法（呼叫端給太小的值不會造成 panic）。
pub fn yamux_config(max_streams: usize, recv_window_mb: usize) -> Config {
    let mut cfg = Config::default();
    cfg.set_max_num_streams(max_streams);
    let floor = max_streams * 256 * 1024;
    let requested = recv_window_mb * 1024 * 1024;
    cfg.set_max_connection_receive_window(Some(requested.max(floor)));
    cfg
}

// ───────────────────────── Client 端 ─────────────────────────

/// `SessionPool` 的可調參數。
#[derive(Debug, Clone)]
pub struct SessionPoolConfig {
    /// 維護幾條並行的 yamux session。
    pub sessions: u16,
    /// 每條 session 的 stream 上限。
    pub max_streams: usize,
    /// 每條 session 的 yamux 總接收窗（MiB）。
    pub recv_window_mb: usize,
    /// 重連退避基數。
    pub reconnect_base: Duration,
    /// 重連退避封頂。
    pub reconnect_max: Duration,
}

/// Client 端的 yamux session 連線池。
///
/// 維護 `sessions` 條到 tunnel server 的 session，每條獨立斷線、
/// 獨立以指數退避重連。server 透過這些 session 開 inbound stream，
/// 每條 stream 對應一個 proxy flow。
pub struct SessionPool {
    server_addr: String,
    client_id: String,
    psk: [u8; 32],
    cfg: SessionPoolConfig,
}

impl SessionPool {
    pub fn new(
        server_addr: String,
        client_id: String,
        secret: &str,
        cfg: SessionPoolConfig,
    ) -> Self {
        Self {
            server_addr,
            client_id,
            psk: derive_psk(secret),
            cfg,
        }
    }

    /// 啟動連線池 —— 為每條 session spawn 一個獨立維護的 worker。
    pub fn start(&self, cancel: CancellationToken) {
        for index in 0..self.cfg.sessions {
            let server_addr = self.server_addr.clone();
            let client_id = self.client_id.clone();
            let psk = self.psk;
            let cfg = self.cfg.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                session_worker(index, server_addr, client_id, psk, cfg, cancel).await;
            });
        }
    }
}

/// 單條 session 的長壽 worker：建立連線、斷線後以指數退避重連，
/// 直到被取消。
async fn session_worker(
    index: u16,
    server_addr: String,
    client_id: String,
    psk: [u8; 32],
    cfg: SessionPoolConfig,
    cancel: CancellationToken,
) {
    let mut backoff = Backoff::new(cfg.reconnect_base, cfg.reconnect_max);
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let started = Instant::now();
        match run_client_session(
            index,
            &server_addr,
            &client_id,
            &psk,
            cfg.max_streams,
            cfg.recv_window_mb,
            &cancel,
        )
        .await
        {
            Ok(()) => return, // 乾淨取消
            Err(e) => {
                if cancel.is_cancelled() {
                    return;
                }
                // session 曾穩定存活 → 視為健康，退避歸零。
                if started.elapsed() > STABLE_AFTER {
                    backoff.reset();
                }
                let delay = backoff.next_delay();
                tracing::debug!(index, error = %e, ?delay, "session lost, reconnecting");
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

/// 建立一條 client 端 session 並驅動其 yamux 連線，直到斷線或被取消。
///
/// 回傳 `Ok(())` 僅代表「乾淨取消」；任何其他結束（含對端關閉）回 `Err`，
/// 讓 worker 重連。
async fn run_client_session(
    index: u16,
    server_addr: &str,
    client_id: &str,
    psk: &[u8; 32],
    max_streams: usize,
    recv_window_mb: usize,
    cancel: &CancellationToken,
) -> io::Result<()> {
    let tcp = TcpStream::connect(server_addr).await?;
    tcp.set_nodelay(true)?;

    // Noise 握手。
    let mut noise = NoiseStream::connect(tcp, psk).await?;

    // Hello / HelloAck 握手（yamux 之前）。
    let hello = Hello {
        proto_version: PROTO_VERSION,
        session_index: index,
        client_id: client_id.to_string(),
    };
    noise.send(&hello.encode()).await?;
    let ack_bytes = noise.recv().await?;
    let ack = HelloAck::decode(&ack_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if !ack.accepted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("server rejected session: {}", ack.reason),
        ));
    }

    // 轉成位元組流，疊上 yamux（client 端為 Mode::Client，接 inbound stream）。
    let compat = noise.into_byte_stream().compat();
    let mut conn = Connection::new(compat, yamux_config(max_streams, recv_window_mb), Mode::Client);

    tracing::info!(index, "tunnel session established");

    loop {
        let inbound = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            inbound = std::future::poll_fn(|cx| conn.poll_next_inbound(cx)) => inbound,
        };
        match inbound {
            Some(Ok(stream)) => {
                tokio::spawn(handle_inbound_stream(stream));
            }
            Some(Err(e)) => return Err(io::Error::other(format!("yamux: {e}"))),
            None => return Err(io::Error::other("session closed by peer")),
        }
    }

    // 被取消 —— 盡力優雅關閉。
    let _ = std::future::poll_fn(|cx| conn.poll_close(cx)).await;
    Ok(())
}

/// 處理一條 server 開來的 inbound stream：讀 preamble → dial 目標 → relay。
async fn handle_inbound_stream(stream: Stream) {
    let mut io = stream.compat(); // futures -> tokio

    let open = match read_stream_open(&mut io).await {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!(error = %e, "failed to read StreamOpen preamble");
            return;
        }
    };

    match open {
        StreamOpen::Tcp { target } => {
            match TcpStream::connect(&target).await {
                Ok(mut target_stream) => {
                    let _ = target_stream.set_nodelay(true);
                    let bind = target_stream
                        .local_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                    let reply = StreamReply { status: 0, message: bind };
                    if io.write_all(&reply.encode()).await.is_err() {
                        return;
                    }
                    tracing::debug!(%target, "tunnel TCP flow connected, relaying");
                    let _ = relay_bidirectional(&mut io, &mut target_stream, None, None).await;
                }
                Err(e) => {
                    tracing::debug!(%target, error = %e, "tunnel TCP connect failed");
                    let reply = StreamReply {
                        status: ReplyCode::for_connect_error(&e) as u8,
                        message: e.to_string(),
                    };
                    let _ = io.write_all(&reply.encode()).await;
                }
            }
        }
        StreamOpen::Udp => {
            handle_udp_stream(io).await;
        }
    }
}

/// 處理一條 UDP-over-tunnel stream：回 reply、bind UDP socket、雙向橋接。
async fn handle_udp_stream<S>(mut io: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let reply = StreamReply { status: 0, message: String::new() };
    if io.write_all(&reply.encode()).await.is_err() {
        return;
    }
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::debug!(error = %e, "UDP socket bind failed");
            return;
        }
    };
    tracing::debug!("tunnel UDP flow established");
    let (sr, sw) = tokio::io::split(io);
    tokio::select! {
        _ = client_udp_t2s(sr, socket.clone()) => {}
        _ = client_udp_s2t(sw, socket) => {}
    }
}

/// tunnel stream → 真實 UDP socket：讀 datagram、解析目標、發出。
async fn client_udp_t2s<R>(mut sr: R, socket: Arc<UdpSocket>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let dat = read_udp_datagram(&mut sr).await?;
        let dest = match resolve_udp_target(&dat.addr).await {
            Ok(a) => a,
            Err(_) => continue,
        };
        socket.send_to(&dat.payload, dest).await?;
    }
}

/// 真實 UDP socket → tunnel stream：收回包、以來源位址 framing 後送回。
async fn client_udp_s2t<W>(mut sw: W, socket: Arc<UdpSocket>) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        let dat = UdpDatagram {
            addr: TargetAddr::Ip(src),
            payload: buf[..n].to_vec(),
        };
        sw.write_all(&dat.encode()).await?;
    }
}

/// 從 stream 開頭精確讀出 `StreamOpen` preamble（自帶長度，不會超讀）。
async fn read_stream_open<S>(s: &mut S) -> io::Result<StreamOpen>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut kind = [0u8; 1];
    s.read_exact(&mut kind).await?;
    match kind[0] {
        0x01 => {
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await?;
            let n = u16::from_be_bytes(len) as usize;
            let mut target = vec![0u8; n];
            s.read_exact(&mut target).await?;
            Ok(StreamOpen::Tcp {
                target: String::from_utf8_lossy(&target).into_owned(),
            })
        }
        0x02 => Ok(StreamOpen::Udp),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown StreamOpen kind {other:#x}"),
        )),
    }
}

// ───────────────────────── Server 端 ─────────────────────────

/// 驅動一條 server 端 yamux session。
///
/// 擁有 `Connection`，從 `open_rx` 收「開 outbound stream」請求 → `poll_new_outbound`；
/// 同時持續 poll `poll_next_inbound` 驅動連線（server 不預期 inbound stream）。
pub async fn server_session_driver(
    byte_stream: NoiseByteStream,
    mut open_rx: mpsc::Receiver<StreamRequest>,
    max_streams: usize,
    recv_window_mb: usize,
    cancel: CancellationToken,
) {
    let compat = byte_stream.compat();
    let mut conn = Connection::new(compat, yamux_config(max_streams, recv_window_mb), Mode::Server);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            req = open_rx.recv() => {
                let Some(reply) = req else { break }; // 所有 SessionHandle 已 drop
                let result = std::future::poll_fn(|cx| conn.poll_new_outbound(cx))
                    .await
                    .map_err(|e| io::Error::other(format!("yamux open: {e}")));
                let _ = reply.send(result);
            }
            inbound = std::future::poll_fn(|cx| conn.poll_next_inbound(cx)) => {
                match inbound {
                    Some(Ok(s)) => drop(s), // server 不預期 inbound stream
                    Some(Err(_)) | None => break,
                }
            }
        }
    }

    let _ = std::future::poll_fn(|cx| conn.poll_close(cx)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builds_for_various_inputs() {
        // 低於下限、剛好下限、高於下限 —— 都不應 panic。
        let _ = yamux_config(256, 1); // 要求 1 MiB，下限 64 MiB → clamp
        let _ = yamux_config(256, 64); // 剛好等於下限
        let _ = yamux_config(128, 256); // 高於下限
    }
}

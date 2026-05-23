//! yamux session 的建立與驅動。
//!
//! - Client 端：`SessionPool` 維護 N 條 session，接 server 開來的 inbound stream。
//! - Server 端：`server_session_driver` 驅動一條 session，依請求開 outbound stream。

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;
use yamux::{Config, Connection, Mode, Stream};

use crate::protocol::addr::TargetAddr;
use crate::protocol::socks5::ReplyCode;
use crate::relay::tcp::{idle_watcher, relay_bidirectional};
use crate::relay::udp::{read_udp_datagram, resolve_udp_target};
use crate::tunnel::apply_tunnel_keepalive;
use crate::tunnel::backoff::Backoff;
use crate::tunnel::noise::{derive_psk, NoiseStream};
use crate::tunnel::noise_stream::NoiseByteStream;
use crate::tunnel::protocol::{Hello, HelloAck, StreamOpen, StreamReply, UdpDatagram, PROTO_VERSION};
use crate::tunnel::router::StreamRequest;

/// session 穩定存活超過此時間後，視為「健康」，重連退避歸零。
const STABLE_AFTER: Duration = Duration::from_secs(30);

/// 每 session 的 stream 上限硬上限。防止設定檔給出荒謬值，導致
/// `yamux_config` 的接收窗下限乘法在 32-bit 上溢位、或配出過大的窗。
const MAX_STREAMS_CAP: usize = 4096;

/// yamux 接收窗硬上限（1 GiB）。`MAX_STREAMS_CAP` 已保證下限不超過此值。
const MAX_RECV_WINDOW: usize = 1024 * 1024 * 1024;

/// `session_worker` panic 後等多久才重啟,避免「panic → 立即重啟 → 再 panic」
/// 演變成 100% CPU 迴圈。
const WORKER_PANIC_BACKOFF: Duration = Duration::from_secs(1);

/// UDP 一條 association 內保留的「resolved dest → 原始目標」上限。超過後
/// FIFO 汰換最早的 entry。長壽 UDP association 對許多獨立目標時不會無限增長。
const MAX_UDP_DESTS: usize = 4096;

/// Insertion-order-bounded HashMap for `handle_udp_stream`'s dest tracking.
/// Overwrites keep the existing FIFO position; new keys push to the back and
/// pop the front when over the cap.
struct DestMap {
    inner: HashMap<SocketAddr, TargetAddr>,
    order: VecDeque<SocketAddr>,
}

impl DestMap {
    fn new() -> Self {
        Self {
            inner: HashMap::new(),
            order: VecDeque::new(),
        }
    }
    fn insert(&mut self, dest: SocketAddr, addr: TargetAddr) {
        if self.inner.insert(dest, addr).is_none() {
            self.order.push_back(dest);
            if self.order.len() > MAX_UDP_DESTS
                && let Some(oldest) = self.order.pop_front()
            {
                self.inner.remove(&oldest);
            }
        }
    }
    fn get(&self, dest: &SocketAddr) -> Option<&TargetAddr> {
        self.inner.get(dest)
    }
}

/// 依 spec §6 建構 yamux Config。
///
/// `max_streams` = 每 session stream 上限；`recv_window_mb` = 總接收窗（MiB）。
/// yamux 要求總接收窗 >= 256 KiB × max_streams。本函式：
/// - 把 `max_streams` clamp 進 `[1, MAX_STREAMS_CAP]`，下限乘法因此不會溢位；
/// - 接收窗用 saturating 乘法並封頂在 `MAX_RECV_WINDOW`；
///
/// 故任何輸入（含設定檔的荒謬值）都不會 panic 或配出失控的記憶體。
///
/// **效能注意**：yamux 對單一 stream 起始 receive window = 256 KiB，並會
/// 依 BDP 自動翻倍上去；但**翻倍的 headroom 取自 `(recv_window_mb_total
/// − max_streams × 256 KiB)`**（見 yamux `flow_control.rs::next_window_update`）。
/// 若呼叫端把 `recv_window_mb` 設到剛好等於下限，BDP auto-tune 完全失效，
/// 單流吞吐被夾在 `256 KiB / RTT`（RTT 10 ms ≈ 200 Mbps）。預設值刻意
/// 給 max_streams 的 4 倍 headroom。
pub fn yamux_config(max_streams: usize, recv_window_mb: usize) -> Config {
    let max_streams = max_streams.clamp(1, MAX_STREAMS_CAP);
    let mut cfg = Config::default();
    cfg.set_max_num_streams(max_streams);
    // max_streams <= 4096 → floor <= 1 GiB，即使 usize 為 32-bit 也不溢位。
    let floor = max_streams * 256 * 1024;
    let requested = recv_window_mb
        .saturating_mul(1024 * 1024)
        .min(MAX_RECV_WINDOW);
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
    /// 連到 proxy 目標的逾時。
    pub connect_timeout: Duration,
    /// relay 的閒置逾時（兩個方向都無資料）。
    pub idle_timeout: Duration,
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

    /// 啟動連線池 —— 為每條 session spawn 一個獨立維護的 worker,
    /// 並用 `catch_unwind` 監控:worker 若 panic,等 1s 後自動重啟,
    /// 避免單一未預期錯誤永久損失一個 session slot。
    pub fn start(&self, cancel: CancellationToken) {
        for index in 0..self.cfg.sessions {
            let server_addr = self.server_addr.clone();
            let client_id = self.client_id.clone();
            let psk = self.psk;
            let cfg = self.cfg.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    let worker = session_worker(
                        index,
                        server_addr.clone(),
                        client_id.clone(),
                        psk,
                        cfg.clone(),
                        cancel.clone(),
                    );
                    match AssertUnwindSafe(worker).catch_unwind().await {
                        Ok(()) => return, // session_worker 自己 cancel-clean 退出
                        Err(panic_payload) => {
                            tracing::error!(
                                index,
                                payload = ?panic_payload_str(&panic_payload),
                                "session_worker panicked, restarting after backoff"
                            );
                            if cancel.is_cancelled() {
                                return;
                            }
                            tokio::time::sleep(WORKER_PANIC_BACKOFF).await;
                            if cancel.is_cancelled() {
                                return;
                            }
                            // 迴圈重啟 worker
                        }
                    }
                }
            });
        }
    }
}

/// 把 `catch_unwind` 拿到的 panic payload 盡力轉成可讀字串。
fn panic_payload_str(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic>".to_string()
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
        match run_client_session(index, &server_addr, &client_id, &psk, &cfg, &cancel).await {
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
    cfg: &SessionPoolConfig,
    cancel: &CancellationToken,
) -> io::Result<()> {
    // 單一 deadline 涵蓋整段「session 建立」:TCP connect + Noise 握手 +
    // Hello/HelloAck 交換。任何一階段卡住都不會永久 wedge 這條 session,
    // backoff loop 會把它收掉重連。對等於 server 端的 HANDSHAKE_TIMEOUT。
    let deadline = tokio::time::Instant::now() + cfg.connect_timeout;
    let to_err = |what: &'static str| {
        io::Error::new(io::ErrorKind::TimedOut, format!("tunnel {what} timed out"))
    };

    let tcp = tokio::time::timeout_at(deadline, TcpStream::connect(server_addr))
        .await
        .map_err(|_| to_err("connect"))??;
    tcp.set_nodelay(true)?;
    // 半開死連線偵測 —— tunnel socket 啟用 OS 層 TCP keepalive。
    // keepalive 設定失敗（極罕見）不該讓整條 session 重連，故寬容處理。
    let _ = apply_tunnel_keepalive(&tcp);

    // Noise 握手。
    let mut noise = tokio::time::timeout_at(deadline, NoiseStream::connect(tcp, psk))
        .await
        .map_err(|_| to_err("noise handshake"))??;

    // Hello / HelloAck 握手（yamux 之前）。
    let hello = Hello {
        proto_version: PROTO_VERSION,
        session_index: index,
        client_id: client_id.to_string(),
    };
    tokio::time::timeout_at(deadline, noise.send(&hello.encode()))
        .await
        .map_err(|_| to_err("hello send"))??;
    let ack_bytes = tokio::time::timeout_at(deadline, noise.recv())
        .await
        .map_err(|_| to_err("hello-ack recv"))??;
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
    let mut conn = Connection::new(
        compat,
        yamux_config(cfg.max_streams, cfg.recv_window_mb),
        Mode::Client,
    );

    tracing::info!(index, "tunnel session established");

    let connect_timeout = cfg.connect_timeout;
    let idle_timeout = cfg.idle_timeout;
    loop {
        let inbound = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            inbound = std::future::poll_fn(|cx| conn.poll_next_inbound(cx)) => inbound,
        };
        match inbound {
            Some(Ok(stream)) => {
                tokio::spawn(handle_inbound_stream(stream, connect_timeout, idle_timeout));
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
///
/// `connect_timeout` 是「讀 preamble + dial 目標」的**共用** budget(用
/// `timeout_at` 同一 deadline 切分),不再是「每階段一份」—— 避免單一
/// stream 因為兩階段各拿一份逾時而把總時間放大成 2× connect_timeout,
/// 削弱了原本對慢速攻擊的保護。
/// `idle_timeout` 限制 relay 的閒置時間。
async fn handle_inbound_stream(stream: Stream, connect_timeout: Duration, idle_timeout: Duration) {
    let mut io = stream.compat(); // futures -> tokio
    let deadline = tokio::time::Instant::now() + connect_timeout;

    // preamble 必須在 server 開 stream 後迅速到達；逾時或出錯即放棄。
    let open = match tokio::time::timeout_at(deadline, read_stream_open(&mut io)).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "failed to read StreamOpen preamble");
            return;
        }
        Err(_) => {
            tracing::debug!("StreamOpen preamble timed out");
            return;
        }
    };

    match open {
        StreamOpen::Tcp { target } => {
            match tokio::time::timeout_at(deadline, TcpStream::connect(&target)).await {
                Ok(Ok(mut target_stream)) => {
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
                    let (c2s, s2c, outcome) = relay_bidirectional(
                        &mut io,
                        &mut target_stream,
                        None,
                        None,
                        Some(idle_timeout),
                    )
                    .await;
                    if let Err(e) = outcome {
                        tracing::debug!(%target, c2s, s2c, error = %e, "tunnel TCP relay error");
                    } else {
                        tracing::trace!(%target, c2s, s2c, "tunnel TCP relay finished");
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!(%target, error = %e, "tunnel TCP connect failed");
                    let reply = StreamReply {
                        status: ReplyCode::for_connect_error(&e) as u8,
                        message: e.to_string(),
                    };
                    let _ = io.write_all(&reply.encode()).await;
                }
                Err(_) => {
                    tracing::debug!(%target, "tunnel TCP connect timed out");
                    let reply = StreamReply {
                        status: ReplyCode::TtlExpired as u8,
                        message: "connect timeout".into(),
                    };
                    let _ = io.write_all(&reply.encode()).await;
                }
            }
        }
        StreamOpen::Udp => {
            handle_udp_stream(io, idle_timeout).await;
        }
    }
}

/// 處理一條 UDP-over-tunnel stream：回 reply、bind UDP socket、雙向橋接。
///
/// 用 `idle_timeout` 看守整條 flow —— 無資料達該時間即收工，避免閒置的
/// UDP socket 與 yamux stream 永久洩漏。
async fn handle_udp_stream<S>(mut io: S, idle_timeout: Duration)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::debug!(error = %e, "UDP socket bind failed");
            return;
        }
    };
    let reply = StreamReply { status: 0, message: String::new() };
    if io.write_all(&reply.encode()).await.is_err() {
        return;
    }
    tracing::debug!("tunnel UDP flow established");

    // `resolved dest -> SOCKS client 原始目標位址`。回程據此 (a) 只接受曾
    // 送達目標的來源回包,(b) 還原 client 當初使用的位址(可能是網域)。
    // FIFO-bounded(MAX_UDP_DESTS):長壽 association 對許多目標時不會無限增長。
    let dests: Arc<Mutex<DestMap>> = Arc::new(Mutex::new(DestMap::new()));
    // 共用的最後活動時間戳。**bind + reply 之後**才取樣 —— 否則「等 client
    // 第一筆 datagram」的時間會錯計成 idle,可能在 association 還沒被用過
    // 之前就誤觸 idle_watcher。
    let last = Arc::new(Mutex::new(Instant::now()));

    let (sr, sw) = tokio::io::split(io);
    tokio::select! {
        _ = client_udp_t2s(sr, socket.clone(), dests.clone(), last.clone()) => {}
        _ = client_udp_s2t(sw, socket, dests, last.clone()) => {}
        _ = idle_watcher(last, idle_timeout) => {
            tracing::debug!("tunnel UDP flow idle, closing");
        }
    }
}

/// tunnel stream → 真實 UDP socket：讀 datagram、解析目標、發出。
async fn client_udp_t2s<R>(
    mut sr: R,
    socket: Arc<UdpSocket>,
    dests: Arc<Mutex<DestMap>>,
    last: Arc<Mutex<Instant>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let dat = read_udp_datagram(&mut sr).await?;
        // 收到 datagram 本身就算「活動」—— 在 DNS resolve **之前**就更新
        // last,否則慢 DNS 會悄悄吃掉 idle 預算,active flow 也可能被 idle
        // watcher 砍掉,違反 CLAUDE.md priority #1 (connection stability)。
        *last.lock().unwrap() = Instant::now();
        let dest = match resolve_udp_target(&dat.addr).await {
            Ok(a) => a,
            Err(_) => continue,
        };
        // 記下「resolved dest → 原始目標」，供回程過濾與位址還原。
        dests.lock().unwrap().insert(dest, dat.addr.clone());
        socket.send_to(&dat.payload, dest).await?;
    }
}

/// 真實 UDP socket → tunnel stream：收回包、framing 後送回。
///
/// 只轉送「我們確實送過封包」的目標來的回包（S1：來源過濾），且回程
/// 的位址欄沿用 SOCKS client 當初使用的目標位址（A6：保留網域）。
async fn client_udp_s2t<W>(
    mut sw: W,
    socket: Arc<UdpSocket>,
    dests: Arc<Mutex<DestMap>>,
    last: Arc<Mutex<Instant>>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        // 取出原始目標位址；來源不在已送達集合內就丟棄（防回應注入）。
        let addr = match dests.lock().unwrap().get(&src).cloned() {
            Some(orig) => orig,
            None => continue,
        };
        *last.lock().unwrap() = Instant::now();
        let dat = UdpDatagram {
            addr,
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
/// 每輪迭代「**永遠先**」推進 `poll_next_inbound`,**再**處理 outbound
/// open 請求 —— 因為 ACK / window-update frame 都從 inbound 來,如果連續
/// 多個 outbound open 都立刻 Ready,前一版會 continue 回 step 1 而不碰
/// inbound,在 burst K 個請求時讓 inbound buffer 飽和,peer 無法送 ACK
/// 而 credit-bound 寫入卡死 —— 就是 D1 fix 原本要根治的死鎖。
///
/// `made_progress` 旗標讓 loop 只在「真的有東西動」時 continue,沒進度
/// 就回 Pending 等 waker,避免空轉。
pub async fn server_session_driver(
    byte_stream: NoiseByteStream,
    mut open_rx: mpsc::Receiver<StreamRequest>,
    max_streams: usize,
    recv_window_mb: usize,
    cancel: CancellationToken,
) {
    let compat = byte_stream.compat();
    let mut conn = Connection::new(
        compat,
        yamux_config(max_streams, recv_window_mb),
        Mode::Server,
    );
    // 目前手上待處理的「開 outbound stream」請求（一次處理一個）。
    let mut pending: Option<StreamRequest> = None;

    tokio::select! {
        biased;
        _ = cancel.cancelled() => {}
        _ = std::future::poll_fn(|cx| {
            loop {
                let mut made_progress = false;

                // 1. **每輪先** poll inbound,確保 ACK / window-update 一定
                //    被讀出,即使下面有大量 outbound open 要服務。
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(s))) => {
                        drop(s); // server 不預期 inbound stream
                        made_progress = true;
                    }
                    Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                        return Poll::Ready(());
                    }
                    Poll::Pending => {}
                }

                // 2. 沒有 pending 請求 → 試收一個新的。
                if pending.is_none() {
                    match open_rx.poll_recv(cx) {
                        Poll::Ready(Some(req)) => {
                            pending = Some(req);
                            made_progress = true;
                        }
                        Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                }

                // 3. 有 pending → 推進 poll_new_outbound。
                if pending.is_some()
                    && let Poll::Ready(result) = conn.poll_new_outbound(cx)
                {
                    let reply = pending.take().unwrap();
                    let _ = reply.send(
                        result.map_err(|e| io::Error::other(format!("yamux open: {e}"))),
                    );
                    made_progress = true;
                }

                if !made_progress {
                    return Poll::Pending;
                }
                // 有進度就再轉一圈 —— inbound 可能還有 frame 待讀,或下一筆
                // open 請求可在剛清空的 pending slot 就位。
            }
        }) => {}
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
        // 荒謬輸入：clamp + saturating 後不 panic、不溢位（含 32-bit usize）。
        let _ = yamux_config(0, 0);
        let _ = yamux_config(usize::MAX, usize::MAX);
        let _ = yamux_config(1_000_000, 10_000_000);
    }

    #[test]
    fn dest_map_evicts_oldest_when_over_cap() {
        // #14 regression: DestMap must bound its size via FIFO eviction,
        // not grow without limit.
        let mut m = DestMap::new();
        for i in 0..MAX_UDP_DESTS {
            let addr: SocketAddr = format!("10.0.0.1:{}", i % 65535 + 1).parse().unwrap();
            m.insert(addr, TargetAddr::Ip(addr));
        }
        assert_eq!(m.inner.len(), MAX_UDP_DESTS);
        let oldest: SocketAddr = "10.0.0.1:1".parse().unwrap();
        assert!(m.get(&oldest).is_some());

        // One more insert pushes us over the cap and evicts the oldest.
        let new_addr: SocketAddr = "10.0.0.99:9999".parse().unwrap();
        m.insert(new_addr, TargetAddr::Ip(new_addr));
        assert_eq!(m.inner.len(), MAX_UDP_DESTS);
        assert!(m.get(&oldest).is_none(), "oldest entry should be evicted");
        assert!(m.get(&new_addr).is_some());
    }

    #[test]
    fn dest_map_repeat_insert_keeps_size() {
        // Re-inserting the same key must not push to the FIFO order again
        // or grow the map.
        let mut m = DestMap::new();
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        m.insert(addr, TargetAddr::Ip(addr));
        m.insert(addr, TargetAddr::Ip(addr));
        m.insert(addr, TargetAddr::Ip(addr));
        assert_eq!(m.inner.len(), 1);
        assert_eq!(m.order.len(), 1);
    }
}

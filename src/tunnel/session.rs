//! yamux session 的建立與驅動。
//!
//! - Client 端：`SessionPool` 維護 N 條 session，接 server 開來的 inbound stream。
//! - Server 端：`server_session_driver` 驅動一條 session，依請求開 outbound stream。

use std::io;
use std::panic::AssertUnwindSafe;
use std::task::Poll;
use std::time::{Duration, Instant};

use futures::FutureExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::MissedTickBehavior;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;
use yamux::{Config, Connection, Mode, Stream};

use crate::net::{self, KeepaliveParams};
use crate::protocol::socks5::ReplyCode;
use crate::relay::tcp::relay_bidirectional;
use crate::relay::udp::{UdpOutbound, relay_udp_exit};
use crate::tunnel::backoff::Backoff;
use crate::tunnel::noise::{NoiseStream, derive_psk};
use crate::tunnel::noise_stream::NoiseByteStream;
use crate::tunnel::protocol::{Hello, HelloAck, PROTO_VERSION, StreamOpen, StreamReply};
use crate::tunnel::router::StreamRequest;
use crate::tunnel::{CLOSE_TIMEOUT, HEARTBEAT_INTERVAL, READ_IDLE_TIMEOUT, configure_tunnel_socket};

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

/// 週期性喚醒 session driver 的 timer(見 [`HEARTBEAT_INTERVAL`])。
fn heartbeat() -> tokio::time::Interval {
    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

/// 盡力優雅關閉 yamux 連線,但不超過 [`CLOSE_TIMEOUT`]。
async fn close_connection<T>(conn: &mut Connection<T>)
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    let close = std::future::poll_fn(|cx| conn.poll_close(cx));
    if tokio::time::timeout(CLOSE_TIMEOUT, close).await.is_err() {
        tracing::debug!("yamux close timed out (peer unresponsive)");
    }
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
    /// UDP 目標的 DNS 解析逾時。
    pub dns_timeout: Duration,
    /// shutdown 時等進行中 relay 跑完的上限。
    pub drain_timeout: Duration,
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
    /// 避免單一未預期錯誤永久損失一個 session slot。(release profile 必須是
    /// `panic = "unwind"`,否則這層監控形同虛設。)
    ///
    /// 回傳各 worker 的 handle:`cancel` 之後 await 它們,即等同等所有 session
    /// 把進行中的 relay drain 完(上限 `drain_timeout`)。
    pub fn start(&self, cancel: CancellationToken) -> Vec<JoinHandle<()>> {
        (0..self.cfg.sessions)
            .map(|index| {
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
                                tokio::select! {
                                    _ = cancel.cancelled() => return,
                                    _ = tokio::time::sleep(WORKER_PANIC_BACKOFF) => {}
                                }
                            }
                        }
                    }
                })
            })
            .collect()
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
///
/// **取消 = drain,不是中斷**:收到 cancel 後不再接新 stream,但繼續驅動 yamux
/// 連線,直到進行中的 relay 全部結束或 `drain_timeout` 到期 —— 連線一旦停止
/// 被 poll,其上所有 stream 就全部卡死,等於把傳輸中的 flow 攔腰砍斷。
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
    // socket 選項設定失敗（極罕見）不該讓整條 session 重連，故寬容處理。
    let _ = configure_tunnel_socket(&tcp);

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
    let byte_stream = noise.into_byte_stream().with_read_idle_timeout(READ_IDLE_TIMEOUT);
    let mut conn = Connection::new(
        byte_stream.compat(),
        yamux_config(cfg.max_streams, cfg.recv_window_mb),
        Mode::Client,
    );

    tracing::info!(index, "tunnel session established");

    // 進行中的 stream。session 以錯誤結束時 JoinSet 被 drop、全部 abort ——
    // 連線沒了,它們也不可能再有進展。
    let mut streams = JoinSet::new();
    let mut heartbeat = heartbeat();
    let mut draining = false;
    let drain_deadline = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(drain_deadline);

    loop {
        if draining && streams.is_empty() {
            break;
        }
        let inbound = tokio::select! {
            biased;
            _ = cancel.cancelled(), if !draining => {
                draining = true;
                drain_deadline
                    .as_mut()
                    .reset(tokio::time::Instant::now() + cfg.drain_timeout);
                tracing::info!(index, in_flight = streams.len(), "tunnel session draining");
                continue;
            }
            _ = &mut drain_deadline, if draining => {
                tracing::warn!(index, remaining = streams.len(), "drain timeout, aborting relays");
                streams.abort_all();
                break;
            }
            // 回收結束的 stream task,JoinSet 才不會無限累積。
            Some(_) = streams.join_next(), if !streams.is_empty() => continue,
            _ = heartbeat.tick() => continue,
            inbound = std::future::poll_fn(|cx| conn.poll_next_inbound(cx)) => inbound,
        };
        match inbound {
            // drain 期間不接新 flow —— drop 即 reset 該 stream。
            Some(Ok(stream)) if draining => drop(stream),
            Some(Ok(stream)) => {
                streams.spawn(handle_inbound_stream(stream, cfg.clone()));
            }
            Some(Err(e)) => return Err(io::Error::other(format!("yamux: {e}"))),
            None => return Err(io::Error::other("session closed by peer")),
        }
    }

    close_connection(&mut conn).await;
    Ok(())
}

/// Dial 一個 `"host:port"` 目標:解析出全部位址後依序嘗試(見
/// [`net::connect_any`]),整體不超過 `deadline`。
async fn dial_target(target: &str, deadline: tokio::time::Instant) -> io::Result<TcpStream> {
    let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "connect timeout");
    let addrs: Vec<_> = tokio::time::timeout_at(deadline, tokio::net::lookup_host(target))
        .await
        .map_err(|_| timed_out())??
        .collect();
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(timed_out());
    }
    let stream = net::connect_any(&addrs, remaining).await?;
    // 目標端同樣需要半開偵測,否則只能等 idle_timeout。設定失敗不致命。
    let _ = net::configure_stream(&stream, &KeepaliveParams::PROXY_DEFAULT);
    Ok(stream)
}

/// 處理一條 server 開來的 inbound stream：讀 preamble → dial 目標 → relay。
///
/// `connect_timeout` 是「讀 preamble + dial 目標」的**共用** budget(用
/// 同一 deadline 切分),不是「每階段一份」—— 避免單一 stream 把總時間放大成
/// 2× connect_timeout,削弱對慢速攻擊的保護。
async fn handle_inbound_stream(stream: Stream, cfg: SessionPoolConfig) {
    let mut io = stream.compat(); // futures -> tokio
    let deadline = tokio::time::Instant::now() + cfg.connect_timeout;

    // preamble 必須在 server 開 stream 後迅速到達；逾時或出錯即放棄。
    let open = match tokio::time::timeout_at(deadline, StreamOpen::read_from(&mut io)).await {
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
        StreamOpen::Tcp { target } => match dial_target(&target, deadline).await {
            Ok(mut target_stream) => {
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
                    &[],
                    &[],
                    Some(cfg.idle_timeout),
                )
                .await;
                if let Err(e) = outcome {
                    tracing::debug!(%target, c2s, s2c, error = %e, "tunnel TCP relay error");
                } else {
                    tracing::trace!(%target, c2s, s2c, "tunnel TCP relay finished");
                }
            }
            Err(e) => {
                tracing::debug!(%target, error = %e, "tunnel TCP connect failed");
                let reply = StreamReply {
                    status: ReplyCode::for_connect_error(&e) as u8,
                    message: e.to_string(),
                };
                let _ = io.write_all(&reply.encode()).await;
            }
        },
        StreamOpen::Udp => {
            let outbound = match UdpOutbound::bind(cfg.dns_timeout).await {
                Ok(o) => o,
                Err(e) => {
                    tracing::debug!(error = %e, "UDP socket bind failed");
                    let reply = StreamReply {
                        status: ReplyCode::GeneralFailure as u8,
                        message: e.to_string(),
                    };
                    let _ = io.write_all(&reply.encode()).await;
                    return;
                }
            };
            let reply = StreamReply { status: 0, message: String::new() };
            if io.write_all(&reply.encode()).await.is_err() {
                return;
            }
            tracing::debug!("tunnel UDP flow established");
            if let Err(e) = relay_udp_exit(io, outbound, cfg.idle_timeout).await {
                tracing::debug!(error = %e, "tunnel UDP flow ended with error");
            }
        }
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
/// 就回 Pending 等 waker,避免空轉。heartbeat tick 也算進度:它的作用就是
/// 讓閒置連線也定期被 poll(見 [`HEARTBEAT_INTERVAL`])。
pub async fn server_session_driver(
    byte_stream: NoiseByteStream,
    mut open_rx: mpsc::Receiver<StreamRequest>,
    max_streams: usize,
    recv_window_mb: usize,
    cancel: CancellationToken,
) {
    let byte_stream = byte_stream.with_read_idle_timeout(READ_IDLE_TIMEOUT);
    let mut conn = Connection::new(
        byte_stream.compat(),
        yamux_config(max_streams, recv_window_mb),
        Mode::Server,
    );
    // 目前手上待處理的「開 outbound stream」請求（一次處理一個）。
    let mut pending: Option<StreamRequest> = None;
    let mut heartbeat = heartbeat();

    tokio::select! {
        biased;
        _ = cancel.cancelled() => {}
        _ = std::future::poll_fn(|cx| {
            loop {
                let mut made_progress = false;

                // 0. heartbeat 到期 → 本輪照常 poll 連線(yamux 藉此送 ping)。
                while heartbeat.poll_tick(cx).is_ready() {
                    made_progress = true;
                }

                // 1. **每輪先** poll inbound,確保 ACK / window-update 一定
                //    被讀出,即使下面有大量 outbound open 要服務。
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(s))) => {
                        drop(s); // server 不預期 inbound stream
                        made_progress = true;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        tracing::debug!(error = %e, "tunnel session failed");
                        return Poll::Ready(());
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
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

    close_connection(&mut conn).await;
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
}

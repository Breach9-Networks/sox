//! Tunnel: TCP + Noise + yamux multiplexed reverse-proxy transport.

pub mod backoff;
pub mod noise;
pub mod noise_stream;
pub mod protocol;
pub mod router;
pub mod session;

use std::time::Duration;

/// session driver 喚醒 yamux 的週期。yamux 0.13 的 RTT ping 沒有自己的 timer ——
/// 連線不被 poll 就不會送。閒置 session 因此完全沒有流量,半開連線也就無從
/// 偵測。driver 每隔這段時間 poll 一次,讓 ping(及對端的 pong)持續流動。
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// tunnel socket 多久沒收到任何位元組就視為已死(見 `NoiseByteStream` 的讀取
/// 看門狗)。容得下數次 heartbeat 遺失 —— 雙方各自每 `HEARTBEAT_INTERVAL` 送
/// ping,健康連線的靜默期不會超過一個週期加 RTT。
pub const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// 優雅關閉 yamux 連線(GoAway + flush)的時間上限 —— 對端已死時 flush 可能
/// 永遠等不到,不可因此卡住 shutdown。
pub const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// 對 tunnel session 的底層 TCP socket 設定 NODELAY 與 OS 層 keepalive。
///
/// 半開死連線有兩層偵測:
/// 1. **OS keepalive**([`KeepaliveParams::TUNNEL`],約 35s)—— 連線閒置時有效。
///    Windows 無 per-socket 探測次數介面,偵測窗約 45-70s。
/// 2. **讀取看門狗**([`READ_IDLE_TIMEOUT`])—— 有未 ACK 資料時 keepalive 不探測
///    (由 RTO 決定,可達 ~15 分鐘),這層補上該缺口,且跨平台一致。
pub fn configure_tunnel_socket(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    crate::net::configure_stream(stream, &crate::net::KeepaliveParams::TUNNEL)
}

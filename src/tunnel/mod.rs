//! Tunnel: TCP + Noise + yamux multiplexed reverse-proxy transport.

pub mod backoff;
pub mod noise;
pub mod noise_stream;
pub mod protocol;
pub mod router;
pub mod session;

use std::time::Duration;

/// 對 tunnel session 的底層 TCP socket 啟用 OS 層 keepalive。
///
/// 用來偵測「半開死連線」—— 對端斷電、或 NAT/防火牆靜默丟棄閒置流
/// （無 FIN/RST）。yamux 對閒置連線不主動送 ping，故需靠 kernel 探測；
/// 探測失敗會讓底層 socket 報錯，session driver 隨之結束、觸發重連。
///
/// **目標偵測窗:** idle 20s + interval 5s × 3 probes ≈ 35s。
///
/// **跨平台一致性:** socket2 0.5 的 `with_retries` 只在 Linux/Android,
/// 我們在所有 unix(含 macOS、musl)用 libc setsockopt 直接設 TCP_KEEPCNT,
/// 確保偵測窗一致。Windows 無 per-socket 介面(系統層
/// `TcpMaxDataRetransmissions`,通常 5-10),會退到 OS 預設,偵測窗約
/// 45-70s。
pub fn apply_tunnel_keepalive(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(20))
        .with_interval(Duration::from_secs(5));
    socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive)?;
    set_keepalive_probes(stream, 3);
    Ok(())
}

/// 在 unix 平台直接以 libc::setsockopt 設定 `TCP_KEEPCNT`(探測次數)。
///
/// `socket2` 的 `TcpKeepalive::with_retries` 只在 Linux/Android 可用,
/// macOS / musl Linux 因而拿不到自訂值。這個 helper 用 libc 直接呼叫
/// setsockopt,把支援平台統一到所有 unix。失敗只 log 不傳染。
///
/// Windows 無此功能,空實作。
#[cfg(unix)]
pub(crate) fn set_keepalive_probes(stream: &tokio::net::TcpStream, count: u32) {
    use std::os::fd::AsRawFd;
    let retries: libc::c_int = count as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            &retries as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        tracing::debug!(
            error = %std::io::Error::last_os_error(),
            "TCP_KEEPCNT setsockopt failed; using OS default probe count"
        );
    }
}

#[cfg(not(unix))]
pub(crate) fn set_keepalive_probes(_stream: &tokio::net::TcpStream, _count: u32) {
    // Windows: TCP_KEEPCNT is not exposed per-socket; falls back to the
    // system-wide TcpMaxDataRetransmissions registry value.
}

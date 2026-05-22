//! yamux session 的建立、驅動與（client 端）連線池。

use yamux::Config;

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

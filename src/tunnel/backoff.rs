//! 指數退避 + jitter，供 session 重連使用。
//!
//! 每次重連失敗，等待時間指數成長並封頂在 `max`；session 穩定後
//! `reset()` 把計數歸零，下次重連回到 `base`。

use std::time::Duration;

/// 退避曲線參數。
const MULTIPLIER: f64 = 1.5;
/// jitter 幅度：±20%，打散大量 client 的同步重連洪峰。
const JITTER: f64 = 0.2;
/// `base` 下限:0 會讓斷線的 client 以零延遲空轉重連(吃滿 CPU 並轟炸 server)。
const MIN_BASE: Duration = Duration::from_millis(100);
/// `max` 上限:再大沒有實際意義,且過大的值會讓 `Duration::from_secs_f64` panic。
const MAX_CAP: Duration = Duration::from_secs(3600);

/// 單條 session 的重連退避狀態。
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    /// `base` = 第一次重連的等待基數；`max` = 退避封頂。
    ///
    /// 兩者都會被夾進合理範圍(`base` ∈ [100ms, 1h],`max` ∈ [`base`, 1h]),
    /// 所以設定檔 / CLI 給出 0 或荒謬大值都不會造成空轉或 panic。
    pub fn new(base: Duration, max: Duration) -> Self {
        let base = base.clamp(MIN_BASE, MAX_CAP);
        let max = max.clamp(base, MAX_CAP);
        Self { base, max, attempt: 0 }
    }

    /// session 穩定存活後呼叫，把 attempt 歸零，下次重連回到 base。
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// 回傳下一次重連前應等待的時間，並遞增 attempt 計數。
    ///
    /// 曲線：`base × 1.5^attempt`，封頂 `max`，再乘上 ±20% 的隨機
    /// jitter。jitter 用 `rand` 把大量 client 的重連時間點打散，
    /// 避免 server 恢復瞬間被同步洪峰再次打垮。
    pub fn next_delay(&mut self) -> Duration {
        // attempt 封頂:1.5^64 早已遠超 MAX_CAP,再大只會讓 powi 溢成 inf。
        let raw = self.base.as_secs_f64() * MULTIPLIER.powi(self.attempt.min(64) as i32);
        let capped = raw.min(self.max.as_secs_f64());
        self.attempt = self.attempt.saturating_add(1);

        // jitter factor 落在 [1-JITTER, 1+JITTER) = [0.8, 1.2)
        let factor = 1.0 - JITTER + rand::random::<f64>() * (2.0 * JITTER);
        Duration::from_secs_f64(capped * factor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 註：下列測試刻意用寬鬆邊界，能容忍不同的 multiplier 與 jitter%
    // 選擇；它們驗證的是「行為正確」（有成長、有封頂、reset 有效），
    // 而非把曲線參數釘死。

    #[test]
    fn first_delay_near_base() {
        let mut b = Backoff::new(Duration::from_secs(5), Duration::from_secs(60));
        let d0 = b.next_delay();
        // 第一次重連應落在 base 附近（容忍任意合理 jitter）。
        assert!(
            d0 >= Duration::from_millis(2500) && d0 <= Duration::from_secs(10),
            "first delay {d0:?} should be near base (5s)"
        );
    }

    #[test]
    fn grows_then_caps() {
        let mut b = Backoff::new(Duration::from_secs(5), Duration::from_secs(60));
        let d0 = b.next_delay();
        // 連跳數次後，延遲必定明顯大於起始值（即使 jitter 不利）。
        for _ in 0..4 {
            b.next_delay();
        }
        let d5 = b.next_delay();
        assert!(d5 > d0, "delay should grow exponentially: d5={d5:?} d0={d0:?}");
        // 再連叫多次必定封頂（max 60s + 合理 jitter 餘裕）。
        for _ in 0..30 {
            let d = b.next_delay();
            assert!(d <= Duration::from_secs(90), "delay {d:?} should be capped near max");
        }
    }

    #[test]
    fn reset_returns_to_base() {
        let mut b = Backoff::new(Duration::from_secs(5), Duration::from_secs(60));
        for _ in 0..10 {
            b.next_delay();
        }
        b.reset();
        let d = b.next_delay();
        assert!(d <= Duration::from_secs(10), "after reset delay {d:?} should return to base");
    }

    #[test]
    fn degenerate_inputs_neither_spin_nor_panic() {
        // A14: reconnect_interval = 0 must not become a zero-delay loop.
        let mut b = Backoff::new(Duration::ZERO, Duration::ZERO);
        for _ in 0..100 {
            assert!(b.next_delay() >= Duration::from_millis(50));
        }
        // Absurd cap + many attempts must not overflow `Duration::from_secs_f64`.
        let mut b = Backoff::new(Duration::from_secs(u64::MAX / 4), Duration::MAX);
        for _ in 0..10_000 {
            assert!(b.next_delay() <= Duration::from_secs(3600 * 2));
        }
    }
}

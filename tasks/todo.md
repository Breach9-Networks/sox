# sox — 工作紀錄與交接

`sox` 是跨平台 SOCKS4/4a/5 proxy + reverse tunnel。本檔是進行中工作的交接點。

- 設計／計畫：`docs/specs/2026-05-22-tunnel-multiplexing-design.md`、
  `docs/plans/2026-05-22-tunnel-multiplexing.md`
- 所有變更皆已 commit 在 `main`；66 個測試（56 單元 + 10 整合）全綠，
  `cargo clippy --all-targets` 僅剩一個既有警告（見「下一步」第 1 點）。

## 目前狀態

tunnel 已從「200 條單一 stream 連線池」改寫為 **yamux session 多工**
（`TCP → Noise → yamux session → 多 stream`）。其後又完成數個 enhancement
與 bug 修正。

## 已完成

**核心：yamux multiplexing 重寫**

- 一個 proxy flow = 一條 yamux stream；少量 session（預設 8）取代 200 連線池。
- UDP ASSOCIATE 改走 tunnel。指數退避重連。
- `pool.rs`／`worker.rs`／`TunnelMessage`／`NoiseSender`/`Receiver` 已移除。

**Enhancement（借鏡 TrustTunnel）**

- DNS-aware UDP 生命週期：只跑 DNS 的 UDP 關聯閒置 3s 即提早關閉。
- RAII metrics guard：active 計數綁 `ConnectionGuard`，連線處理 panic 也不漏。
- Graceful shutdown：shutdown 改為 drain 進行中的 relay（`drain_timeout` 上限），
  `run_server` 補上 drain loop、tunnel 分階段關閉。
- accept loop 韌性：accept 出錯（如 `EMFILE`）不再殺死整台 server。

**Bug 修正**

- standalone UDP ASSOCIATE 全斷（port-0 sentinel 過濾掉所有 datagram）。
- SOCKS5 command／RFC 1929 auth request 分片到達時解析失敗、連線被丟。
- `[tunnel] secret` 設定死欄位（從不被讀取）。

## 下一步：程式碼優化 pass

與使用者約定的下一個工作 —— 用乾淨上下文的新 session 進行。

1. 修掉既有 clippy 警告：`src/protocol/addr.rs` 的 `items_after_test_module`
   —— 把 `impl fmt::Display for TargetAddr` 移到 `#[cfg(test)] mod tests` 之前。
2. 用 code-simplifier 審視這次大改的程式碼：`src/tunnel/`、`src/relay/`、
   `src/server/connection.rs`、`src/server/tunnel_listener.rs`。
3. 評估拆分 `src/server/connection.rs`（~800 行，含 SOCKS4／SOCKS5／CONNECT／
   UDP／tunnel 多個 handler）—— 可考慮把 tunnel／udp handler 拆成子模組。
4. 收尾：`cargo test`（66 測試）+ `cargo clippy --all-targets` 須維持全綠／乾淨。

## Backlog（enhancement，無急迫性）

- monitor dashboard 加 Bearer token 認證。
- `sox init` 互動式設定精靈 + 高強度隨機 secret 產生。
- IdChain 階層式 log ID、Prometheus `/metrics` endpoint、可選 crash 上報。
- Noise NN → XX/IK 升級（mutual auth、可撤銷單一 client key）。

## 評估後不採用

- Lazy 連線限制 acquire（TrustTunnel）：那是為「限制付費 VPN 用戶」設計；
  對 sox，per-IP 連線限制是濫用防護，本就該在 accept 當下生效。

## 待觀察

- Blast radius：一條 yamux session 死會帶走其上所有 stream（≈ flows ÷ N）。
  `tunnel_sessions` 預設 8，正式上線依實測在 4–16 間調。
- 記憶體上限 ≈ `recv_window_mb × tunnel_sessions`（server 端預設 64 × 8）。

## 本機測試環境（背景執行中）

sox server + client 正以最新 build 在背景執行：

- SOCKS proxy `127.0.0.1:1080`、tunnel `127.0.0.1:9090`、monitor `127.0.0.1:8080`
- secret `sox-test-secret`；log 在 `/tmp/sox-server.log`、`/tmp/sox-client.log`
- 停止：`pkill -f 'debug/sox'`

# Tunnel Stream Multiplexing

借鏡 TrustTunnel 的多工設計，把 reverse tunnel 從「200 條單一 stream 連線池」
改成「少量 yamux session 多工」。

- 設計：`docs/specs/2026-05-22-tunnel-multiplexing-design.md`
- 計畫：`docs/plans/2026-05-22-tunnel-multiplexing.md`
- 分支：`feat/tunnel-multiplexing`

## 進度（20/20 完成）

- [x] Task 1–8　地基：yamux 依賴、NoiseByteStream、wire codec、Backoff、泛型 relay、yamux Config
- [x] Task 9　　 Client SessionPool
- [x] Task 10–14 原子重構：Router / tunnel_listener / connection.rs / client / 刪舊碼
- [x] Task 15–16 UDP-over-tunnel（server + client）
- [x] Task 17　　設定變更（含修 `[tunnel] secret` 死欄位 bug）
- [x] Task 18–20 整合測試：端到端 TCP、stream 隔離、重連、UDP

## Review

**已交付**

- tunnel 改為 `TCP → Noise → yamux session → 多 stream`；`pool.rs`/`worker.rs`/
  `TunnelMessage`/`NoiseSender`/`NoiseReceiver` 移除。
- 一個 proxy flow = 一條 yamux stream；server 開、client 接。預設 8 條 session。
- UDP ASSOCIATE 改走 tunnel（先前繞過 tunnel 直接從 server 出網）。
- 重連改指數退避（base 5s、cap 60s、±20% jitter），取代固定 5s／硬編碼 2s。
- 58 個測試全綠；`slow_stream_does_not_block_cotenant` 實測驗證 yamux per-stream
  flow control 確實隔離慢 stream。real binary 冒煙測試（curl 穿透）通過。
- `return_data_conn` 的 `_assign_rx` race 隨舊碼刪除而消失。

**待觀察**

- **Blast radius**：一條 session 死，掛在其上的所有 stream 一起死（≈ flows ÷ N）。
  預設 N=8；正式上線依實測在 4–16 間調 `tunnel_sessions`。
- **記憶體**：最壞值 ≈ `recv_window_mb × tunnel_sessions`（server 端預設 64×8）。
- **行為變更**：`run_client` 不再「失敗 30 分鐘後放棄」，改為永久重連。刻意如此
  （daemon 應持續嘗試），但與舊行為不同。

## 後續修正（multiplexing 之後）

**已修 bug**

- standalone 模式 UDP ASSOCIATE 全斷：`relay_udp` 用 port-0 sentinel 過濾來源，
  丟光所有 datagram —— 改為依 IP 過濾、從首包動態學 client 位址。
- SOCKS5 command / RFC 1929 auth request 用單次 `read()`，分片到達時解析
  失敗、連線被丟 —— 改為讀到 parser 回報完整為止。
- 新增重現測試（standalone UDP、command 分片、auth 分片）。

**已完成（TrustTunnel 借鏡）**

- DNS-aware UDP 生命週期：只跑 DNS 的 UDP 關聯閒置 3s 即提早關閉，不再佔住
  yamux stream／socket 到 idle timeout。`relay_udp` 與 `relay_udp_tunneled`
  皆已接上，共 63 測試。

**待辦（TrustTunnel 可再借鏡，依優先序）**

- Lazy 連線限制 acquire：限制「已認證」連線而非 idle TCP accept。
- Graceful shutdown completion barrier：tunnel 側等 in-flight relay 收尾再關。
- RAII metrics guard：active 計數綁物件生命週期，防 panic 路徑洩漏。
- accept loop 致命錯誤（`EMFILE`）用 watch-channel 傳播，避免 busy-spin。
- monitor dashboard 加 Bearer token 認證。
- `sox init` 互動式設定精靈 + 高強度隨機 secret 產生。
- 啟動自動抬高 fd limit（目前只檢查並警告）。
- IdChain 階層式 log ID、Prometheus `/metrics` endpoint、可選 crash 上報。
- Noise NN → XX/IK 升級（mutual auth、可撤銷單一 client key）。

**已知小瑕疵**

- clippy `addr.rs items_after_test_module` —— 早於本次工作，未動。

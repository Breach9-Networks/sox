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

**未做（範圍外，另案）**

- Noise NN → XX/IK 升級（mutual auth、可撤銷單一 client key）—— spec 明列非目標。
- monitor dashboard 無認證保護 —— 原始分析有標記，未處理。
- 既有 clippy 警告 `addr.rs items_after_test_module` —— 早於本次重構，未動。
- standalone 模式的 direct `relay_udp` 有既有的 client-addr 過濾瑕疵（以 ip:0 過濾）；
  tunnel 路徑的 `relay_udp_tunneled` 已正確處理（依 IP 過濾、動態學 client addr）。

# Tunnel Stream Multiplexing 設計

- **日期**：2026-05-22
- **狀態**：設計已核可，待寫實作計畫
- **分支**：`feat/tunnel-multiplexing`

## 1. 背景與動機

`sox` 目前的 reverse tunnel 採「連線池」模型：

- 一條 Noise 連線 = 一個 stream。`ConnectionPool` 預設開 `pool_size = 200` 條獨立 TCP+Noise 連線。
- 每條連線一次只服務一個 `ProxyRequest`，relay 期間整條連線被獨佔。
- control channel 另外獨立一條連線（`Register` + 自訂 heartbeat）。

問題：

- 啟動即做 200 次 X25519 Noise handshake，佔 200 個 fd。
- 每個 `NoiseStream` 各帶 `read_buf`/`write_buf = vec![0u8; 65535]` → 200 條 ≈ **26 MB buffer 閒置**。
- 「並發上限」與「連線數」綁死：要支援 N 個並發就得開 N 條連線。
- `Router::return_data_conn` 有一個 race condition（`_assign_rx` 被立刻 drop，`assign_tx.send()` 永遠失敗）。

## 2. 目標與非目標

**目標**

- 用 stream multiplexing 取代連線池：少量連線承載大量動態 stream。
- 正確的 per-stream flow control，避免 head-of-line blocking。
- 支援 >1000 並發 proxy flow。
- TCP 與 UDP 都走 tunnel（修掉「UDP ASSOCIATE 繞過 tunnel」的缺口）。
- 順手修掉 `return_data_conn` race、`config.rs` secret 死欄位、固定重連間隔。

**非目標**

- 不換傳輸層（維持 TCP + Noise PSK，不引入 QUIC/TLS）。
- 不改 SOCKS4/5 對外行為。
- 不做 client identity 驗證升級（Noise NN→XX/IK 另案處理）。

## 3. 方案選擇

| 方案 | 內容 | 結論 |
|---|---|---|
| **A（採用）** | yamux 疊在「位元組流化」的 Noise 上 | yamux 提供久經實戰的 stream 管理與 credit-based flow control；淨刪自訂 framing 程式碼 |
| B | 手寫 stream 層 + 自製 credit flow control | credit-window 狀態機 subtle、易出 deadlock/記憶體爆，與「穩定性優先」相悖 |
| C | 分片 mux，不做 flow control | >1000 並發下共租 stream 的 HOL 無人管理，與規模不匹配 |

決策依據：大型規模需要正確 flow control；可接受成熟 crate；穩定性優先 → 不手寫最易錯的那塊。

## 4. 架構

### 4.1 分層堆疊

```
   【SOCKS server 端】                         【tunnel client 端】

  SOCKS client ↔ SOCKS handler                  dial 目標 server
        │                                              │
        │  一個 proxy flow = 一個 yamux stream          │
        ▼                                              ▼
   yamux stream  ◀──────────── 多工 ───────────▶  yamux stream
        │                                              │
   yamux Session (Mode::Server，開 stream)      yamux Session (Mode::Client，接 stream)
        │                                              │
   NoiseByteStream  ◀──── 加密位元組管道 ────▶   NoiseByteStream
        │                                              │
    TcpStream  ◀═══════════ 網路 ═══════════▶      TcpStream
  （SessionPool：N 條 session，預設 8）
```

### 4.2 元件

1. **`NoiseByteStream`** — 把 Noise transport 從訊息式（`send`/`recv`）改造成透明的 `AsyncRead + AsyncWrite` 加密管道。Noise handshake（`connect`/`accept`、PSK 衍生）不變。寫入位元組切成 ≤ 65519 bytes 的 Noise message（65535 ciphertext − 16 byte AEAD tag）；讀取時解密吐 byte。實作 tokio 的 `AsyncRead/AsyncWrite`。
2. **yamux `Session`** — 每條 TCP+Noise 連線一個 yamux session。**SOCKS server 端開 outbound stream，tunnel client 端接 inbound stream**（yamux 協定允許兩端皆可開 stream，以奇/偶 ID 區分）。
3. **Session driver task** — 每 session 一個 task，驅動 yamux `Connection`（`Connection` 只有被 poll 才推進）。
4. **`SessionPool`（client 端）** — 取代 `ConnectionPool`。維護 N 條 session，每條獨立斷線、獨立指數退避重連。
5. **`Router`（server 端）** — 持有每個 client 的 N 個 session handle。「取一條 data conn」變成「在該 client 的 session 間輪流開一個新 yamux stream」。
6. **Per-flow task** — 一個 yamux stream 一個 task（與現行一致）。

### 4.3 Session driver 細節

yamux `Connection` 吃 `futures::io::AsyncRead/AsyncWrite`；`NoiseByteStream` 實作 tokio trait，用 `tokio_util::compat` 的 `.compat()` 轉接。

- **Server driver**：擁有 `Connection`，從 mpsc 收 SOCKS handler 的開 stream 請求 → `poll_new_outbound`；同時持續 poll `poll_next_inbound` 驅動連線（不預期 inbound stream，收到即視為協定錯誤並 reset）。
- **Client driver**：擁有 `Connection`，迴圈 `poll_next_inbound` 接 stream，每接到一條 spawn 一個 handler task。

## 5. Wire 協定

協定分三層：session 層（yamux 之前）、stream preamble 層（每條 stream 開頭）、payload 層。所有整數 big-endian。

### 5.1 Session 層 — `Hello` 握手（yamux 之前）

Noise handshake 完成後、yamux 接手前，交換一組 `Hello`。明文裝在一個 Noise message（Noise frame 已含長度與完整性，不需額外 length 欄位）。

```
Hello        (client → server)
  [0]      proto_version : u8        從 1 起；不符 → 拒絕
  [1..3]   session_index : u16       該 client 第幾條 session（觀測用）
  [3]      client_id_len : u8
  [4..]    client_id     : UTF-8

HelloAck     (server → client)
  [0]      accepted      : u8 (0/1)
  [1..3]   reason_len    : u16
  [3..]    reason        : UTF-8     被拒原因
```

交換完，雙方把 `TransportState` + TCP 包成 `NoiseByteStream`，yamux 啟動。

### 5.2 Stream preamble 層 — server 開 stream 後的開頭位元組

self-delimiting，不需外層 framing。

```
StreamOpen   (server → client，stream 開頭)
  [0]   kind : u8     0x01 = TCP connect, 0x02 = UDP associate
  -- kind == TCP --
  [1..3] target_len : u16
  [3..]  target     : UTF-8 "host:port"
  -- kind == UDP --
  (無更多欄位)

StreamReply  (client → server，回寫同一條 stream)
  [0]    status  : u8       0 = ok；非 0 = 錯誤碼（對映 SOCKS5 reply code）
  [1..3] msg_len : u16
  [3..]  msg     : UTF-8     成功時 bind addr，失敗時錯誤訊息
```

`status` 非 0 時用一組對映 `ServerError::to_reply_code()` 的錯誤碼，保留精準的 SOCKS5 reply code。

### 5.3 Payload 層

**TCP stream**：`StreamReply` status=0 後，stream 承載裸 TCP 位元組，雙向。EOF 與 half-close 由 yamux stream 原生處理（不需 `RelayData`/`RelayEnd`）。

**UDP stream**：`StreamReply` status=0 後，stream 承載重新 framing 的 datagram（補回 datagram 邊界）：

```
每個 datagram:
  [0..2]  len     : u16     此 frame 剩餘長度
  [2]     atyp    : u8      1=IPv4, 4=IPv6, 3=domain
  [...]   addr               4 / 16 / (1+N) bytes
  [...]   port    : u16
  [...]   payload
```

addr 編碼重用 `src/protocol/addr.rs` 的 `TargetAddr`。一個 UDP ASSOCIATE 關聯 = 一條 UDP stream；client 端為每條 UDP stream 持一個 UDP socket，回包以來源 addr 標記送回同一條 stream。

### 5.4 協定面淨變化

`MessageType` enum 幾乎全拆：

| 舊 | 新 |
|---|---|
| `Register` | `Hello` |
| `Heartbeat` | yamux 內建 keepalive ping |
| `RequestProxy` / `DataReady` | 刪除（pool 概念消失） |
| `ProxyRequest` / `ProxyReply` | `StreamOpen` / `StreamReply`（stream preamble，不帶 `request_id`） |
| `RelayData` / `RelayEnd` | 刪除（yamux stream 即位元組流） |
| `Disconnect` | yamux session GoAway／關閉 |

`request_id` 消失 —— yamux stream 本身即身分。`src/tunnel/protocol.rs` 從 ~430 行縮到只剩四種 codec。

## 6. yamux 設定

`Config` 旋鈕（已對 `/libp2p/rust-yamux` 查證）：

- `set_max_num_streams(n)` — 每 session stream 上限（預設 512），防記憶體耗盡。
- `set_max_connection_receive_window(Some(bytes))` — 整條 session 總接收窗（預設 1 GiB），**必須 ≥ 256 KiB × max_num_streams**。per-stream window 由 yamux 自動調適，只設總量。
- `set_split_send_size` — 預設 16 KiB，遠小於 64KB Noise message，無衝突。

**建議值**：每 session `max_num_streams = 256`、`max_connection_receive_window = 64 MiB`。8 條 session → 容量 ~2000 streams、最壞記憶體 8 × 64 = 512 MiB。皆走 config。

> 記憶體上限由 connection 層 receive window 決定，**不是** `streams × 256KB`。

## 7. 失敗模型與 blast radius

一條 session 死 → driver task 結束 → 其上所有 yamux stream 被 reset → 對應 proxy flow 報錯。

- **Blast radius = 進行中 flow 數 ÷ session 數**。1000 flows、N=8 → 約損失 125 flow。
- **緩解**：server 偵測 session 死即停止往它路由新 stream；client 指數退避重連；期間新 stream 進倖存 session → 單條 session 損失只降容量 ~1/N，不會讓 tunnel 整體倒下。
- **取捨**：此設計在「單次失敗隔離性」上劣於舊模型（舊模型一連線死只死一 flow），代價是換取 25× 的資源節省。預設 N=8，建議範圍 4–16。

## 8. 重連退避

`SessionPool` 重寫時納入指數退避（同時取代 control channel 固定 5s 與 `pool.rs` 硬編碼 2s）：

- 每 session 獨立重連：`reconnect_interval`（預設 5s）為退避基數 → `base × 1.5^attempts`，封頂 `reconnect_max`（新設定，預設 60s），加 ±20% jitter。
- session 穩定存活 > 30s 後 attempts 歸零。

## 9. 設定變更

```toml
[tunnel]
secret = "..."                # 修 bug：apply_to() 目前未讀此欄，改成真的讀
tunnel_sessions = 8           # 取代 pool_size（原 200）
max_streams_per_session = 256 # yamux 防護
recv_window_mb = 64           # yamux 總接收窗
reconnect_interval = 5        # 退避基數
reconnect_max = 60            # 退避封頂（新增）
```

`pool_size` 移除。

## 10. 刪除／變更清單

**刪除**

- `src/tunnel/pool.rs` 整個（`ConnectionPool`/`pool_slot`/`establish_and_serve_loop`）。
- `MessageType` 的 `Register`/`Heartbeat`/`RequestProxy`/`DataReady`/`RelayData`/`RelayEnd`/`Disconnect`。
- `NoiseStream::split`/`reunite`、`NoiseSender`、`NoiseReceiver`。
- `relay_tunneled`（`src/relay/tcp.rs`）。
- `Router` 的 `PendingDataConn`/`push_data_conn`/`get_data_conn`/`return_data_conn`（race bug 隨之消失）。

**新增**

- `src/tunnel/noise_stream.rs`（或擴充 `noise.rs`）— `NoiseByteStream`。
- `src/tunnel/session.rs` — `SessionPool`、session driver、退避。
- UDP-over-tunnel 的 client 端 stream handler。

**變更**

- `src/tunnel/protocol.rs` — 縮成 `Hello`/`StreamOpen`/`StreamReply`/UDP datagram codec。
- `src/server/tunnel_listener.rs` — Noise 握手 → `Hello` → 交給 yamux server session、登記 Router。
- `src/server/connection.rs`（`handle_connect_via_tunnel`）— 改用 `router.open_stream(...)`。
- `src/client/mod.rs` + `src/client/worker.rs` — 跑 `SessionPool`；worker 接 inbound stream、讀 preamble、dial、relay。
- `src/relay/tcp.rs` — relay 泛型化為兩個 `AsyncRead+AsyncWrite` 之間。
- `src/relay/udp.rs` — UDP ASSOCIATE 改走 tunnel。
- `src/config.rs` — 新欄位、修 secret 死欄位。

## 11. 測試策略

專案目前零整合測試，此重寫必須補上。

1. **單元**：`NoiseByteStream` 讀寫 roundtrip（含跨 65519-byte chunk 邊界）；`Hello`/`StreamOpen`/`StreamReply`/UDP datagram codec roundtrip；退避序列（注入時鐘）。
2. **整合 — stream 隔離**（核心）：同一 session 多條 stream，一條故意慢速消費，不得拖垮另一條吞吐 — 驗證 yamux flow control 確實運作。
3. **整合 — session 損失／重連**：中途砍一條 session，其 stream 報錯、倖存 session 續行、被砍 session 退避重連後新 stream 正常。
4. **整合 — 端到端**：行程內 server+client，SOCKS5 CONNECT 過 tunnel 位元組精確 echo；SOCKS5 UDP ASSOCIATE 過 tunnel datagram echo。

## 12. 建置順序

1. `NoiseByteStream` 轉接層 + 單元測試（地基）。
2. yamux session 建立 + `Hello` 握手 + `SessionPool` + 退避。
3. Server `Router` 改寫 + `tunnel_listener` 改寫 + driver task。
4. TCP proxy flow 過 yamux stream（preamble、relay）。
5. UDP-over-tunnel。
6. 整合測試 + 刪死碼 + config。

## 13. 風險與待驗證項

- **`NoiseByteStream` 的 `poll_read`/`poll_write` 狀態機**：部分 frame 讀取、剩餘 plaintext 緩衝是最易出錯處 —— 以單元測試覆蓋 chunk 邊界。
- **yamux crate 確切 API**：`Config` 旋鈕名稱、`poll_new_outbound` 在 `Mode::Server` 的可用性，實作時對 pin 住的版本最終確認。
- **記憶體上限**：`recv_window_mb × tunnel_sessions` 為最壞值；上線後依實測調整。
- **協定不相容**：`proto_version` 確保舊 client 連新 server 在第一個 round-trip 即明確報錯。專案僅 4 個 commit、無已部署用戶 → 採乾淨切換，不保留舊協定相容。

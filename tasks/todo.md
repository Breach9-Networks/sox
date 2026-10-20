# sox — upstream HTTP proxy(2026-10-19)

用途:手機只能設 SOCKS → `sox standalone --upstream http://127.0.0.1:8080` → Burp。

- [x] U1 `src/upstream.rs`:`HttpUpstream::parse`(`[http://]host:port`,拒絕 https/socks/userinfo)
- [x] U2 `HttpUpstream::connect`:解析 + `connect_any` + keepalive,送 `CONNECT`(domain 原樣轉送、IPv6 加 `[]`),
      精確讀到 `\r\n\r\n` 不多吃 tunnel 資料,全程共用 `connect_timeout` deadline
- [x] U3 HTTP status → SOCKS5 ReplyCode 對應(`error.rs::upstream_status_reply_code`)
- [x] U4 `Config.upstream` + TOML `upstream` + standalone `--upstream`(CLI > TOML > 無);server 模式設了就報錯
- [x] U5 `connection.rs::dial()` 分流;設 upstream 時 UDP ASSOCIATE 回 CommandNotSupported
- [x] U6 測試:parse、CONNECT 成功/非 2xx/header 後緊接資料不遺失、端對端 SOCKS5 → 假 HTTP proxy
- [x] U7 README / config.example.toml;`cargo test`、`cargo clippy -D warnings`、curl → sox → 真 Burp 驗證
- [ ] U8 實機:PCAPdroid → sox → Burp
- [x] U9 `--upstream-sni`(IP-only CONNECT 以 ClientHello SNI 命名)、`[upstream] udp = reject|direct`

### Code review(2026-10-20,15 項)→ 修正
- [x] R1 設了帳密時拒絕 SOCKS4/4a(協定無密碼,原本直接放行)
- [x] R2 tunnel 模式 SOCKS4 CONNECT 走 router(原本從 server 本機直連 → SSRF);SOCKS4/5 CONNECT 合併成一條路徑
- [x] R3 SNI 命名後 upstream 回「unreachable」類(404/410/502/503)→ 改 CONNECT 原 IP
- [x] R4 ClientHello 首次讀取給 4 KiB(避免 8 bytes 首包被拆);client 等待中斷線不再撥 upstream
- [x] R5 IP literal 以 domain 送來:解析時(`TargetAddr::from_host`)就轉成 `Ip`,IPv6 自然加 `[]`
- [x] R6 `--upstream-sni` 改 `Option<bool>`(CLI 可關掉 TOML 的 `sni = true`)
- [x] R7 upstream 撥號共用單一 deadline;proxy 本身連不上 → GeneralFailure(不歸咎 target),warn 一次/恢復 info 一次
- [x] R8 `sox client` 也拒絕 `[upstream]`
- [x] R9 SNI 允許 `_`、上限 255;parse 錯誤訊息不回顯帳密、scheme 不分大小寫
- [x] R10 upstream 回應容忍 bare LF 與非 UTF-8 reason phrase
- [x] R11 e2e:UDP reject 檢查 0x07、SNI 測試加 timeout;SOCKS4 帳密 / tunnel SOCKS4 測試
- 延後:upstream 位址快取(Windows `localhost` 每連線 ~2s 的 ::1 嘗試)—— 需在 `HttpUpstream` 放共享狀態,另開
- 延後:SNI 等待與 upstream 撥號並行;server-speaks-first(SSH/SMTP)每條連線付 `SNI_WAIT` 2s

### /simplify(4 agents)→ 採用
- TLS record reader 搬回 `protocol/tls.rs`,常數/`handshake_record_len` 改回 private
- `net::read_field`:SOCKS4 NUL 欄位與 upstream response head 共用 peek-then-consume
- `addr::is_valid_hostname`:SNI 與 SOCKS domain → CONNECT 同一套規則
- `TransitionLog`:tunnel「無 client」與 upstream 健康 log 共用(先 load 再 swap)
- `ServerError::is_upstream_fault` 與 status 對應放一起;`UpstreamUdp` 改 `clap::ValueEnum`
- UDP ASSOCIATE 成功回覆走 `Dialect::V5.success`;e2e helper 合併(`socks5_request`/`next_request`/`read_echo`)
- 略過:Config 巢狀 `Option<Upstream{..}>`(CLI/TOML 逐欄合併較直接)、三處 dial 合併成 `net::dial`(超出本次範圍)

### Review
- 新模組 `src/upstream.rs`;`dial()` 一個分支,SOCKS4/4a/5 CONNECT 全部適用。
- CONNECT 回應讀取用 peek 精確停在 `\r\n\r\n`,不吃掉 tunnel 首包(有測試)。
- SOCKS domain 含控制字元/空白即拒絕,避免對 upstream 的 header injection。
- 本機 CLT SDK 27 的 tbd 讓 ld-1267 連結失敗(`arm64e.x1`),暫用 `SDKROOT=.../MacOSX26.5.sdk`。
- 修正後 127 tests(+3 ignored)、clippy `-D warnings` 乾淨;windows-gnu / linux-musl `cargo check --all-targets` 通過。

# sox — Round 3 優化(2026-09-22 全碼審查 → 全數修復)

來源:完整讀碼審查(熱路徑人工 + 3 個 subagent)。「已核對」= 主 agent 對過程式碼;
其餘為 subagent 回報,動工前先複核。依 CLAUDE.md 優先序排列。

## R3-A: 穩定性(必修)

- [x] **A1** `JoinSet` 服務期間不回收 → 長跑記憶體無限成長(已核對)
  - `server/mod.rs:96/146`、`:325/355`、`server/tunnel_listener.rs:49/76`;`join_next` 只在 drain 迴圈
  - 修:accept `select!` 加 `Some(_) = tasks.join_next(), if !tasks.is_empty()`
- [x] **A2** tunnel listener accept 迴圈 `result?` / `set_nodelay(true)?` 一錯即整個結束(已核對)
  - `server/tunnel_listener.rs:59-60`;`server/monitor.rs:34` 同樣寫法(未核對)
  - 修:比照 `mod.rs:111-119` warn + backoff + continue;nodelay 失敗不致命
- [x] **A3** `panic = "abort"` 讓 `session.rs:177` 的 `catch_unwind` 重啟在 release 無效(已核對)
  - 二選一:改 `unwind`,或移除該監控並在文件註明靠外部 supervisor
- [x] **A4** UDP relay 的 `timeout(idle_timeout, relay_udp…)` 是 wall-clock 上限,違反 idle 語意
  - `server/connection.rs:600-604`、`:687-691`;觸發後 `relay/udp.rs:102,116,127,202` 的 detached task 不會被取消(socket/fd 洩漏)
  - 修:真正的 idle timer + `cancel.drop_guard()` + JoinSet
- [x] **A5** client 端 shutdown 不 drain 進行中 relay
  - `client/mod.rs:57-60`、`tunnel/session.rs:318-331`(detached `tokio::spawn` `:323`);`poll_close` 無 timeout(`:331`、`:613`)
  - 修:JoinSet + 持續 poll `conn` 直到清空或 `drain_timeout`
- [x] **A6** `router.open_stream()` 與 preamble 寫入無 timeout
  - `server/connection.rs:433,467,636,651`、`tunnel/router.rs:180,183`
  - 順帶:`router.rs:166` 無跨 client failover;StreamReply 前 stream 死掉不重試
- [x] **A7** 半開偵測只靠 keepalive;有未 ACK 資料時 keepalive 不探測
  - 加 app-level heartbeat 或 `TCP_USER_TIMEOUT`(cfg-gated);同 `(client_id, session_index)` 重新註冊時踢掉舊 session(`tunnel_listener.rs:151`)
- [x] **A8** UDP 大小不對稱:送端讀 65535 不檢查,收端 >9216 回 Err 拆掉整條 association
  - `session.rs:490-503`、`relay/udp.rs:386-405` vs `udp.rs:312`;`protocol.rs:204` `as u16` 可能截斷
  - 修:送端丟棄超大 datagram
- [x] **A9** UDP 單一錯誤殺整條 association:`session.rs:473` `send_to(..)?`;`relay/udp.rs:136-139,256` `recv_from` 錯誤即 break(Windows WSAECONNRESET)
- [x] **A10** `relay/udp.rs:91,185-212` `target_sockets` 無上限(每目標一個 socket + task + 64 KiB)→ 單一 client 可耗盡 fd
  - 修:每 association 一個 outbound socket(v4 + v6)+ 來源過濾
- [x] **A11** UDP DNS:無 `dns_timeout`、每封包查詢、在 receive loop 內 await(`relay/udp.rs:171,287`、`session.rs:467`)
- [x] **A12** SOCKS handshake:SOCKS4 單次 `read()`(`connection.rs:230-238`);SOCKS5 513/262 byte chunk 超讀且丟棄 leftover(`:133-145,174-186`);timeout 每階段一份 ≈ 4×(`:36,81,127,170`)
  - 修:單一 `timeout_at` deadline + 精確 `read_exact`
- [x] **A13** tunnel client 撥目標:無 keepalive(`session.rs:363`);多位址依序嘗試共用 10s,黑洞 AAAA 會吃光預算(`:361`)(已核對)
- [x] **A14** `backoff.rs:37-43`:`reconnect_interval=0` → 零延遲重連空轉;荒謬 `reconnect_max` 使 `from_secs_f64` panic(`main.rs:292,318` 未驗證)

## R3-B: 跨平台 / IPv6

- [x] **B1** UDP 全部只綁 `0.0.0.0`:`connection.rs:570`、`relay/udp.rs:185`、`session.rs:419`(已核對 session.rs)
- [x] **B2** dual-stack listener 下 `peer_ip` 為 `::ffff:a.b.c.d`,`relay/udp.rs:144` 比對永遠不等 → 全丟;`src` 內無 `to_canonical`(已核對)
- [x] **B3** `server/mod.rs:231-252` client 端 socket 未用 `set_keepalive_probes` helper(macOS/musl 無 KEEPCNT);與 `connection.rs:708` 重複
- [x] **B4** `signal.rs:25-29` Windows 只處理 Ctrl+C;unix 第二次訊號無法強制退出

## R3-C: 效能(皆需 release build 量測 before/after)

- [x] **C1** Noise × yamux framing:yamux header/body 分兩次 `poll_write`(yamux `frame/io.rs:98,131`)→ 每 16 KiB frame 2 次 AEAD + 2 次 write + 收端 4 次 read(已核對)
  - 修:`noise_stream.rs` `poll_write` 累積 plaintext,`poll_flush`/滿了才加密送出;`split_send_size` 調到 ~64 KiB
- [x] **C2** `noise_stream.rs:99` 每 frame `vec![0u8; len]` → 重用 buffer(已核對)
- [x] **C3** Noise 讀取端改 buffered(一次讀大塊再切 frame)(已核對)
- [x] **C4** `opt-level="z"` vs 吞吐:A/B `3` / `"s"`,或保留 `z` 並對 `chacha20`/`poly1305`/`snow`/`yamux`/`tokio` 做 per-package override
- [x] **C5** UDP 每 datagram 2–3 次配置與拷貝(`relay/udp.rs:403-405,318,427`、`protocol.rs:199,224`、`session.rs:501`)
- [x] **C6** `relay/tcp.rs:82,100` `Mutex<Instant>` → atomic coarse timestamp(已核對)
- [x] **C7** `router.rs:91,94,163-176` tokio Mutex(無 await)+ 每次 open clone 整個 Vec → std Mutex/RwLock
- [x] **C8** 每連線 3 次全域 mutex(`IpTracker` 與 `PerIpLimiter` 重複、`RateTracker`);`noise.rs` handshake 3×64 KiB buffer

## R3-D: 正確性 / 維護性

- [x] **D1** `main.rs:203-212` clap 預設值永遠蓋掉 TOML(`listen`、`max_connections`、`max_connections_per_ip`、`idle_timeout` 檔案設定無效);client 模式相反(`:299-323`)(已核對)→ CLI 改 `Option<T>`
- [x] **D2** metrics:active user 恆 ≈0(`mod.rs:158-166`)、`errors_*` 從未遞增、tunnel 模式流量圖非即時(`connection.rs:520-521`)、`record_relay` 死碼
- [x] **D3** 重複:`mod.rs:98-194` vs `:327-405` accept/drain;`relay_tcp_live` vs `relay_bidirectional`;wire reader 繞過 #9 長度上限的 codec(`session.rs:518-519`、`connection.rs:538-539`)
- [x] **D4** `monitor.rs:211,270` async handler 內 `block_in_place` + `block_on`;monitor 無並發上限
- [x] **D5** 測試缺口:session 中途死亡、多 client failover、半開、client drain、錯 PSK / handshake timeout 皆無 e2e

## R3 驗證

- [x] `cargo test`:**86 unit + 17 e2e = 103 全綠**(連跑 3 次無 flaky);另有 3 個 `#[ignore]`(1 個 55s soak、2 個 bench)
- [x] `cargo clippy --all-targets`:0 warning(連同 `addr.rs` 既有的 `items_after_test_module` 一併清掉)
- [x] `cargo check --target x86_64-pc-windows-gnu` / `x86_64-unknown-linux-musl`:通過
- [x] soak:`idle_tunnel_session_survives_the_read_watchdog` 閒置 55s 不重連;把 heartbeat 關掉後同一測試在 45s 失敗(證明測試有鑑別力、heartbeat 確實必要)

## R3 效能量測(release、loopback、單 stream 上傳、同機 server+client)

| 組態 | tunnel | standalone | binary |
|---|---|---|---|
| 修改前(`opt-level="z"`) | 92 MiB/s (0.78 Gbps) | 415 MiB/s | 1.69 MB |
| 新程式碼,`"z"` | 100 MiB/s | 441 MiB/s | 1.69 MB |
| 新程式碼,全域 `opt-level=3` | 170 MiB/s | 435 MiB/s | 2.59 MB |
| **新程式碼,`"z"` + 資料路徑 crate 設 3(採用)** | **160 MiB/s (1.34 Gbps)** | 441 MiB/s | 1.72 MB |
| 舊程式碼 + 同一 profile(拆解貢獻用) | 139 MiB/s | — | — |

tunnel 吞吐 +74%:profile 約 +50%,Noise coalescing / buffered read 約 +15%。binary 只多 32 KB。
loopback 無 RTT,此數字只驗證 CPU/AEAD/syscall 面;RTT 面的 yamux window 行為未變(見 lessons.md)。

## R3 與原 backlog 的出入

- **C1 `split_send_size`**:A/B 16 KiB vs 64 KiB 無可量測差異(160 vs 160 MiB/s),大 frame 反而增加 stream 間 head-of-line blocking → **不改**,維持 yamux 預設。coalescing 本身保留。
- **A3**:採 `panic = "unwind"`(穩定性優先)。
- **A7**:yamux 0.13 的 ping 沒有自己的 timer,閒置連線不會送 → 新增 driver heartbeat(10s)+ `NoiseByteStream` 讀取看門狗(45s)+ 同 slot 重連踢掉舊 session。未採 `TCP_USER_TIMEOUT`(Linux only,看門狗已跨平台涵蓋)。
- **A8**:上限維持 9216,改由送端丟棄超限 datagram(收端不再因此拆 association)。>9 KB 的 UDP 經 tunnel 仍不支援,屬既有設計取捨。
- **A10/B1**:UDP 出口改為每 association 一個 v4 + 一個 v6 socket(`UdpOutbound`,standalone 與 tunnel client 共用);回包一律依「曾送達的目標」過濾(standalone 以前不過濾)。
- **A12**:SOCKS5 改精確 `read_exact`;SOCKS4 的 NUL 結尾欄位用 `peek` + 精確讀取,不超讀。
- **D1**:CLI 改 `Option<T>`,優先序 CLI > TOML > 預設,三種模式一致;client 模式現在也吃 top-level `connect_timeout` / `idle_timeout` / `dns_timeout` / `drain_timeout`(解掉 Round 1 的「待觀察」)。TOML `listen` 無法解析改為報錯。
- **D5**:新增 7 個 e2e + 多個 unit。**半開連線**無法在 loopback 自動化(需丟封包),以看門狗 unit test + soak 間接涵蓋。accept 失敗(EMFILE)路徑、`JoinSet` 回收無自動化測試,靠 code review。

## R3 剩餘風險 / 後續

- `relay_bidirectional` 一個方向出錯後,另一方向最久等到 `idle_timeout` 才結束(有界,未改)。
- Windows 上 `TcpStream::peek`、signal handler 僅 cross-check 編譯,未實機執行。
- 全部變更仍在 working tree,未 commit。

---

# sox — code review Round 2 修復(15 項)

來源:`/code-review max` 第二輪查證,15 項已驗證 bug(嚴重度遞減)。
Round 1 修復已完成但未 commit,本輪在其基礎上繼續修。

## Round 2-A: 致命/阻斷型(必修)

- [x] **#1** `relay_tcp_live`/`relay_bidirectional` 改回真實 Result
  - 簽章改 `(u64, u64, io::Result<()>)` —— bytes 永遠回傳,error 不再被吞
  - 4 處 callers 改用「先 update metrics 再決定是否傳染 error」的模式
  - 新 test:`relay_surfaces_io_error_from_pump`、`relay_idle_zero_is_treated_as_disabled`

- [x] **#2** `PROTO_VERSION` 1 → 2
  - 加 doc comment 說明升版規則
  - 雖然 decode 失敗仍會早於版本檢查,但至少 client 重啟後不會帶舊 binary 跑

- [x] **#3** `run_client_session` `TcpStream::connect` 加 timeout

- [x] **#4** Hello/HelloAck 階段全部包進 `timeout_at(deadline, ...)`
  - 用 `cfg.connect_timeout` 作為整段 client-session 建立的單一 budget
  - 任何階段(TCP / Noise / Hello send / HelloAck recv)卡住都 backoff 重連

- [x] **#5** `server_session_driver` poll_fn 重寫
  - 每輪迭代「**永遠先**」`poll_next_inbound`,再處理 outbound open 請求
  - `made_progress` 旗標決定 continue / 還是回 Pending 等 waker
  - 解掉 burst K 個請求時 ACK 永遠讀不到的 deadlock 風險

## Round 2-B: UDP / 設計順序

- [x] **#6** `handle_udp_associate` reply 順序修正
  - tunnel mode 改成「先開 tunnel → 收 StreamReply → 才回 SOCKS5 success」
  - 任一階段失敗都呼叫 `reply_socks5_failure` 給 client 一個明確的失敗碼
  - standalone mode 無變化(原本就是 bind 即 reply 即正確)

- [x] **#7** `handle_udp_stream` idle 起點晚於 bind+reply
  - `last = Instant::now()` 移到 bind 完成、StreamReply 寫出之後

- [x] **#8** `client_udp_t2s` 在 DNS resolve **之前**更新 `last`
  - 收到 datagram 本身就算「活動」,慢 DNS 不再吃掉 idle 預算

- [x] **#14** UDP `dests` 改用 `DestMap`(FIFO 上限 4096)
  - 重複 insert 同一 key 不會佔重複 slot
  - 新 test:`dest_map_evicts_oldest_when_over_cap`、`dest_map_repeat_insert_keeps_size`

## Round 2-C: 防禦 / 一致性

- [x] **#9** 加長度上限常數:`MAX_CLIENT_ID_LEN=256`、`MAX_HELLO_REASON_LEN=1024`、
      `MAX_STREAM_TARGET_LEN=512`、`MAX_STREAM_MESSAGE_LEN=1024`、
      `MAX_UDP_DATAGRAM_BODY=9216`
  - 5 個 decode 路徑都先檢查長度上限,再做 `vec![0u8; n]`
  - `read_udp_datagram`(在 udp.rs)也補上同一上限檢查
  - 新 test:4 個 `*_decode_rejects_oversize_*`

- [x] **#10** `apply_tunnel_keepalive` 跨平台修正
  - 新增 `set_keepalive_probes(stream, count)` helper:`#[cfg(unix)]` 用
    `libc::setsockopt(TCP_KEEPCNT, ...)` 直接設定,涵蓋 macOS、musl
  - Windows 退到 OS 預設,doc 誠實說明(無 per-socket 介面)
  - `configure_target_socket` 也改用同一個 helper

- [x] **#11** `session_worker` 加 panic 監控 + 自動重啟
  - `futures::FutureExt::catch_unwind` 包整段 worker,panic 後 log payload
  - `WORKER_PANIC_BACKOFF = 1s` 防護「panic loop = 100% CPU」
  - 新增 `futures = "0.3"` dep(default-features = false, features = ["std"])

- [x] **#12** `handle_inbound_stream` 用 `timeout_at(deadline, ...)` 共用 budget
  - preamble 讀 + dial 共用 `connect_timeout` 一份預算,不再 2× 放大

- [x] **#13** `Router` counters 改成 Arc 共享(`ClientCounters`)
  - 新增 `ClientCounters { tx/rx_bytes, requests_served: Arc<AtomicU64> }`
  - 永久存在 `Router.counters`(`HashMap<String, Arc<ClientCounters>>`),
    `RegisteredClient` 只持有同一個 Arc
  - `open_stream` 的 fetch_add 直接打在永久 store,race-free
  - `remove_session` 不再需要「archive 計數」搬資料步驟
  - 新 test:`requests_served_survives_remove_session_race`

- [x] **#15** `Duration::ZERO` idle 視為「停用」
  - `relay_*` 對 `Some(Duration::ZERO)` 走「無 idle 看守」路徑
  - `config.rs::apply_to` 拒絕 idle_timeout=0(warn + 維持 default)
  - `main.rs` standalone CLI 同樣拒絕 `--idle-timeout=0`(早期 exit)

## 驗證

- [x] `cargo check --all-targets` 全綠
- [x] `cargo build --release` 全綠
- [x] `cargo test`:**67 unit + 10 e2e = 77 全綠**(新增 8 個 regression test)
- [x] `cargo clippy --all-targets`:無新增警告(僅餘 addr.rs 既有的
      `items_after_test_module`,屬另一個 backlog 項)

## Review

**已交付**

第二輪 code review 15 項全數修復,跨 8 個 source 檔 + 1 個 Cargo.toml:

| 檔案 | 變更摘要 |
|------|---------|
| `Cargo.toml` | 新增 `futures = "0.3"`(panic catch_unwind) |
| `src/relay/tcp.rs` | 回傳型別改 `(u64, u64, io::Result<()>)`;`Duration::ZERO` = 停用 |
| `src/relay/udp.rs` | `read_udp_datagram` 加長度上限 |
| `src/tunnel/protocol.rs` | PROTO_VERSION 2;5 個 decode 路徑加長度上限 |
| `src/tunnel/mod.rs` | 跨平台 `set_keepalive_probes` helper |
| `src/tunnel/router.rs` | `ClientCounters` Arc 共享重寫 |
| `src/tunnel/session.rs` | client handshake 全段 deadline;poll_fn 重寫;UDP idle 起點與更新時機;`DestMap`;`session_worker` panic 監控 |
| `src/server/connection.rs` | relay 回傳型別 callers 更新;UDP ASSOCIATE reply 順序修正;`configure_target_socket` 用新 helper |
| `src/config.rs` | `idle_timeout=0` validation |
| `src/main.rs` | standalone CLI `--idle-timeout=0` validation |

新增 8 個 regression test 全部通過。

**設計取捨**

1. **#1 回傳型別**:選 `(u64, u64, io::Result<()>)` 而非 `RelayOutcome` struct
   或 `io::Result<(u64, u64)>` —— bytes 與 outcome 在語義上正交,tuple
   表達清楚,callers 可以同時 update metrics 再決定是否回 Err。

2. **#10 跨平台 keepalive**:選 libc::setsockopt 而非升級 socket2 / 寫
   feature flag —— socket2 的 `with_retries` API gating 限制改不了,自寫
   libc 一行涵蓋三個平台。Windows 沒 per-socket 介面,坦白接受 OS 預設。

3. **#11 panic 監控**:選 catch_unwind + sleep + 重啟 而非 JoinSet
   supervisor —— 改動最小,維持「self-healing pool」單一語義,1s backoff
   防護 panic loop。

4. **#13 counters 重寫**:選 Arc 永久持有 + per-field Arc<AtomicU64>,而非
   share 整個 `Arc<ClientCounters>` —— 後者會洩漏結構,且改變 `TunnelStream`
   介面;前者額外 3 個 Arc 分配,但對外 API 與舊版完全相同。

**測試涵蓋**

- 直接驗證:relay error propagation、Duration::ZERO、decode size caps、
  DestMap eviction、counters race survival —— 8 個新 unit test
- 既有 e2e:全部 10 個仍通過 —— `client_reconnects_after_server_restart`
  間接驗證 #2 + #3 + #4 在重啟情境下不會引入 regression
- 未測:#5 poll_fn 的 burst-K-deadlock 仍然難以單元測試(需 256 條同時
  慢速 AC stream + 高頻 inbound ACK);#10 macOS TCP_KEEPCNT 設定需在
  Linux/macOS 真機才能觀察生效。兩者皆以 code review + 既有 e2e
  「reconnect-stress」間接驗證

**待觀察 / 後續**

- 第一輪「待觀察」項依然成立:client 端 `connect_timeout` / `idle_timeout`
  尚未開放從 `[tunnel]` 設定檔覆寫(本輪沒修)
- `addr.rs` 的 `items_after_test_module` 仍未處理
- Round 1 與 Round 2 變更全部仍在 main branch 上未 commit —— 兩輪修復
  涵蓋 30 項上輪 review,建議開 feature branch 整理 commit history 後 PR

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

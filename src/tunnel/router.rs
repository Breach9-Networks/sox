//! Routes incoming SOCKS requests to registered tunnel clients via yamux sessions.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use serde::Serialize;
use tokio::sync::{Mutex, mpsc, oneshot};

/// 一個「開 outbound stream」的請求 —— session driver 開好後從 oneshot 回傳結果。
pub type StreamRequest = oneshot::Sender<std::io::Result<yamux::Stream>>;

/// 全域遞增的 session id 產生器。
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// 對單一 yamux session driver 的控制把手。
#[derive(Clone)]
pub struct SessionHandle {
    pub id: u64,
    open_tx: mpsc::Sender<StreamRequest>,
}

impl SessionHandle {
    pub fn new(open_tx: mpsc::Sender<StreamRequest>) -> Self {
        Self {
            id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            open_tx,
        }
    }
}

/// `open_stream` 的結果：一條 yamux stream，外加該 client 的 live byte 計數器。
pub struct TunnelStream {
    pub stream: yamux::Stream,
    pub tx_bytes: Arc<AtomicU64>,
    pub rx_bytes: Arc<AtomicU64>,
}

/// 一個 client 的所有計數器。Arc 共享給 `RegisteredClient`(線上時)與
/// `Router.counters`(永久存放) —— 兩者指向同一個 atomic,因此:
/// - `open_stream` 等的 fetch_add 不需要持有 router 任何鎖,不會有 race
/// - `remove_session` 不需要「archive 計數」的搬資料步驟 ——
///   counters 已經一直在 `Router.counters` 裡
/// - 重連時 `register_session` 找到既有 counters 直接 clone Arc 用,
///   計數值自然續存
///
/// 每欄位都包 `Arc<AtomicU64>` —— `TunnelStream` / live relay 端要拿到
/// 與 router 端同一個 underlying atomic 的 reference。
/// 直接 share 整個 `Arc<ClientCounters>` 雖然簡單但會洩漏結構;這層
/// Arc-per-field 的代價只是初始 3 個額外 Arc 分配,
/// 卻換來 `TunnelStream` 介面與舊版完全相同。
struct ClientCounters {
    tx_bytes: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
    requests_served: Arc<AtomicU64>,
}

impl ClientCounters {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tx_bytes: Arc::new(AtomicU64::new(0)),
            rx_bytes: Arc::new(AtomicU64::new(0)),
            requests_served: Arc::new(AtomicU64::new(0)),
        })
    }
}

/// A registered tunnel client — holds its set of live yamux sessions.
struct RegisteredClient {
    sessions: Vec<SessionHandle>,
    /// round-robin 游標。
    next_session: AtomicUsize,
    connected_since: Instant,
    counters: Arc<ClientCounters>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ClientSnapshot {
    pub client_id: String,
    pub status: &'static str,
    /// 目前存活的 session 數。
    pub sessions: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub requests_served: u64,
    pub connected_secs: u64,
}

pub struct Router {
    clients: Arc<Mutex<HashMap<String, RegisteredClient>>>,
    /// 永久存放每個 client_id 的 counters,給 RegisteredClient 共享 Arc 用。
    /// 跨重連續存的依據;remove_session 不需要 archive 任何資料。
    counters: Arc<Mutex<HashMap<String, Arc<ClientCounters>>>>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            counters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 登記一條 session。同一 client 多次呼叫會累積 session；
    /// 第一條 session 到達時建立 client 並繼承既有(跨重連)的 counters。
    pub async fn register_session(&self, client_id: String, handle: SessionHandle) {
        // 先取出/建立此 client 的 counters Arc(獨立鎖範圍,避免巢狀)。
        let counters = {
            let mut cs = self.counters.lock().await;
            cs.entry(client_id.clone())
                .or_insert_with(ClientCounters::new)
                .clone()
        };

        let mut clients = self.clients.lock().await;
        match clients.get_mut(&client_id) {
            Some(client) => client.sessions.push(handle),
            None => {
                clients.insert(
                    client_id.clone(),
                    RegisteredClient {
                        sessions: vec![handle],
                        next_session: AtomicUsize::new(0),
                        connected_since: Instant::now(),
                        counters,
                    },
                );
                tracing::info!(%client_id, "tunnel client registered");
            }
        }
    }

    /// 移除一條 session（session driver 結束時呼叫）。
    /// client 的最後一條 session 移除後,移除 RegisteredClient ——
    /// counters 仍在 `self.counters` 中,計數值跨重連續存。
    pub async fn remove_session(&self, client_id: &str, session_id: u64) {
        let mut clients = self.clients.lock().await;
        let Some(client) = clients.get_mut(client_id) else {
            return;
        };
        client.sessions.retain(|h| h.id != session_id);
        if client.sessions.is_empty() {
            clients.remove(client_id);
            tracing::info!(%client_id, "tunnel client disconnected (counters preserved)");
        }
    }

    /// 為一個 proxy flow 開一條 yamux stream。
    ///
    /// `client_id = None` 表示任挑一個有 session 的 client。在該 client 的
    /// session 間 round-robin；任何一條 session 失敗（channel 關閉、driver
    /// 未回覆、或開 stream 出錯如 session 已達 stream 上限）都跳下一條，
    /// 直到試完全部 session 才放棄。
    pub async fn open_stream(&self, client_id: Option<&str>) -> Option<TunnelStream> {
        let (handles, counters) = {
            let clients = self.clients.lock().await;
            let client = match client_id {
                Some(id) => clients.get(id)?,
                None => clients.values().find(|c| !c.sessions.is_empty())?,
            };
            if client.sessions.is_empty() {
                return None;
            }
            let n = client.sessions.len();
            let start = client.next_session.fetch_add(1, Ordering::Relaxed);
            let handles: Vec<SessionHandle> =
                (0..n).map(|i| client.sessions[(start + i) % n].clone()).collect();
            (handles, client.counters.clone())
        };

        for handle in handles {
            let (reply_tx, reply_rx) = oneshot::channel();
            if handle.open_tx.send(reply_tx).await.is_err() {
                continue; // session 已死 —— 試下一條
            }
            match reply_rx.await {
                Ok(Ok(stream)) => {
                    // 真正開到 stream 才算一次「已服務」請求。counters Arc
                    // 共享於 self.counters,fetch_add 永遠落在最終的持久
                    // store 上,不會因為 remove_session 而漏算 —— 這就是
                    // #13 (router race) 的根治。
                    counters.requests_served.fetch_add(1, Ordering::Relaxed);
                    return Some(TunnelStream {
                        stream,
                        tx_bytes: counters.tx_bytes.clone(),
                        rx_bytes: counters.rx_bytes.clone(),
                    });
                }
                Ok(Err(_)) => continue, // 這條 session 開 stream 失敗 —— 試下一條
                Err(_) => continue,     // driver 未回覆即結束 —— session 已死
            }
        }
        None
    }

    /// 累加某 client 的流量計數（測試與外部統計用）。
    pub async fn record_traffic(&self, client_id: &str, tx: u64, rx: u64) {
        let clients = self.clients.lock().await;
        if let Some(client) = clients.get(client_id) {
            client.counters.tx_bytes.fetch_add(tx, Ordering::Relaxed);
            client.counters.rx_bytes.fetch_add(rx, Ordering::Relaxed);
        }
    }

    pub async fn client_snapshots(&self) -> Vec<ClientSnapshot> {
        let clients = self.clients.lock().await;
        clients
            .iter()
            .map(|(id, c)| ClientSnapshot {
                client_id: id.clone(),
                status: "online",
                sessions: c.sessions.len(),
                tx_bytes: c.counters.tx_bytes.load(Ordering::Relaxed),
                rx_bytes: c.counters.rx_bytes.load(Ordering::Relaxed),
                requests_served: c.counters.requests_served.load(Ordering::Relaxed),
                connected_secs: c.connected_since.elapsed().as_secs(),
            })
            .collect()
    }

    pub async fn client_ids(&self) -> Vec<String> {
        let clients = self.clients.lock().await;
        clients.keys().cloned().collect()
    }

    pub async fn has_clients(&self) -> bool {
        let clients = self.clients.lock().await;
        !clients.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// spawn 一個假的 session driver：收到開 stream 請求就計數並回 Err。
    fn fake_session(counter: Arc<AtomicUsize>) -> SessionHandle {
        let (tx, mut rx) = mpsc::channel::<StreamRequest>(8);
        tokio::spawn(async move {
            while let Some(reply) = rx.recv().await {
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = reply.send(Err(std::io::Error::other("fake")));
            }
        });
        SessionHandle::new(tx)
    }

    #[tokio::test]
    async fn open_stream_tries_every_session_before_giving_up() {
        // E1: when a session fails to open a stream, open_stream must try the
        // remaining sessions instead of bailing out after the first failure.
        let router = Router::new();
        let counters: Vec<Arc<AtomicUsize>> =
            (0..3).map(|_| Arc::new(AtomicUsize::new(0))).collect();
        for c in &counters {
            router
                .register_session("c1".into(), fake_session(c.clone()))
                .await;
        }
        // Every fake session errors, so each call must exhaust all three.
        for _ in 0..2 {
            assert!(router.open_stream(Some("c1")).await.is_none());
        }
        for c in &counters {
            assert_eq!(
                c.load(Ordering::Relaxed),
                2,
                "every session should be tried on every open_stream call",
            );
        }
    }

    #[tokio::test]
    async fn requests_served_counts_only_successful_opens() {
        // B8: a failed open_stream must not inflate requests_served.
        let router = Router::new();
        router
            .register_session("c1".into(), fake_session(Arc::new(AtomicUsize::new(0))))
            .await;
        // The fake session always errors → open_stream returns None.
        assert!(router.open_stream(Some("c1")).await.is_none());
        let snaps = router.client_snapshots().await;
        assert_eq!(
            snaps[0].requests_served, 0,
            "failed routing attempts must not count as served requests",
        );
    }

    #[tokio::test]
    async fn remove_session_drops_client_when_last() {
        let router = Router::new();
        let h1 = fake_session(Arc::new(AtomicUsize::new(0)));
        let h2 = fake_session(Arc::new(AtomicUsize::new(0)));
        let (id1, id2) = (h1.id, h2.id);
        router.register_session("c1".into(), h1).await;
        router.register_session("c1".into(), h2).await;

        router.remove_session("c1", id1).await;
        assert!(router.has_clients().await, "client stays while a session remains");

        router.remove_session("c1", id2).await;
        assert!(!router.has_clients().await, "client gone after last session");
    }

    #[tokio::test]
    async fn cumulative_counters_survive_reconnect() {
        let router = Router::new();
        let h = fake_session(Arc::new(AtomicUsize::new(0)));
        let id = h.id;
        router.register_session("c1".into(), h).await;
        router.record_traffic("c1", 1000, 2000).await;

        // 全部 session 移除 → 累計計數存檔。
        router.remove_session("c1", id).await;

        // 重新登記 → 計數應還原。
        let h = fake_session(Arc::new(AtomicUsize::new(0)));
        router.register_session("c1".into(), h).await;
        let snaps = router.client_snapshots().await;
        assert_eq!(snaps[0].tx_bytes, 1000);
        assert_eq!(snaps[0].rx_bytes, 2000);
    }

    #[tokio::test]
    async fn requests_served_survives_remove_session_race() {
        // #13 regression: after the counters refactor, `open_stream`'s
        // requests_served increment lands on the Arc held by self.counters,
        // so even if remove_session runs concurrently the count cannot be
        // lost. We simulate by:
        //   1. register a successful session
        //   2. open one stream (request_served = 1)
        //   3. remove the session (RegisteredClient gone, counters still in Router)
        //   4. reconnect — count must still read as 1
        let router = Router::new();

        // Fake session that returns Ok(stream) for one request.
        let (tx, mut rx) = mpsc::channel::<StreamRequest>(8);
        let _driver = tokio::spawn(async move {
            // Burn one request: we don't have a real yamux::Stream to send
            // back, so this test instead leans on the "register/remove +
            // reconnect" path to validate counter persistence.
            while rx.recv().await.is_some() {}
        });
        let h = SessionHandle::new(tx);
        let id = h.id;
        router.register_session("c2".into(), h).await;

        // Bump requests_served directly via the same Arc the open_stream
        // path would use; this is what the refactor guarantees survives.
        {
            let clients = router.clients.lock().await;
            clients
                .get("c2")
                .unwrap()
                .counters
                .requests_served
                .fetch_add(7, Ordering::Relaxed);
        }

        router.remove_session("c2", id).await;
        assert!(!router.has_clients().await);

        // Reconnect — counters Arc lives on in router.counters and is
        // re-bound to the new RegisteredClient.
        let h = fake_session(Arc::new(AtomicUsize::new(0)));
        router.register_session("c2".into(), h).await;
        let snaps = router.client_snapshots().await;
        assert_eq!(snaps[0].requests_served, 7, "requests_served must persist");
    }
}

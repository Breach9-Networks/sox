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

/// A registered tunnel client — holds its set of live yamux sessions.
struct RegisteredClient {
    sessions: Vec<SessionHandle>,
    /// round-robin 游標。
    next_session: AtomicUsize,
    connected_since: Instant,
    tx_bytes: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
    requests_served: AtomicU64,
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

/// Cumulative counters that survive client reconnects.
struct CumulativeCounters {
    tx_bytes: u64,
    rx_bytes: u64,
    requests_served: u64,
}

pub struct Router {
    clients: Arc<Mutex<HashMap<String, RegisteredClient>>>,
    /// Persisted across reconnects — accumulated when a client fully disconnects.
    cumulative: Arc<Mutex<HashMap<String, CumulativeCounters>>>,
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
            cumulative: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 登記一條 session。同一 client 多次呼叫會累積 session；
    /// 第一條 session 到達時建立 client 並還原累計流量計數。
    pub async fn register_session(&self, client_id: String, handle: SessionHandle) {
        // 先在獨立的鎖範圍讀累計計數，避免巢狀鎖。
        let (prev_tx, prev_rx, prev_reqs) = {
            let cum = self.cumulative.lock().await;
            cum.get(&client_id)
                .map(|c| (c.tx_bytes, c.rx_bytes, c.requests_served))
                .unwrap_or((0, 0, 0))
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
                        tx_bytes: Arc::new(AtomicU64::new(prev_tx)),
                        rx_bytes: Arc::new(AtomicU64::new(prev_rx)),
                        requests_served: AtomicU64::new(prev_reqs),
                    },
                );
                tracing::info!(%client_id, "tunnel client registered");
            }
        }
    }

    /// 移除一條 session（session driver 結束時呼叫）。
    /// client 的最後一條 session 移除後，client 整體下線、累計計數存檔。
    pub async fn remove_session(&self, client_id: &str, session_id: u64) {
        let mut clients = self.clients.lock().await;
        let Some(client) = clients.get_mut(client_id) else {
            return;
        };
        client.sessions.retain(|h| h.id != session_id);
        if client.sessions.is_empty() {
            let removed = clients.remove(client_id).unwrap();
            let mut cum = self.cumulative.lock().await;
            cum.insert(
                client_id.to_string(),
                CumulativeCounters {
                    tx_bytes: removed.tx_bytes.load(Ordering::Relaxed),
                    rx_bytes: removed.rx_bytes.load(Ordering::Relaxed),
                    requests_served: removed.requests_served.load(Ordering::Relaxed),
                },
            );
            tracing::info!(%client_id, "tunnel client disconnected (counters preserved)");
        }
    }

    /// 為一個 proxy flow 開一條 yamux stream。
    ///
    /// `client_id = None` 表示任挑一個有 session 的 client。在該 client 的
    /// session 間 round-robin；某條 session 已死（channel 關閉）就跳下一條。
    pub async fn open_stream(&self, client_id: Option<&str>) -> Option<TunnelStream> {
        let (handles, tx_bytes, rx_bytes) = {
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
            client.requests_served.fetch_add(1, Ordering::Relaxed);
            (handles, client.tx_bytes.clone(), client.rx_bytes.clone())
        };

        for handle in handles {
            let (reply_tx, reply_rx) = oneshot::channel();
            if handle.open_tx.send(reply_tx).await.is_err() {
                continue; // session 已死 —— 試下一條
            }
            match reply_rx.await {
                Ok(Ok(stream)) => {
                    return Some(TunnelStream {
                        stream,
                        tx_bytes: tx_bytes.clone(),
                        rx_bytes: rx_bytes.clone(),
                    });
                }
                Ok(Err(_)) => return None, // 開 stream 失敗 —— 不重試其他 session
                Err(_) => continue,        // driver 未回覆即結束 —— session 已死
            }
        }
        None
    }

    /// 累加某 client 的流量計數（測試與外部統計用）。
    pub async fn record_traffic(&self, client_id: &str, tx: u64, rx: u64) {
        let clients = self.clients.lock().await;
        if let Some(client) = clients.get(client_id) {
            client.tx_bytes.fetch_add(tx, Ordering::Relaxed);
            client.rx_bytes.fetch_add(rx, Ordering::Relaxed);
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
                tx_bytes: c.tx_bytes.load(Ordering::Relaxed),
                rx_bytes: c.rx_bytes.load(Ordering::Relaxed),
                requests_served: c.requests_served.load(Ordering::Relaxed),
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
    async fn open_stream_round_robins_sessions() {
        let router = Router::new();
        let counters: Vec<Arc<AtomicUsize>> =
            (0..3).map(|_| Arc::new(AtomicUsize::new(0))).collect();
        for c in &counters {
            router
                .register_session("c1".into(), fake_session(c.clone()))
                .await;
        }
        // open_stream 等待 driver 回覆 → 回傳時該 session 必已計數。
        for _ in 0..6 {
            assert!(router.open_stream(Some("c1")).await.is_none());
        }
        for c in &counters {
            assert_eq!(c.load(Ordering::Relaxed), 2, "each session should get 2 requests");
        }
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
}

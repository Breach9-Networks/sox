//! Routes incoming SOCKS requests to registered tunnel clients via connection pool.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::tunnel::noise::NoiseStream;

/// A pending data connection from a pool worker.
pub struct PendingDataConn {
    pub noise: NoiseStream,
    /// Sent () when the connection is taken — keeps the server-side handler alive.
    pub assign_tx: oneshot::Sender<()>,
}

/// A registered tunnel client.
pub struct RegisteredClient {
    /// Receive pending data connections from pool workers.
    pub data_conns: mpsc::Receiver<PendingDataConn>,
    /// Send side (held by tunnel_listener to push incoming data connections).
    pub data_conn_tx: mpsc::Sender<PendingDataConn>,
    pub pool_size: u16,
    pub connected_since: Instant,
    pub tx_bytes: Arc<AtomicU64>,
    pub rx_bytes: Arc<AtomicU64>,
    pub requests_served: AtomicU64,
}

#[derive(Debug, Serialize, Clone)]
pub struct ClientSnapshot {
    pub client_id: String,
    pub status: &'static str,
    pub pool_size: u16,
    pub pool_ready: usize,
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
    /// Persisted across reconnects — accumulated when client unregisters.
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

    /// Register a client. Returns a Sender for pushing PendingDataConns.
    pub async fn register(
        &self,
        client_id: String,
        pool_size: u16,
    ) -> mpsc::Sender<PendingDataConn> {
        let (tx, rx) = mpsc::channel(256);

        // Load cumulative counters from previous sessions
        let (prev_tx, prev_rx, prev_reqs) = {
            let cum = self.cumulative.lock().await;
            cum.get(&client_id)
                .map(|c| (c.tx_bytes, c.rx_bytes, c.requests_served))
                .unwrap_or((0, 0, 0))
        };

        let client = RegisteredClient {
            data_conns: rx,
            data_conn_tx: tx.clone(),
            pool_size,
            connected_since: Instant::now(),
            tx_bytes: Arc::new(AtomicU64::new(prev_tx)),
            rx_bytes: Arc::new(AtomicU64::new(prev_rx)),
            requests_served: AtomicU64::new(prev_reqs),
        };

        let mut clients = self.clients.lock().await;
        clients.insert(client_id.clone(), client);
        tracing::info!(%client_id, %pool_size, "client registered");

        tx
    }

    pub async fn unregister(&self, client_id: &str) {
        let mut clients = self.clients.lock().await;
        if let Some(old) = clients.remove(client_id) {
            // Save cumulative counters for reconnection
            let mut cum = self.cumulative.lock().await;
            cum.insert(client_id.to_string(), CumulativeCounters {
                tx_bytes: old.tx_bytes.load(Ordering::Relaxed),
                rx_bytes: old.rx_bytes.load(Ordering::Relaxed),
                requests_served: old.requests_served.load(Ordering::Relaxed),
            });
            tracing::info!(%client_id, "client unregistered (counters preserved)");
        }
    }

    /// Get a data connection for a proxy request.
    /// Returns (client_id, NoiseStream, client_tx_counter, client_rx_counter).
    pub async fn get_data_conn(
        &self,
        client_id: Option<&str>,
    ) -> Option<(String, NoiseStream, Arc<AtomicU64>, Arc<AtomicU64>)> {
        let mut clients = self.clients.lock().await;

        let target_ids: Vec<String> = if let Some(id) = client_id {
            if clients.contains_key(id) {
                vec![id.to_string()]
            } else {
                return None;
            }
        } else {
            clients.keys().cloned().collect()
        };

        for id in &target_ids {
            if let Some(client) = clients.get_mut(id) {
                if let Ok(pending) = client.data_conns.try_recv() {
                    client.requests_served.fetch_add(1, Ordering::Relaxed);
                    let _ = pending.assign_tx.send(());
                    let tx = client.tx_bytes.clone();
                    let rx = client.rx_bytes.clone();
                    return Some((id.clone(), pending.noise, tx, rx));
                }
            }
        }
        None
    }

    /// Push a data connection into the pool for a client.
    /// Returns a oneshot::Receiver that the caller must await to keep the connection alive.
    pub async fn push_data_conn(
        &self,
        client_id: &str,
        noise: NoiseStream,
    ) -> Result<oneshot::Receiver<()>, std::io::Error> {
        // Clone the sender and release the lock before awaiting send()
        let data_conn_tx = {
            let clients = self.clients.lock().await;
            let client = clients.get(client_id).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("client {client_id} not registered"),
                )
            })?;
            client.data_conn_tx.clone()
        }; // lock released here

        let (assign_tx, assign_rx) = oneshot::channel();
        let pending = PendingDataConn { noise, assign_tx };

        data_conn_tx.send(pending).await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "data conn channel closed",
            )
        })?;

        Ok(assign_rx)
    }

    /// Return a used data connection to the pool for reuse.
    /// Called by the SOCKS handler after relay completes cleanly.
    pub async fn return_data_conn(
        &self,
        client_id: &str,
        noise: NoiseStream,
    ) -> Result<(), std::io::Error> {
        let data_conn_tx = {
            let clients = self.clients.lock().await;
            let client = clients.get(client_id).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("client {client_id} not registered"),
                )
            })?;
            client.data_conn_tx.clone()
        }; // lock released here

        let (assign_tx, _assign_rx) = oneshot::channel();
        let pending = PendingDataConn { noise, assign_tx };

        data_conn_tx.send(pending).await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "data conn channel closed",
            )
        })?;

        tracing::trace!(%client_id, "data connection returned to pool");
        Ok(())
    }

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
                pool_size: c.pool_size,
                pool_ready: c.data_conns.len(),
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

    #[tokio::test]
    async fn test_register_unregister() {
        let router = Router::new();
        let _tx = router.register("client-1".into(), 4).await;

        let ids = router.client_ids().await;
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "client-1");
        assert!(router.has_clients().await);

        router.unregister("client-1").await;

        let ids = router.client_ids().await;
        assert!(ids.is_empty());
        assert!(!router.has_clients().await);
    }

    #[tokio::test]
    async fn test_cumulative_counters_preserved() {
        let router = Router::new();
        let _tx = router.register("client-1".into(), 4).await;

        // Record some traffic
        router.record_traffic("client-1", 1000, 2000).await;

        // Verify traffic is recorded
        let snaps = router.client_snapshots().await;
        assert_eq!(snaps[0].tx_bytes, 1000);
        assert_eq!(snaps[0].rx_bytes, 2000);

        // Unregister (saves cumulative counters)
        router.unregister("client-1").await;

        // Re-register — counters should be restored
        let _tx = router.register("client-1".into(), 4).await;
        let snaps = router.client_snapshots().await;
        assert_eq!(snaps[0].tx_bytes, 1000);
        assert_eq!(snaps[0].rx_bytes, 2000);

        // Record more traffic — should add to preserved counters
        router.record_traffic("client-1", 500, 300).await;
        let snaps = router.client_snapshots().await;
        assert_eq!(snaps[0].tx_bytes, 1500);
        assert_eq!(snaps[0].rx_bytes, 2300);
    }

    #[tokio::test]
    async fn test_client_snapshots() {
        let router = Router::new();
        let _tx = router.register("node-a".into(), 8).await;

        let snaps = router.client_snapshots().await;
        assert_eq!(snaps.len(), 1);

        let snap = &snaps[0];
        assert_eq!(snap.client_id, "node-a");
        assert_eq!(snap.status, "online");
        assert_eq!(snap.pool_size, 8);
        assert_eq!(snap.tx_bytes, 0);
        assert_eq!(snap.rx_bytes, 0);
        assert_eq!(snap.requests_served, 0);
    }
}

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Bidirectional TCP relay with explicit half-close handling
/// and live byte counting.
///
/// Returns `(client_to_server_bytes, server_to_client_bytes)`.
pub async fn relay_tcp(
    client: &mut TcpStream,
    server: &mut TcpStream,
) -> io::Result<(u64, u64)> {
    relay_tcp_live(client, server, None, None).await
}

/// Relay with live atomic counters that external code can observe
/// during the relay (e.g., for traffic charts).
pub async fn relay_tcp_live(
    client: &mut TcpStream,
    server: &mut TcpStream,
    live_tx: Option<&AtomicU64>,
    live_rx: Option<&AtomicU64>,
) -> io::Result<(u64, u64)> {
    let (mut cr, mut cw) = client.split();
    let (mut sr, mut sw) = server.split();

    // Shared counters so we can read totals even if try_join errors
    let tx_total = Arc::new(AtomicU64::new(0));
    let rx_total = Arc::new(AtomicU64::new(0));

    let tx_total_c = tx_total.clone();
    let rx_total_c = rx_total.clone();

    let c2s = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                sw.shutdown().await?;
                break;
            }
            sw.write_all(&buf[..n]).await?;
            tx_total_c.fetch_add(n as u64, Ordering::Relaxed);
            if let Some(counter) = live_tx {
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        Ok::<(), io::Error>(())
    };

    let s2c = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = sr.read(&mut buf).await?;
            if n == 0 {
                cw.shutdown().await?;
                break;
            }
            cw.write_all(&buf[..n]).await?;
            rx_total_c.fetch_add(n as u64, Ordering::Relaxed);
            if let Some(counter) = live_rx {
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        Ok::<(), io::Error>(())
    };

    // Even if one side errors, we still have accurate byte counts
    let _ = tokio::try_join!(c2s, s2c);

    let tx = tx_total.load(Ordering::Relaxed);
    let rx = rx_total.load(Ordering::Relaxed);
    Ok((tx, rx))
}

/// 在任兩個雙向串流間 relay，附 live byte 計數。
/// 回傳 `(a→b bytes, b→a bytes)`。
///
/// 用 `join!`（非 `try_join!`）讓兩個方向都跑完 —— `try_join!` 會在
/// 一邊出錯時中途取消另一邊，可能留下半寫的 frame。
pub async fn relay_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    live_ab: Option<&AtomicU64>,
    live_ba: Option<&AtomicU64>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let ab_total = Arc::new(AtomicU64::new(0));
    let ba_total = Arc::new(AtomicU64::new(0));
    let ab_c = ab_total.clone();
    let ba_c = ba_total.clone();

    let a_to_b = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = ar.read(&mut buf).await?;
            if n == 0 {
                bw.shutdown().await?;
                break;
            }
            bw.write_all(&buf[..n]).await?;
            ab_c.fetch_add(n as u64, Ordering::Relaxed);
            if let Some(c) = live_ab {
                c.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        Ok::<(), io::Error>(())
    };
    let b_to_a = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = br.read(&mut buf).await?;
            if n == 0 {
                aw.shutdown().await?;
                break;
            }
            aw.write_all(&buf[..n]).await?;
            ba_c.fetch_add(n as u64, Ordering::Relaxed);
            if let Some(c) = live_ba {
                c.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        Ok::<(), io::Error>(())
    };

    let _ = tokio::join!(a_to_b, b_to_a);
    Ok((ab_total.load(Ordering::Relaxed), ba_total.load(Ordering::Relaxed)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn relay_copies_both_directions() {
        let (mut a, mut a_outer) = duplex(1024);
        let (mut b, mut b_outer) = duplex(1024);

        let relay = tokio::spawn(async move {
            relay_bidirectional(&mut a, &mut b, None, None).await
        });

        a_outer.write_all(b"ping").await.unwrap();
        a_outer.shutdown().await.unwrap();
        let mut got = Vec::new();
        b_outer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");

        b_outer.shutdown().await.unwrap();
        let (tx, _rx) = relay.await.unwrap().unwrap();
        assert_eq!(tx, 4);
    }
}

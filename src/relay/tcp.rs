use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::tunnel::noise::{NoiseSender, NoiseReceiver};

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

/// Bidirectional relay through a Noise tunnel using framed messages.
///
/// `sender`/`receiver` are the split halves of the tunnel NoiseStream.
/// `local` is the local TCP stream (SOCKS client on server side, target on client side).
///
/// "tx" = local → tunnel, "rx" = tunnel → local.
pub async fn relay_tunneled(
    sender: &mut NoiseSender,
    receiver: &mut NoiseReceiver,
    local: &mut TcpStream,
    live_tx: Option<&AtomicU64>,
    live_rx: Option<&AtomicU64>,
) -> io::Result<(u64, u64)> {
    let (mut local_reader, mut local_writer) = local.split();

    let tx_total = Arc::new(AtomicU64::new(0));
    let rx_total = Arc::new(AtomicU64::new(0));
    let tx_total_c = tx_total.clone();
    let rx_total_c = rx_total.clone();

    // local → tunnel: read from local, send as RelayData through Noise
    // Pre-allocate send buffer: [type_byte | data]. Avoids per-chunk Vec allocation.
    let local_to_tunnel = async {
        let mut buf = [0u8; 1 + 16384]; // type byte + data
        buf[0] = 0x10; // MessageType::RelayData
        loop {
            let n = local_reader.read(&mut buf[1..]).await?;
            if n == 0 {
                // Local side EOF — send RelayEnd
                sender.send(&[0x11]).await?; // MessageType::RelayEnd
                break;
            }
            sender.send(&buf[..1 + n]).await?;
            tx_total_c.fetch_add(n as u64, Ordering::Relaxed);
            if let Some(counter) = live_tx {
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        Ok::<(), io::Error>(())
    };

    // tunnel → local: receive from Noise, write to local
    let tunnel_to_local = async {
        loop {
            let plaintext = receiver.recv().await?;
            if plaintext.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "empty tunnel message"));
            }
            match plaintext[0] {
                0x10 => { // RelayData
                    let data = &plaintext[1..];
                    if data.is_empty() {
                        continue;
                    }
                    local_writer.write_all(data).await?;
                    rx_total_c.fetch_add(data.len() as u64, Ordering::Relaxed);
                    if let Some(counter) = live_rx {
                        counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                }
                0x11 => { // RelayEnd
                    local_writer.shutdown().await?;
                    break;
                }
                other => {
                    tracing::warn!(msg_type = other, "unexpected message during relay");
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected message type during relay: {other:#x}"),
                    ));
                }
            }
        }
        Ok::<(), io::Error>(())
    };

    // Use join! (not try_join!) so both directions run to completion.
    // try_join! cancels the surviving future mid-operation, which can leave
    // a Noise frame half-written and permanently corrupt the stream.
    // This is critical for WebSocket and other long-lived connections where
    // one side closing normally causes a write error on the other side.
    let (r1, r2) = tokio::join!(local_to_tunnel, tunnel_to_local);

    if let Err(e) = &r1 {
        tracing::trace!(error = %e, "relay local→tunnel ended with error");
    }
    if let Err(e) = &r2 {
        tracing::trace!(error = %e, "relay tunnel→local ended with error");
    }

    let tx = tx_total.load(Ordering::Relaxed);
    let rx = rx_total.load(Ordering::Relaxed);
    Ok((tx, rx))
}

//! Handles proxy requests on NoiseStream-based data connections.

use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::relay::tcp::relay_tunneled;
use crate::tunnel::noise::NoiseStream;
use crate::tunnel::protocol::TunnelMessage;

/// Handle a single proxy request on an existing NoiseStream.
/// Returns the NoiseStream on success for reuse, or an error if the connection is broken.
pub async fn handle_data_connection(
    mut noise: NoiseStream,
    cancel: CancellationToken,
) -> Result<NoiseStream, std::io::Error> {
    // 1. Receive ProxyRequest
    let data = tokio::select! {
        _ = cancel.cancelled() => return Ok(noise),
        result = noise.recv() => result?,
    };

    let msg = TunnelMessage::decode(&data).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}"))
    })?;

    let (request_id, target) = match msg {
        TunnelMessage::ProxyRequest { request_id, target } => (request_id, target),
        other => {
            tracing::debug!(msg = ?other, "expected ProxyRequest");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected ProxyRequest",
            ));
        }
    };

    tracing::debug!(request_id, %target, "proxy request received");

    // 2. Connect to target
    match TcpStream::connect(&target).await {
        Ok(mut target_stream) => {
            target_stream.set_nodelay(true)?;

            let bind_addr = target_stream
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_default();

            // 3. Send ProxyReply (success)
            let reply = TunnelMessage::ProxyReply {
                request_id,
                success: true,
                message: bind_addr,
            };
            noise.send(&reply.encode()).await?;

            tracing::debug!(request_id, %target, "connected, starting relay");

            // 4. Split NoiseStream for concurrent bidirectional relay
            let (mut sender, mut receiver) = noise.split();

            // 5. Relay traffic through framed Noise tunnel
            let relay_result = relay_tunneled(
                &mut sender,
                &mut receiver,
                &mut target_stream,
                None,
                None,
            )
            .await;

            // 6. Reunite — relay always returns Ok now (join! not try_join!)
            let (tx, rx) = relay_result.unwrap_or((0, 0));
            let noise = NoiseStream::reunite(sender, receiver)?;

            tracing::debug!(request_id, %target, tx, rx, "relay finished");
            Ok(noise)
        }
        Err(e) => {
            tracing::debug!(request_id, %target, error = %e, "connect failed");

            let reply = TunnelMessage::ProxyReply {
                request_id,
                success: false,
                message: e.to_string(),
            };
            noise.send(&reply.encode()).await?;
            // Connection still usable after a failed connect
            Ok(noise)
        }
    }
}

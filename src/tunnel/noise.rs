//! Noise Protocol encrypted stream for tunnel communication.
//!
//! Uses Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s pattern for PSK-based authentication.
//! NoiseStream wraps a TcpStream with encryption for send/recv of framed messages.
//! After the proxy handshake, into_inner() yields the raw TcpStream for relay.

use std::io;
use std::sync::Arc;

use snow::{Builder, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;

const NOISE_PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const MAX_MSG_LEN: usize = 65535;

/// An encrypted stream wrapping TcpStream + Noise TransportState.
pub struct NoiseStream {
    stream: TcpStream,
    transport: TransportState,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl NoiseStream {
    /// Perform Noise handshake as initiator (client) and return a NoiseStream.
    pub async fn connect(mut stream: TcpStream, psk: &[u8; 32]) -> io::Result<Self> {
        let mut hs = Builder::new(NOISE_PATTERN.parse().map_err(noise_err)?)
            .psk(0, psk)
            .build_initiator()
            .map_err(noise_err)?;

        let mut buf = vec![0u8; MAX_MSG_LEN];

        // -> e
        let len = hs.write_message(&[], &mut buf).map_err(noise_err)?;
        send_frame(&mut stream, &buf[..len]).await?;

        // <- e, ee
        let frame = recv_frame(&mut stream).await?;
        hs.read_message(&frame, &mut buf).map_err(noise_err)?;

        let transport = hs.into_transport_mode().map_err(noise_err)?;

        Ok(Self {
            stream,
            transport,
            read_buf: vec![0u8; MAX_MSG_LEN],
            write_buf: vec![0u8; MAX_MSG_LEN],
        })
    }

    /// Perform Noise handshake as responder (server) and return a NoiseStream.
    pub async fn accept(mut stream: TcpStream, psk: &[u8; 32]) -> io::Result<Self> {
        let mut hs = Builder::new(NOISE_PATTERN.parse().map_err(noise_err)?)
            .psk(0, psk)
            .build_responder()
            .map_err(noise_err)?;

        let mut buf = vec![0u8; MAX_MSG_LEN];

        // <- e
        let frame = recv_frame(&mut stream).await?;
        hs.read_message(&frame, &mut buf).map_err(noise_err)?;

        // -> e, ee
        let len = hs.write_message(&[], &mut buf).map_err(noise_err)?;
        send_frame(&mut stream, &buf[..len]).await?;

        let transport = hs.into_transport_mode().map_err(noise_err)?;

        Ok(Self {
            stream,
            transport,
            read_buf: vec![0u8; MAX_MSG_LEN],
            write_buf: vec![0u8; MAX_MSG_LEN],
        })
    }

    /// Send an encrypted, length-prefixed message.
    pub async fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let len = self
            .transport
            .write_message(plaintext, &mut self.write_buf)
            .map_err(noise_err)?;
        send_frame(&mut self.stream, &self.write_buf[..len]).await
    }

    /// Receive and decrypt a length-prefixed message.
    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        let frame = recv_frame(&mut self.stream).await?;
        let len = self
            .transport
            .read_message(&frame, &mut self.read_buf)
            .map_err(noise_err)?;
        Ok(self.read_buf[..len].to_vec())
    }

    /// Consume the NoiseStream and return the underlying TcpStream for raw relay.
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }

    /// Split into independent send/receive halves for concurrent bidirectional relay.
    pub fn split(self) -> (NoiseSender, NoiseReceiver) {
        let (read_half, write_half) = self.stream.into_split();
        let transport = Arc::new(Mutex::new(self.transport));
        (
            NoiseSender {
                writer: write_half,
                transport: Arc::clone(&transport),
                write_buf: self.write_buf,
            },
            NoiseReceiver {
                reader: read_half,
                transport,
                read_buf: self.read_buf,
            },
        )
    }

    /// Reunite a split NoiseSender + NoiseReceiver back into a NoiseStream.
    pub fn reunite(sender: NoiseSender, receiver: NoiseReceiver) -> io::Result<Self> {
        let stream = sender.writer.reunite(receiver.reader).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "reunite: mismatched halves")
        })?;
        // Both halves share the same Arc — drop receiver's copy first,
        // then unwrap sender's (now the sole owner).
        let read_buf = receiver.read_buf;
        drop(receiver.transport);
        let transport = Arc::try_unwrap(sender.transport).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "reunite: Arc still shared")
        })?;
        let transport = transport.into_inner();
        Ok(Self {
            stream,
            transport,
            read_buf,
            write_buf: sender.write_buf,
        })
    }
}

/// Write half of a split NoiseStream.
pub struct NoiseSender {
    writer: OwnedWriteHalf,
    transport: Arc<Mutex<TransportState>>,
    write_buf: Vec<u8>,
}

impl NoiseSender {
    /// Send an encrypted, length-prefixed message.
    pub async fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let len = {
            let mut transport = self.transport.lock().await;
            transport
                .write_message(plaintext, &mut self.write_buf)
                .map_err(noise_err)?
        };
        send_frame_half(&mut self.writer, &self.write_buf[..len]).await
    }
}

/// Read half of a split NoiseStream.
pub struct NoiseReceiver {
    reader: OwnedReadHalf,
    transport: Arc<Mutex<TransportState>>,
    read_buf: Vec<u8>,
}

impl NoiseReceiver {
    /// Receive and decrypt a length-prefixed message.
    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        let frame = recv_frame_half(&mut self.reader).await?;
        let len = {
            let mut transport = self.transport.lock().await;
            transport
                .read_message(&frame, &mut self.read_buf)
                .map_err(noise_err)?
        };
        Ok(self.read_buf[..len].to_vec())
    }
}

/// Send a length-prefixed frame (header + data coalesced into one write_all).
async fn send_frame(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u16;
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// Receive a length-prefixed frame.
async fn recv_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    if len > MAX_MSG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {len}"),
        ));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Send a length-prefixed frame on an OwnedWriteHalf (coalesced write).
async fn send_frame_half(writer: &mut OwnedWriteHalf, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u16;
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

/// Receive a length-prefixed frame from an OwnedReadHalf.
async fn recv_frame_half(reader: &mut OwnedReadHalf) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    if len > MAX_MSG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {len}"),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Derive a 32-byte PSK from a user-provided secret string using BLAKE2s.
pub fn derive_psk(secret: &str) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};

    let mut hasher = Blake2s256::new();
    hasher.update(b"sox-psk-v1:");
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

fn noise_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("noise: {e}"))
}

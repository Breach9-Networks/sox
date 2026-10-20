//! Just enough TLS to read the server name a client asks for: the SNI
//! extension of a ClientHello. Nothing is decrypted or validated beyond the
//! lengths needed to walk to that extension.

use std::io;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::protocol::addr::is_valid_hostname;

/// TLS record content type of a handshake record.
const CONTENT_HANDSHAKE: u8 = 0x16;
/// Handshake message type of a ClientHello.
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
/// Extension type `server_name` (RFC 6066).
const EXT_SERVER_NAME: u16 = 0x0000;
/// `NameType` of a DNS host name inside the `server_name` extension.
const NAME_TYPE_HOST: u8 = 0x00;

/// TLS record header: type (1) + legacy version (2) + length (2).
const RECORD_HEADER_LEN: usize = 5;
/// Largest plaintext record payload a peer may send (RFC 8446 §5.1).
const MAX_RECORD_PAYLOAD: usize = 1 << 14;

/// Total length of the TLS record that `buf` begins with, once its header is
/// available. `None` when `buf` cannot start a handshake record — the client
/// is not speaking TLS, so there is nothing to wait for.
fn handshake_record_len(buf: &[u8]) -> Option<usize> {
    let header = buf.get(..RECORD_HEADER_LEN)?;
    if header[0] != CONTENT_HANDSHAKE {
        return None;
    }
    let payload = usize::from(u16::from_be_bytes([header[3], header[4]]));
    (payload <= MAX_RECORD_PAYLOAD).then_some(RECORD_HEADER_LEN + payload)
}

/// The host name from the SNI extension of the ClientHello in the first
/// record of `buf`. `None` for anything else: not TLS, a truncated or
/// malformed hello, no SNI, or a name that is not a plain ASCII host name.
///
/// Only the first record is read. A ClientHello fragmented across several
/// records (legal, but not something real clients do) yields `None`.
pub fn client_hello_server_name(buf: &[u8]) -> Option<String> {
    let record_len = handshake_record_len(buf)?;
    let mut r = Reader(buf.get(RECORD_HEADER_LEN..record_len)?);

    if r.u8()? != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let len = r.u24()?;
    let mut hello = Reader(r.bytes(len)?);
    hello.bytes(2 + 32)?; // legacy_version, random
    let n = usize::from(hello.u8()?);
    hello.bytes(n)?; // legacy_session_id
    let n = usize::from(hello.u16()?);
    hello.bytes(n)?; // cipher_suites
    let n = usize::from(hello.u8()?);
    hello.bytes(n)?; // legacy_compression_methods

    let n = usize::from(hello.u16()?);
    let mut extensions = Reader(hello.bytes(n)?);
    while !extensions.0.is_empty() {
        let ext_type = extensions.u16()?;
        let n = usize::from(extensions.u16()?);
        let body = extensions.bytes(n)?;
        if ext_type == EXT_SERVER_NAME {
            return server_name_from_extension(body);
        }
    }
    None
}

fn server_name_from_extension(body: &[u8]) -> Option<String> {
    let mut ext = Reader(body);
    let n = usize::from(ext.u16()?);
    let mut list = Reader(ext.bytes(n)?);
    while !list.0.is_empty() {
        let name_type = list.u8()?;
        let n = usize::from(list.u16()?);
        let name = list.bytes(n)?;
        if name_type == NAME_TYPE_HOST {
            // The name ends up in an HTTP request line.
            return is_valid_hostname(name).then(|| String::from_utf8_lossy(name).into_owned());
        }
    }
    None
}

/// Room for the first read: a whole ClientHello (0.5–2 KB) or plaintext
/// request arrives in one piece, rather than split after a few bytes — which
/// defeats an upstream proxy's protocol sniffing.
const FIRST_READ: usize = 4 * 1024;

/// Read the client's opening bytes — up to the end of its first TLS record —
/// so its ClientHello's SNI can be read. Stops early on EOF, on a first byte
/// that cannot start TLS, or after `wait`; a client that leaves without
/// sending anything is an error.
/// The bytes are consumed: the caller must send them on first.
pub async fn read_client_hello(stream: &mut TcpStream, wait: Duration) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(FIRST_READ);
    match tokio::time::timeout(wait, read_first_record(stream, &mut buf)).await {
        Ok(Err(e)) => Err(e),
        // Done, or out of time: either way `buf` holds all that arrived.
        Ok(Ok(())) | Err(_) => Ok(buf),
    }
}

/// Cancel-safe: `read_buf` appends only completed reads, so on timeout `buf`
/// holds exactly the bytes taken off the socket.
async fn read_first_record(stream: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<()> {
    loop {
        if buf.first().is_some_and(|&b| b != CONTENT_HANDSHAKE) {
            return Ok(());
        }
        let want = if buf.len() < RECORD_HEADER_LEN {
            RECORD_HEADER_LEN
        } else {
            match handshake_record_len(buf) {
                Some(len) => len,
                None => return Ok(()),
            }
        };
        if buf.len() >= want {
            return Ok(());
        }
        // `read_buf` reads into spare capacity only: keep room for the rest.
        buf.reserve(want - buf.len());
        if stream.read_buf(buf).await? == 0 {
            return if buf.is_empty() { Err(io::ErrorKind::UnexpectedEof.into()) } else { Ok(()) };
        }
    }
}

/// Bounds-checked big-endian cursor; every read is `None` past the end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        let b = self.bytes(3)?;
        Some(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ClientHello record carrying `extensions` verbatim.
    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0xAB; 32]); // random
        hello.push(0); // session id
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        hello.extend_from_slice(&[0x01, 0x00]); // null compression
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(extensions);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);

        let mut record = vec![CONTENT_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn sni_extension(name: &[u8]) -> Vec<u8> {
        let mut entry = vec![NAME_TYPE_HOST];
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name);
        let mut body = (entry.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&entry);
        let mut ext = EXT_SERVER_NAME.to_be_bytes().to_vec();
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);
        ext
    }

    #[test]
    fn reads_sni_after_other_extensions() {
        let mut exts = vec![0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]; // ec_point_formats
        exts.extend(sni_extension(b"www.tw.coupang.com"));
        let record = client_hello(&exts);
        assert_eq!(client_hello_server_name(&record).as_deref(), Some("www.tw.coupang.com"));
        assert_eq!(handshake_record_len(&record), Some(record.len()));
    }

    #[test]
    fn no_sni_or_not_tls_is_none() {
        assert_eq!(client_hello_server_name(&client_hello(&[])), None);
        assert_eq!(client_hello_server_name(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(handshake_record_len(b"GET /"), None);
        assert_eq!(handshake_record_len(&[0x16, 0x03]), None);
    }

    #[test]
    fn truncated_hello_is_none_at_every_length() {
        let record = client_hello(&sni_extension(b"example.com"));
        for len in 0..record.len() {
            assert_eq!(client_hello_server_name(&record[..len]), None, "len {len}");
        }
    }

    #[test]
    fn names_that_could_inject_are_rejected() {
        for bad in [&b"a.com\r\nX: 1"[..], b"a.com:443", b"a b", b"", &[b'a'; 256]] {
            let record = client_hello(&sni_extension(bad));
            assert_eq!(client_hello_server_name(&record), None);
        }
        let record = client_hello(&sni_extension(b"my_svc.corp.example"));
        assert_eq!(client_hello_server_name(&record).as_deref(), Some("my_svc.corp.example"));
    }

    #[test]
    fn oversized_record_length_is_not_a_hello() {
        assert_eq!(handshake_record_len(&[0x16, 0x03, 0x01, 0xff, 0xff]), None);
    }
}

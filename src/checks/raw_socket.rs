//! Persistent raw TCP/TLS socket for multi-round-trip exchanges.
//!
//! Unlike `tcp_connect` (one send, one read) and `tcp_dialogue` (a fixed
//! command/frame list resolved up front), this primitive keeps one connection
//! open across several engine steps so a later frame can be *computed from* an
//! earlier reply. It is the building block for binary challenge–response
//! protocols — e.g. the Erlang distribution handshake
//! (`send NAME_MSG → read challenge → send MD5(cookie+challenge) → read result`)
//! — and mirrors NASL's `open_sock_tcp` / `send` / `recv` / `close`.
//!
//! The engine drives the exchange through three actions (`tcp_open`,
//! `tcp_send`, `tcp_close`); between `tcp_send` steps an ordinary `script`
//! step computes the next frame with the existing `unpack` / `md5` / `pack`
//! builtins. No protocol specifics live here — the feed drives every byte.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use rustls::pki_types::ServerName;

use super::tcp::insecure_client_config;
use crate::error::{NoctisError, Result};

/// Idle gap that marks the end of one reply (the socket stays open).
const READ_IDLE_MS: u64 = 500;
/// Hard cap on bytes accumulated for a single reply.
const MAX_REPLY_BYTES: usize = 64 * 1024;

/// A live connection held in the execution context across steps.
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

/// Result of `tcp_open` — stored via `store_as`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenResult {
    pub connected: bool,
    /// Greeting bytes as lossy text, when `read_banner` captured any.
    pub banner: Option<String>,
    /// Greeting bytes as lowercase hex, when any arrived.
    pub banner_hex: Option<String>,
    pub duration_ms: u64,
}

/// Result of `tcp_send` — stored via `store_as`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    /// The handle was open and the frame was written.
    pub sent: bool,
    /// At least one reply byte arrived before the idle gap / EOF.
    pub responded: bool,
    /// Reply as lossy text (ASCII markers inside binary replies survive).
    pub response: Option<String>,
    /// Reply as lowercase hex — use for binary offset parsing (`u32be`, …).
    pub response_hex: Option<String>,
    pub length: usize,
    pub duration_ms: u64,
}

#[cfg(test)]
fn to_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end().to_string()
}

#[cfg(test)]
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read until no bytes arrive for `READ_IDLE_MS`, EOF, or the byte cap.
async fn read_reply<S: AsyncReadExt + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut acc = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match timeout(Duration::from_millis(READ_IDLE_MS), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                acc.extend_from_slice(&chunk[..n]);
                if acc.len() >= MAX_REPLY_BYTES {
                    break;
                }
            }
            Ok(Err(_)) => break, // read error
            Err(_) => break,     // idle timeout → reply complete
        }
    }
    acc
}

impl Conn {
    /// Open a connection (optionally wrapped in TLS). Does not read anything.
    pub async fn open(host: &str, port: u16, use_tls: bool, timeout_secs: u64) -> Result<Conn> {
        let addr = format!("{host}:{port}");
        let tcp = match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(NoctisError::Tcp(format!("connect {addr}: {e}"))),
            Err(_) => return Err(NoctisError::Tcp(format!("connect {addr}: timed out"))),
        };
        if use_tls {
            let connector = TlsConnector::from(Arc::new(insecure_client_config()?));
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| NoctisError::Tcp(format!("invalid host for TLS SNI: {e}")))?;
            let stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| NoctisError::Tcp(format!("TLS handshake {addr}: {e}")))?;
            Ok(Conn::Tls(Box::new(stream)))
        } else {
            Ok(Conn::Plain(tcp))
        }
    }

    /// Write a frame verbatim.
    pub async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        let r = match self {
            Conn::Plain(s) => s.write_all(bytes).await,
            Conn::Tls(s) => s.write_all(bytes).await,
        };
        r.map_err(|e| NoctisError::Tcp(format!("send: {e}")))
    }

    /// Read one reply (bounded by the idle gap / byte cap).
    pub async fn read_reply(&mut self) -> Vec<u8> {
        match self {
            Conn::Plain(s) => read_reply(s).await,
            Conn::Tls(s) => read_reply(s).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A scripted challenge–response server mirroring the Erlang flow:
    /// greet, then reply to frame 1 with a 4-byte challenge, and to frame 2
    /// with "ok" only when it carries the expected digest bytes.
    async fn challenge_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"HELLO\r\n").await;
                let mut buf = [0u8; 1024];
                // frame 1 → challenge 0x01020304
                if let Ok(n) = sock.read(&mut buf).await {
                    if n > 0 {
                        let _ = sock.write_all(&[0x00, 0x01, 0x02, 0x03, 0x04]).await;
                    }
                }
                // frame 2 → "accepted" when the last 4 bytes are the digest
                if let Ok(n) = sock.read(&mut buf).await {
                    if n >= 4 && buf[n - 4..n] == [0xde, 0xad, 0xbe, 0xef] {
                        let _ = sock.write_all(b"accepted").await;
                    } else {
                        let _ = sock.write_all(b"denied").await;
                    }
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn multi_round_trip_computed_frame() {
        let addr = challenge_server().await;
        let mut c = Conn::open(&addr.ip().to_string(), addr.port(), false, 5)
            .await
            .unwrap();

        // banner
        let banner = c.read_reply().await;
        assert_eq!(to_text(&banner), "HELLO");

        // frame 1 → challenge
        c.send(&[0xaa]).await.unwrap();
        let reply = c.read_reply().await;
        let hex = to_hex(&reply);
        assert_eq!(hex, "0001020304");
        // parse the big-endian u32 challenge at byte offset 1 (hex offset 2)
        assert_eq!(&hex[2..], "01020304");

        // frame 2 → built from the "computed" digest bytes
        c.send(&[0xde, 0xad, 0xbe, 0xef]).await.unwrap();
        let result = c.read_reply().await;
        assert_eq!(to_text(&result), "accepted");
    }

    #[tokio::test]
    async fn open_failure_is_an_error() {
        // Nothing listening on this port → connect error.
        let err = Conn::open("127.0.0.1", 1, false, 2).await;
        assert!(err.is_err());
    }
}

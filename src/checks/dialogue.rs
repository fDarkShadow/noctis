//! Generic line-oriented TCP dialogue: connect, read the greeting, then send a
//! feed-supplied sequence of commands and capture each reply. Expresses FTP, SMTP,
//! Telnet, POP3, IMAP and similar text protocols without any protocol specifics in
//! the engine — the feed drives the exchange.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use rustls::pki_types::ServerName;

use super::tcp::insecure_client_config;
use crate::error::{NoctisError, Result};

/// Idle gap that marks the end of one reply (line protocols keep the socket open).
const READ_IDLE_MS: u64 = 500;
/// Hard cap on bytes accumulated for a single reply.
const MAX_REPLY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialogueResult {
    pub connected: bool,
    pub banner: Option<String>,
    pub responses: Vec<String>,
    pub transcript: String,
    pub duration_ms: u64,
}

/// Read until no more bytes arrive for `READ_IDLE_MS`, EOF, or the byte cap.
async fn read_reply<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<String> {
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
    if acc.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&acc).trim_end().to_string())
    }
}

async fn converse<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    read_banner: bool,
    commands: &[String],
    line_ending: &str,
) -> (Option<String>, Vec<String>) {
    let banner = if read_banner {
        read_reply(stream).await
    } else {
        None
    };
    let mut responses = Vec::new();
    for cmd in commands {
        let line = format!("{cmd}{line_ending}");
        if stream.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        responses.push(read_reply(stream).await.unwrap_or_default());
    }
    (banner, responses)
}

fn assemble(banner: &Option<String>, responses: &[String]) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if let Some(b) = banner {
        parts.push(b);
    }
    for r in responses {
        parts.push(r);
    }
    parts.join("\n")
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    host: &str,
    port: u16,
    use_tls: bool,
    read_banner: bool,
    commands: Vec<String>,
    line_ending: String,
    timeout_secs: u64,
) -> Result<DialogueResult> {
    let addr = format!("{host}:{port}");
    let start = std::time::Instant::now();

    let tcp = match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(NoctisError::Tcp(format!("connect {addr}: {e}"))),
        Err(_) => {
            return Ok(DialogueResult {
                connected: false,
                banner: None,
                responses: Vec::new(),
                transcript: String::new(),
                duration_ms: start.elapsed().as_millis() as u64,
            })
        }
    };

    let (banner, responses) = if use_tls {
        let connector = TlsConnector::from(Arc::new(insecure_client_config()?));
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| NoctisError::Tcp(format!("invalid host for TLS SNI: {e}")))?;
        let mut stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| NoctisError::Tcp(format!("TLS handshake {addr}: {e}")))?;
        converse(&mut stream, read_banner, &commands, &line_ending).await
    } else {
        let mut stream = tcp;
        converse(&mut stream, read_banner, &commands, &line_ending).await
    };

    let transcript = assemble(&banner, &responses);
    Ok(DialogueResult {
        connected: true,
        banner,
        responses,
        transcript,
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// A scripted server: sends a greeting, then echoes "<n>: <cmd>" per line received.
    async fn scripted_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"220 ready\r\n").await;
                let mut buf = [0u8; 1024];
                let mut n = 0u32;
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(len) => {
                            n += 1;
                            let line = String::from_utf8_lossy(&buf[..len]);
                            let reply = format!("{n}: {}\r\n", line.trim());
                            if sock.write_all(reply.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn banner_and_command_replies() {
        let addr = scripted_server().await;
        let r = run(
            &addr.ip().to_string(),
            addr.port(),
            false,
            true,
            vec!["EHLO x".into(), "QUIT".into()],
            "\r\n".into(),
            5,
        )
        .await
        .unwrap();

        assert!(r.connected);
        assert_eq!(r.banner.as_deref(), Some("220 ready"));
        assert_eq!(r.responses.len(), 2);
        assert_eq!(r.responses[0], "1: EHLO x");
        assert_eq!(r.responses[1], "2: QUIT");
        assert!(r.transcript.contains("220 ready"));
        assert!(r.transcript.contains("1: EHLO x"));
    }

    #[tokio::test]
    async fn skip_banner() {
        let addr = scripted_server().await;
        // Not reading the banner: the greeting stays buffered and is consumed as the
        // first command's "reply" — so responses[0] contains the greeting.
        let r = run(
            &addr.ip().to_string(),
            addr.port(),
            false,
            false,
            vec!["NOOP".into()],
            "\r\n".into(),
            5,
        )
        .await
        .unwrap();
        assert!(r.banner.is_none());
        assert_eq!(r.responses.len(), 1);
        assert!(r.responses[0].contains("220 ready"));
    }
}

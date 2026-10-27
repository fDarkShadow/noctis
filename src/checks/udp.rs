//! Generic UDP probe: send an optional payload to a UDP port and capture the
//! reply. Covers request/response UDP services (DNS, NTP, NetBIOS, SIP,
//! memcached-UDP, SSDP…) where the feed supplies the payload and matches the reply.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::error::{NoctisError, Result};

const MAX_REPLY_BYTES: usize = 65_535;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpResult {
    pub responded: bool,
    /// Reply rendered as text when printable, else hex.
    pub response: Option<String>,
    /// Reply as lowercase hex (always, when any bytes arrived).
    pub response_hex: Option<String>,
    pub length: usize,
    pub duration_ms: u64,
}

/// Decode a hex string ("deadbeef", whitespace/`:` ignored) into bytes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(NoctisError::Tcp("hex payload has odd length".into()));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| {
                NoctisError::Tcp(format!("bad hex in payload: {}", &cleaned[i..i + 2]))
            })
        })
        .collect()
}

fn render(bytes: &[u8]) -> String {
    if bytes
        .iter()
        .all(|&b| b == 0x09 || b == 0x0a || b == 0x0d || (0x20..0x7f).contains(&b))
    {
        String::from_utf8_lossy(bytes).trim_end().to_string()
    } else {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

pub async fn probe(host: &str, port: u16, payload: &[u8], timeout_secs: u64) -> Result<UdpResult> {
    let start = std::time::Instant::now();
    let budget = Duration::from_secs(timeout_secs.max(1));

    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| NoctisError::Tcp(format!("udp bind: {e}")))?;
    sock.connect((host, port))
        .await
        .map_err(|e| NoctisError::Tcp(format!("udp connect {host}:{port}: {e}")))?;

    sock.send(payload)
        .await
        .map_err(|e| NoctisError::Tcp(format!("udp send: {e}")))?;

    let mut buf = vec![0u8; 4096];
    let result = match timeout(budget, sock.recv(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let n = n.min(MAX_REPLY_BYTES);
            let bytes = &buf[..n];
            UdpResult {
                responded: true,
                response: Some(render(bytes)),
                response_hex: Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
                length: n,
                duration_ms: start.elapsed().as_millis() as u64,
            }
        }
        _ => UdpResult {
            responded: false,
            response: None,
            response_hex: None,
            length: 0,
            duration_ms: start.elapsed().as_millis() as u64,
        },
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_ok_and_errors() {
        assert_eq!(
            decode_hex("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(decode_hex("de ad:be").unwrap(), vec![0xde, 0xad, 0xbe]);
        assert!(decode_hex("abc").is_err()); // odd length
        assert!(decode_hex("zz").is_err()); // bad digit
    }

    #[test]
    fn render_text_vs_hex() {
        assert_eq!(render(b"PONG"), "PONG");
        assert_eq!(render(&[0x00, 0xff]), "00ff");
    }

    #[tokio::test]
    async fn probe_gets_echo_reply() {
        // In-process UDP echo server.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1024];
            if let Ok((n, peer)) = server.recv_from(&mut b).await {
                let _ = server.send_to(&b[..n], peer).await;
            }
        });

        let r = probe(&addr.ip().to_string(), addr.port(), b"ping", 3)
            .await
            .unwrap();
        assert!(r.responded);
        assert_eq!(r.response.as_deref(), Some("ping"));
        assert_eq!(r.length, 4);
    }

    #[tokio::test]
    async fn probe_times_out_with_no_server() {
        // Nothing listening on this ephemeral port → no reply.
        let r = probe("127.0.0.1", 1, b"x", 1).await.unwrap();
        assert!(!r.responded);
        assert_eq!(r.length, 0);
    }
}

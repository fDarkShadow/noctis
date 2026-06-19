use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{NoctisError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpResult {
    pub connected: bool,
    pub banner: Option<String>,
    pub duration_ms: u64,
}

pub async fn connect_and_grab(
    host: &str,
    port: u16,
    send: Option<&str>,
    timeout_secs: u64,
) -> Result<TcpResult> {
    let addr = format!("{host}:{port}");
    let start = std::time::Instant::now();

    let stream_result = timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(&addr),
    )
    .await;

    let duration_ms = start.elapsed().as_millis() as u64;

    let mut stream = match stream_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(NoctisError::Tcp(format!("connect {addr}: {e}")));
        }
        Err(_) => {
            return Ok(TcpResult {
                connected: false,
                banner: None,
                duration_ms,
            });
        }
    };

    if let Some(payload) = send {
        let _ = stream.write_all(payload.as_bytes()).await;
    }

    // Read banner with a short deadline
    let mut banner_buf = vec![0u8; 16384];
    let banner = timeout(Duration::from_secs(3), stream.read(&mut banner_buf))
        .await
        .ok()
        .and_then(|r| r.ok())
        .and_then(|n| {
            if n > 0 {
                String::from_utf8_lossy(&banner_buf[..n])
                    .trim()
                    .to_string()
                    .into()
            } else {
                None
            }
        });

    Ok(TcpResult {
        connected: true,
        banner,
        duration_ms,
    })
}

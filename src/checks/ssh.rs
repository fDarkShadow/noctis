use std::net::TcpStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{NoctisError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshResult {
    pub connected: bool,
    pub banner: Option<String>,
    pub server_version: Option<String>,
    pub host_key_algo: Option<String>,
    /// Auth methods advertised by the server for a probe user
    pub auth_methods: Vec<String>,
    pub duration_ms: u64,
}

pub async fn inspect(
    host: &str,
    port: u16,
    probe_user: &str,
    timeout_secs: u64,
) -> Result<SshResult> {
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_secs(timeout_secs);
    let start = std::time::Instant::now();

    // ssh2 is synchronous; run in a blocking thread
    let _host = host.to_string();
    let probe_user = probe_user.to_string();

    let result = tokio::task::spawn_blocking(move || -> Result<SshResult> {
        let tcp = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|_| NoctisError::Ssh(format!("bad addr: {addr}")))?,
            timeout,
        )
        .map_err(|e| NoctisError::Ssh(format!("connect {addr}: {e}")))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        let mut sess =
            ssh2::Session::new().map_err(|e| NoctisError::Ssh(format!("session: {e}")))?;

        sess.set_tcp_stream(tcp);
        sess.handshake()
            .map_err(|e| NoctisError::Ssh(format!("handshake: {e}")))?;

        let banner = sess.banner().map(|b| b.trim().to_string());

        let host_key_algo = sess.host_key().map(|(_, kt)| format!("{kt:?}"));

        let auth_methods = sess
            .auth_methods(&probe_user)
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(SshResult {
            connected: true,
            banner,
            server_version: None,
            host_key_algo,
            auth_methods,
            duration_ms,
        })
    })
    .await
    .map_err(|e| NoctisError::Ssh(format!("thread: {e}")))?;

    result
}

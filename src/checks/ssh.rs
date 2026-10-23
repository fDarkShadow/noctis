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
    /// True when one of the supplied credentials authenticated (ssh_exec only).
    #[serde(default)]
    pub authenticated: bool,
    /// The username that authenticated, if any.
    #[serde(default)]
    pub auth_user: Option<String>,
    /// Captured stdout+stderr of `command`, if one ran.
    #[serde(default)]
    pub exec_output: Option<String>,
    /// Exit status of `command`, if one ran.
    #[serde(default)]
    pub exit_status: Option<i32>,
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
            authenticated: false,
            auth_user: None,
            exec_output: None,
            exit_status: None,
            duration_ms,
        })
    })
    .await
    .map_err(|e| NoctisError::Ssh(format!("thread: {e}")))?;

    result
}

/// Try each `(user, password)` credential in order; on the first that authenticates,
/// optionally run `command` and capture its stdout+stderr. Credentials are supplied
/// explicitly by the feed (no generated brute-force).
pub async fn exec(
    host: &str,
    port: u16,
    credentials: Vec<(String, String)>,
    command: Option<String>,
    timeout_secs: u64,
) -> Result<SshResult> {
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_secs(timeout_secs);
    let start = std::time::Instant::now();

    let result = tokio::task::spawn_blocking(move || -> Result<SshResult> {
        let socket = addr
            .parse()
            .map_err(|_| NoctisError::Ssh(format!("bad addr: {addr}")))?;
        let tcp = TcpStream::connect_timeout(&socket, timeout)
            .map_err(|e| NoctisError::Ssh(format!("connect {addr}: {e}")))?;

        let mut sess =
            ssh2::Session::new().map_err(|e| NoctisError::Ssh(format!("session: {e}")))?;
        sess.set_tcp_stream(tcp);
        sess.handshake()
            .map_err(|e| NoctisError::Ssh(format!("handshake: {e}")))?;

        let banner = sess.banner().map(|b| b.trim().to_string());
        let host_key_algo = sess.host_key().map(|(_, kt)| format!("{kt:?}"));
        let probe_user = credentials
            .first()
            .map(|(u, _)| u.as_str())
            .unwrap_or("root");
        let auth_methods = sess
            .auth_methods(probe_user)
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mut out = SshResult {
            connected: true,
            banner,
            server_version: None,
            host_key_algo,
            auth_methods,
            authenticated: false,
            auth_user: None,
            exec_output: None,
            exit_status: None,
            duration_ms: start.elapsed().as_millis() as u64,
        };

        for (user, pass) in &credentials {
            if sess.userauth_password(user, pass).is_ok() && sess.authenticated() {
                out.authenticated = true;
                out.auth_user = Some(user.clone());
                break;
            }
        }

        if out.authenticated {
            if let Some(cmd) = &command {
                if let Ok(mut channel) = sess.channel_session() {
                    if channel.exec(cmd).is_ok() {
                        let mut buf = String::new();
                        use std::io::Read;
                        let _ = channel.read_to_string(&mut buf);
                        let mut err = String::new();
                        let _ = channel.stderr().read_to_string(&mut err);
                        let _ = channel.wait_close();
                        if !err.is_empty() {
                            buf.push_str(&err);
                        }
                        out.exec_output = Some(buf);
                        out.exit_status = channel.exit_status().ok();
                    }
                }
            }
        }

        out.duration_ms = start.elapsed().as_millis() as u64;
        Ok(out)
    })
    .await
    .map_err(|e| NoctisError::Ssh(format!("thread: {e}")))?;

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SshResult {
        SshResult {
            connected: true,
            banner: Some("SSH-2.0-OpenSSH_7.4".into()),
            server_version: None,
            host_key_algo: None,
            auth_methods: vec!["password".into(), "publickey".into()],
            authenticated: true,
            auth_user: Some("root".into()),
            exec_output: Some("uid=0(root) gid=0(root)".into()),
            exit_status: Some(0),
            duration_ms: 12,
        }
    }

    #[test]
    fn result_exposes_exec_fields_to_feeds() {
        let v = serde_json::to_value(sample()).unwrap();
        assert_eq!(v["authenticated"], serde_json::json!(true));
        assert_eq!(v["auth_user"], serde_json::json!("root"));
        assert_eq!(
            v["exec_output"],
            serde_json::json!("uid=0(root) gid=0(root)")
        );
        assert_eq!(v["exit_status"], serde_json::json!(0));
    }

    #[test]
    fn exec_fields_default_when_absent() {
        // A legacy/inspect-style result deserializes with the new fields defaulted.
        let json = r#"{"connected":true,"banner":null,"server_version":null,
            "host_key_algo":null,"auth_methods":[],"duration_ms":3}"#;
        let r: SshResult = serde_json::from_str(json).unwrap();
        assert!(!r.authenticated);
        assert!(r.auth_user.is_none());
        assert!(r.exec_output.is_none());
        assert!(r.exit_status.is_none());
    }
}

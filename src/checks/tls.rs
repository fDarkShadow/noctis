use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::*;

use crate::error::{NoctisError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsResult {
    pub connected: bool,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub cert_valid: bool,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_expiry: Option<String>,
    pub cert_sans: Vec<String>,
    pub duration_ms: u64,
}

pub async fn inspect(host: &str, port: u16, timeout_secs: u64) -> Result<TlsResult> {
    let addr = format!("{host}:{port}");
    let start = std::time::Instant::now();

    let stream = tokio::time::timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr))
        .await
        .map_err(|_| NoctisError::Tls(format!("connect timeout: {addr}")))?
        .map_err(|e| NoctisError::Tls(format!("connect {addr}: {e}")))?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| NoctisError::Tls(format!("invalid server name: {e}")))?;

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| NoctisError::Tls(format!("TLS handshake: {e}")))?;

    let duration_ms = start.elapsed().as_millis() as u64;
    let conn = tls_stream.get_ref().1;

    let protocol_version = conn.protocol_version().map(|v| format!("{v:?}"));

    let cipher_suite = conn.negotiated_cipher_suite().map(|cs| format!("{cs:?}"));

    // Extract certificate info from the peer cert chain
    let mut cert_subject = None;
    let mut cert_issuer = None;
    let mut cert_expiry = None;
    let mut cert_sans = Vec::new();
    let mut cert_valid = false;

    if let Some(certs) = conn.peer_certificates() {
        if let Some(leaf) = certs.first() {
            if let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) {
                cert_valid = true;
                cert_subject = Some(cert.subject().to_string());
                cert_issuer = Some(cert.issuer().to_string());
                cert_expiry = Some(
                    cert.validity()
                        .not_after
                        .to_rfc2822()
                        .unwrap_or_else(|_| "unknown".to_string()),
                );
                if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
                    for san in &san_ext.value.general_names {
                        let s = match san {
                            GeneralName::DNSName(n) => n.to_string(),
                            GeneralName::IPAddress(b) => {
                                if b.len() == 4 {
                                    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
                                } else {
                                    format!("{b:?}")
                                }
                            }
                            other => format!("{other:?}"),
                        };
                        cert_sans.push(s);
                    }
                }
            }
        }
    }

    Ok(TlsResult {
        connected: true,
        protocol_version,
        cipher_suite,
        cert_valid,
        cert_subject,
        cert_issuer,
        cert_expiry,
        cert_sans,
        duration_ms,
    })
}

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::SignatureScheme;
use rustls::{ClientConfig, DigitallySignedStruct};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::error::{NoctisError, Result};

/// Accepts any server certificate — used for raw TLS connections over HTTPS test targets
/// that carry self-signed certs (never used in production scanning of external hosts).
#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

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
    use_tls: bool,
) -> Result<TcpResult> {
    if use_tls {
        connect_and_grab_tls(host, port, send, timeout_secs).await
    } else {
        connect_and_grab_plain(host, port, send, timeout_secs).await
    }
}

async fn connect_and_grab_plain(
    host: &str,
    port: u16,
    send: Option<&str>,
    timeout_secs: u64,
) -> Result<TcpResult> {
    let addr = format!("{host}:{port}");
    let start = std::time::Instant::now();

    let stream_result = timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await;

    let duration_ms = start.elapsed().as_millis() as u64;

    let mut stream = match stream_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(NoctisError::Tcp(format!("connect {addr}: {e}"))),
        Err(_) => {
            return Ok(TcpResult {
                connected: false,
                banner: None,
                duration_ms,
            })
        }
    };

    if let Some(payload) = send {
        let _ = stream.write_all(payload.as_bytes()).await;
    }

    let banner = read_banner(&mut stream).await;
    Ok(TcpResult {
        connected: true,
        banner,
        duration_ms,
    })
}

async fn connect_and_grab_tls(
    host: &str,
    port: u16,
    send: Option<&str>,
    timeout_secs: u64,
) -> Result<TcpResult> {
    let addr = format!("{host}:{port}");
    let start = std::time::Instant::now();

    let tcp = timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr))
        .await
        .map_err(|_| NoctisError::Tcp(format!("connect timeout: {addr}")))?
        .map_err(|e| NoctisError::Tcp(format!("connect {addr}: {e}")))?;

    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| NoctisError::Tcp(format!("TLS config: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| NoctisError::Tcp(format!("invalid host for TLS SNI: {e}")))?;

    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| NoctisError::Tcp(format!("TLS handshake {addr}: {e}")))?;

    let duration_ms = start.elapsed().as_millis() as u64;

    if let Some(payload) = send {
        let _ = stream.write_all(payload.as_bytes()).await;
    }

    let banner = read_banner(&mut stream).await;
    Ok(TcpResult {
        connected: true,
        banner,
        duration_ms,
    })
}

const READ_TIMEOUT_SECS: u64 = 3;

async fn read_banner<R: AsyncReadExt + Unpin>(stream: &mut R) -> Option<String> {
    let mut acc = Vec::new();
    // Ignore EOF-vs-timeout: acc retains whatever arrived before either fires.
    let _ = timeout(
        Duration::from_secs(READ_TIMEOUT_SECS),
        stream.read_to_end(&mut acc),
    )
    .await;
    if acc.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&acc).trim().to_string())
    }
}

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::any;
use axum::Router;
use serde_json::Value;
use tokio::sync::{Mutex, Notify};

/// OOB HTTP callback server.
///
/// When a target calls back to `http://<host>:<port>/<token>`, the server
/// stores the request details and notifies any waiter on that token.
pub struct OobServer {
    pub host: String,
    pub port: u16,
    callbacks: Arc<Mutex<HashMap<String, Value>>>,
    notifiers: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
}

impl OobServer {
    pub fn new(host: impl Into<String>, port: u16) -> Arc<Self> {
        Arc::new(Self {
            host: host.into(),
            port,
            callbacks: Arc::new(Mutex::new(HashMap::new())),
            notifiers: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Start listening in the background. Returns immediately.
    ///
    /// The bind happens *before* spawning so errors (port already in use, etc.)
    /// surface here rather than being silently swallowed inside the task.
    pub async fn start(self: Arc<Self>) -> crate::error::Result<()> {
        let addr: SocketAddr = format!("0.0.0.0:{}", self.port)
            .parse()
            .map_err(|e| crate::error::NoctisError::Oob(format!("bad addr: {e}")))?;

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| crate::error::NoctisError::Oob(format!("bind {addr}: {e}")))?;

        tracing::info!(addr = %addr, "OOB server listening");

        let shared = self.clone();
        let app = Router::new()
            .route("/{token}", any(handle_callback))
            .route("/{token}/", any(handle_callback))
            .with_state(shared);

        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("OOB server error: {e}");
            }
        });

        Ok(())
    }

    /// Wait asynchronously until a callback for `token` arrives.
    /// Returns the captured request payload, or None on timeout (handled by caller).
    pub async fn wait_for_token(&self, token: &str) -> Option<Value> {
        // Check if already received
        {
            let map = self.callbacks.lock().await;
            if let Some(v) = map.get(token) {
                return Some(v.clone());
            }
        }

        // Register notifier
        let notify = {
            let mut notifiers = self.notifiers.lock().await;
            notifiers
                .entry(token.to_string())
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone()
        };

        notify.notified().await;

        let map = self.callbacks.lock().await;
        map.get(token).cloned()
    }

    async fn record(&self, token: &str, data: Value) {
        {
            let mut map = self.callbacks.lock().await;
            map.insert(token.to_string(), data);
        }
        let notifiers = self.notifiers.lock().await;
        if let Some(n) = notifiers.get(token) {
            n.notify_waiters();
        }
    }
}

// ── Axum handler ──────────────────────────────────────────────────────────

async fn handle_callback(
    Path(token): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    State(server): State<Arc<OobServer>>,
    method: axum::http::Method,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> StatusCode {
    tracing::info!(token = %token, "OOB callback received");

    let header_map: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let payload = serde_json::json!({
        "method": method.to_string(),
        "headers": header_map,
        "query": params,
        "body": String::from_utf8_lossy(&body).to_string(),
    });

    server.record(&token, payload).await;
    StatusCode::OK
}

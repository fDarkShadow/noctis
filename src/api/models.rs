use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::scan::ScanStatus;

// ── POST /scans response ──────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ScanCreated {
    pub id: Uuid,
    pub status: ScanStatus,
}

// ── GET /health ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Health {
    pub status: &'static str,
    pub version: &'static str,
}

// ── Uniform API error ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ApiError {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl ApiError {
    pub fn not_found(id: Uuid) -> Self {
        Self {
            error: "not_found",
            detail: Some(serde_json::json!({ "id": id })),
        }
    }

    pub fn internal(message: impl std::fmt::Display) -> Self {
        Self {
            error: "internal_error",
            detail: Some(serde_json::Value::String(message.to_string())),
        }
    }
}

// ── Webhook payload ───────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct WebhookEvent<'a, T: Serialize> {
    pub event: &'a str,
    pub timestamp: DateTime<Utc>,
    pub data: &'a T,
}

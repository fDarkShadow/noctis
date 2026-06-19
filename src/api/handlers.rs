use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use uuid::Uuid;

use crate::scan::manager::ScanManager;
use crate::scan::{ScanRequest, ScanStatus};

use super::extract::Valid;
use super::models::{ApiError, Health, ScanCreated};

pub type AppState = Arc<ScanManager>;

// POST /scans
pub async fn create_scan(
    State(mgr): State<AppState>,
    Valid(req): Valid<ScanRequest>,
) -> impl IntoResponse {
    match mgr.submit(req).await {
        Ok(id) => (
            StatusCode::ACCEPTED,
            Json(ScanCreated { id, status: ScanStatus::Pending }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::internal(e)),
        )
            .into_response(),
    }
}

// GET /scans
pub async fn list_scans(State(mgr): State<AppState>) -> impl IntoResponse {
    Json(mgr.list().await)
}

// GET /scans/{id}
pub async fn get_scan(
    State(mgr): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match mgr.get(id).await {
        Some(s) => Json(s).into_response(),
        None => not_found(id),
    }
}

// GET /scans/{id}/findings
pub async fn get_findings(
    State(mgr): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match mgr.findings(id).await {
        Some(f) => Json(f).into_response(),
        None => not_found(id),
    }
}

// DELETE /scans/{id}
pub async fn cancel_scan(
    State(mgr): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if mgr.cancel(id).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        not_found(id)
    }
}

// GET /health
pub async fn health() -> impl IntoResponse {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

fn not_found(id: Uuid) -> axum::response::Response {
    (StatusCode::NOT_FOUND, Json(ApiError::not_found(id))).into_response()
}

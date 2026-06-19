pub mod extract;
pub mod handlers;
pub mod models;
pub mod webhook;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::scan::manager::ScanManager;

use handlers::*;

pub fn router(manager: Arc<ScanManager>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/scans", post(create_scan).get(list_scans))
        .route("/scans/{id}", get(get_scan).delete(cancel_scan))
        .route("/scans/{id}/findings", get(get_findings))
        .with_state(manager)
}

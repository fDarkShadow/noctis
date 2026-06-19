use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::finding::Finding;

use super::request::ScanRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanState {
    pub id: Uuid,
    pub status: ScanStatus,
    pub target: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub total_tests: usize,
    pub completed_tests: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

impl ScanState {
    pub fn new(id: Uuid, request: &ScanRequest) -> Self {
        let target = request.host.clone();
        Self {
            id,
            status: ScanStatus::Pending,
            target,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            total_tests: 0,
            completed_tests: 0,
            findings: Vec::new(),
            error: None,
            webhook_url: request.webhook_url.clone(),
        }
    }

    pub fn elapsed_ms(&self) -> Option<u64> {
        let start = self.started_at?;
        let end = self.completed_at.unwrap_or_else(Utc::now);
        Some((end - start).num_milliseconds().max(0) as u64)
    }
}

// ── Summary (GET /scans, GET /scans/{id}) ─────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub id: Uuid,
    pub status: ScanStatus,
    pub target: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub elapsed_ms: Option<u64>,
    pub progress: Progress,
    pub findings_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Progress {
    pub total: usize,
    pub completed: usize,
}

impl From<&ScanState> for ScanSummary {
    fn from(s: &ScanState) -> Self {
        Self {
            id: s.id,
            status: s.status.clone(),
            target: s.target.clone(),
            created_at: s.created_at,
            started_at: s.started_at,
            completed_at: s.completed_at,
            elapsed_ms: s.elapsed_ms(),
            progress: Progress { total: s.total_tests, completed: s.completed_tests },
            findings_count: s.findings.len(),
            error: s.error.clone(),
            webhook_url: s.webhook_url.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use crate::scan::request::ScanRequest;

    fn req(host: &str, port: u16) -> ScanRequest {
        use crate::scan::request::DiscoveredService;
        ScanRequest {
            host: host.to_string(),
            services: vec![DiscoveredService { port, service: "http".to_string(), protocol: "tcp".to_string() }],
            tests: vec!["tests/".to_string()],
            concurrency: 5,
            webhook_url: None,
            oob: None,
            filters: None,
        }
    }

    #[test]
    fn target_is_host() {
        let s = ScanState::new(Uuid::new_v4(), &req("10.0.0.1", 80));
        assert_eq!(s.target, "10.0.0.1");
    }

    #[test]
    fn initial_status_is_pending() {
        let s = ScanState::new(Uuid::new_v4(), &req("host", 80));
        assert_eq!(s.status, ScanStatus::Pending);
    }

    #[test]
    fn elapsed_ms_not_started_is_none() {
        let s = ScanState::new(Uuid::new_v4(), &req("host", 80));
        assert!(s.elapsed_ms().is_none());
    }

    #[test]
    fn elapsed_ms_with_completed() {
        let mut s = ScanState::new(Uuid::new_v4(), &req("host", 80));
        s.started_at = Some(Utc::now() - Duration::milliseconds(1000));
        s.completed_at = Some(Utc::now());
        let ms = s.elapsed_ms().unwrap();
        assert!(ms >= 990 && ms <= 1100, "expected ~1000ms, got {ms}");
    }

    #[test]
    fn elapsed_ms_running_uses_now() {
        let mut s = ScanState::new(Uuid::new_v4(), &req("host", 80));
        s.started_at = Some(Utc::now() - Duration::milliseconds(500));
        assert!(s.elapsed_ms().unwrap() >= 400);
    }

    #[test]
    fn summary_progress_and_count() {
        let id = Uuid::new_v4();
        let mut s = ScanState::new(id, &req("host", 80));
        s.total_tests = 10;
        s.completed_tests = 4;
        let sum = ScanSummary::from(&s);
        assert_eq!(sum.id, id);
        assert_eq!(sum.progress.total, 10);
        assert_eq!(sum.progress.completed, 4);
        assert_eq!(sum.findings_count, 0);
    }

    #[test]
    fn status_serde_snake_case() {
        let s = serde_json::to_string(&ScanStatus::Completed).unwrap();
        assert_eq!(s, r#""completed""#);
    }
}

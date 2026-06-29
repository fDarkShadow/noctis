use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::{RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::api::webhook;
use crate::engine::Runner;
use crate::error::Result;
use crate::loader;
use crate::model::finding::Finding;
use crate::model::test_def::TestDef;
use crate::oob::OobServer;
use crate::scan::request::ScanRequest;

use super::{OobConfig, ScanState, ScanStatus, ScanSummary};

pub type SharedState = Arc<RwLock<ScanState>>;

pub struct ScanManager {
    scans: Arc<RwLock<HashMap<Uuid, SharedState>>>,
    daemon_oob: Option<Arc<OobServer>>,
    webhook_client: reqwest::Client,
}

impl ScanManager {
    pub fn new(daemon_oob: Option<Arc<OobServer>>) -> Arc<Self> {
        Arc::new(Self {
            scans: Arc::new(RwLock::new(HashMap::new())),
            daemon_oob,
            webhook_client: reqwest::Client::new(),
        })
    }

    /// Submit a scan and return its UUID immediately. Execution is async.
    pub async fn submit(self: Arc<Self>, request: ScanRequest) -> Result<Uuid> {
        let id = Uuid::new_v4();
        tracing::info!(
            scan = %id,
            host = %request.host,
            services = request.services.len(),
            tests = request.tests.len(),
            "scan submitted"
        );
        let state = Arc::new(RwLock::new(ScanState::new(id, &request)));

        self.scans.write().await.insert(id, state.clone());

        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.execute(id, request, state.clone()).await {
                let mut s = state.write().await;
                s.status = ScanStatus::Failed;
                s.error = Some(e.to_string());
                s.completed_at = Some(Utc::now());
                let wh = s.webhook_url.clone();
                let summary = ScanSummary::from(&*s);
                drop(s);
                if let Some(url) = wh {
                    webhook::send(&manager.webhook_client, &url, "scan.failed", &summary).await;
                }
            }
        });

        Ok(id)
    }

    /// Get a summary of a single scan.
    pub async fn get(&self, id: Uuid) -> Option<ScanSummary> {
        let state = {
            let scans = self.scans.read().await;
            scans.get(&id)?.clone()
        };
        let guard = state.read().await;
        let summary = ScanSummary::from(&*guard);
        drop(guard);
        Some(summary)
    }

    /// List summaries of all scans, newest first.
    pub async fn list(&self) -> Vec<ScanSummary> {
        let states: Vec<SharedState> = {
            let scans = self.scans.read().await;
            scans.values().cloned().collect()
        };
        let mut summaries = Vec::with_capacity(states.len());
        for state in states {
            summaries.push(ScanSummary::from(&*state.read().await));
        }
        summaries.sort_by_key(|s| std::cmp::Reverse(s.created_at));
        summaries
    }

    /// Get findings for a scan.
    pub async fn findings(&self, id: Uuid) -> Option<Vec<Finding>> {
        let state = {
            let scans = self.scans.read().await;
            scans.get(&id)?.clone()
        };
        let guard = state.read().await;
        let findings = guard.findings.clone();
        drop(guard);
        Some(findings)
    }

    /// Cancel a scan (marks as cancelled; in-flight tests finish naturally).
    pub async fn cancel(&self, id: Uuid) -> bool {
        let state = {
            let scans = self.scans.read().await;
            match scans.get(&id) {
                Some(s) => s.clone(),
                None => return false,
            }
        };
        let mut s = state.write().await;
        if matches!(s.status, ScanStatus::Pending | ScanStatus::Running) {
            s.status = ScanStatus::Cancelled;
            s.completed_at = Some(Utc::now());
            true
        } else {
            false
        }
    }

    // ── Internal execution ────────────────────────────────────────────────

    async fn execute(&self, id: Uuid, request: ScanRequest, state: SharedState) -> Result<()> {
        let paths = loader::resolve_test_paths(&request.tests)?;

        let filters = request.filters.clone().unwrap_or_default();

        let mut defs = Vec::new();
        for path in &paths {
            match loader::load(path) {
                Ok(d) => {
                    if filters.is_excluded(&d) {
                        tracing::debug!(test = %d.uid, "excluded by filter");
                    } else {
                        defs.push(d);
                    }
                }
                Err(e) => tracing::warn!(path = %path.display(), "skipping: {e}"),
            }
        }

        // Expand each def to one task per matched (port, service_name).
        let defs_count = defs.len();
        let tasks: Vec<(TestDef, u16, String)> = defs
            .into_iter()
            .flat_map(|def| {
                matched_services(&def, &request)
                    .into_iter()
                    .map(move |(p, svc)| (def.clone(), p, svc))
            })
            .collect();

        let total = tasks.len();

        tracing::info!(
            scan = %id,
            host = %request.host,
            defs = defs_count,
            tasks = total,
            "scan starting"
        );

        {
            let mut s = state.write().await;
            s.status = ScanStatus::Running;
            s.started_at = Some(Utc::now());
            s.total_tests = total;
        }

        let oob = self.resolve_oob(&request.oob).await?;
        let webhook_url = request.webhook_url.clone();
        let client = self.webhook_client.clone();

        // scan.started
        {
            let summary = ScanSummary::from(&*state.read().await);
            if let Some(ref url) = webhook_url {
                webhook::send(&client, url, "scan.started", &summary).await;
            }
        }

        let runner = Arc::new(Runner::new(oob));
        let semaphore = Arc::new(Semaphore::new(request.concurrency));
        let cancel = CancellationToken::new();
        let host = Arc::new(request.host.clone());

        let mut handles = Vec::with_capacity(total);

        for (def, port, svc) in tasks {
            let runner = runner.clone();
            let sem = semaphore.clone();
            let host = host.clone();
            let state = state.clone();
            let cancel = cancel.clone();
            let client = client.clone();
            let wh = webhook_url.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore never closed");

                if cancel.is_cancelled() {
                    return;
                }
                {
                    let s = state.read().await;
                    if s.status == ScanStatus::Cancelled {
                        cancel.cancel();
                        return;
                    }
                }

                let findings = match runner.run(&def, host.as_str(), Some(port), &svc).await {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(test = %def.uid, "test error: {e}");
                        vec![]
                    }
                };

                let summary = {
                    let mut s = state.write().await;
                    s.findings.extend(findings);
                    s.completed_tests += 1;
                    ScanSummary::from(&*s)
                };

                if let Some(ref url) = wh {
                    webhook::send(&client, url, "scan.progress", &summary).await;
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        // Final state
        let (summary, wh) = {
            let mut s = state.write().await;
            if s.status != ScanStatus::Cancelled {
                s.status = ScanStatus::Completed;
            }
            s.completed_at = Some(Utc::now());
            let wh = s.webhook_url.clone();
            (ScanSummary::from(&*s), wh)
        };

        if let Some(ref url) = wh {
            let event = if summary.status == ScanStatus::Completed {
                "scan.completed"
            } else {
                "scan.cancelled"
            };
            webhook::send(&client, url, event, &summary).await;
        }

        tracing::info!(scan = %id, status = ?summary.status, findings = summary.findings_count, "scan finished");
        Ok(())
    }

    async fn resolve_oob(&self, cfg: &Option<OobConfig>) -> Result<Option<Arc<OobServer>>> {
        match cfg {
            Some(c) if c.enabled => {
                // Reuse the daemon OOB server if it is already running on the same port.
                // Starting a second listener on the same port would fail with EADDRINUSE.
                if let Some(ref daemon) = self.daemon_oob {
                    if daemon.port == c.port {
                        return Ok(Some(daemon.clone()));
                    }
                }
                let srv = OobServer::new(c.host.clone(), c.port);
                srv.clone().start().await?;
                Ok(Some(srv))
            }
            _ => Ok(self.daemon_oob.clone()),
        }
    }
}

/// Return (port, service_name) pairs on which `def` should run.
///
/// Rules:
/// - `def.services` empty: run on every discovered (port, service).
/// - `def.services` non-empty: only entries whose service name matches.
fn matched_services(def: &TestDef, request: &ScanRequest) -> Vec<(u16, String)> {
    if def.services.is_empty() {
        return request
            .services
            .iter()
            .map(|s| (s.port, s.service.clone()))
            .collect();
    }
    request
        .services
        .iter()
        .filter(|s| def.services.contains(&s.service))
        .map(|s| (s.port, s.service.clone()))
        .collect()
}

use std::sync::Arc;

use serde_json::Value;
use tracing::{debug, info, warn};

use crate::error::Result;
use crate::model::finding::Finding;
use crate::model::step::{LoopConfig, Step};
use crate::model::test_def::TestDef;
use crate::oob::OobServer;
use crate::scan::request::Credentials;

use super::context::Context;
use super::step::execute_step;

pub struct Runner {
    pub oob_server: Option<Arc<OobServer>>,
    /// Scan-level credentials, injected into every test context as `cred_*` vars.
    credentials: Option<Arc<Credentials>>,
}

impl Runner {
    pub fn new(oob_server: Option<Arc<OobServer>>) -> Self {
        Self {
            oob_server,
            credentials: None,
        }
    }

    /// Attach scan credentials (see [`Context::inject_credentials`]).
    pub fn with_credentials(mut self, credentials: Option<Credentials>) -> Self {
        self.credentials = credentials.map(Arc::new);
        self
    }

    pub async fn run(
        &self,
        def: &TestDef,
        target_host: impl Into<String>,
        target_port: Option<u16>,
        target_service: &str,
    ) -> Result<Vec<Finding>> {
        if skip_for_missing_credentials(def, self.credentials.is_some()) {
            return Ok(Vec::new());
        }

        let mut ctx = Context::new(
            target_host,
            target_port,
            target_service,
            self.oob_server.clone(),
        );
        ctx.inject_credentials(self.credentials.as_deref());
        ctx.seed_vars(&def.vars);

        info!(test = %def.uid, name = %def.name, target = %ctx.target_label(), "starting test");

        let steps = &def.steps;
        let mut i = 0;
        while i < steps.len() {
            let step = &steps[i];
            debug!(step = %step.id, action = %step.action, "executing step");

            let stop = if let Some(loop_cfg) = &step.loop_cfg {
                // Group this loop step with immediately following non-loop steps so
                // a match step sees the probe result from the same iteration.
                // wait_oob is excluded — it's a one-shot wait that must run after
                // the full injection loop, not once per iteration.
                let tail = steps[i + 1..]
                    .iter()
                    .take_while(|s| s.loop_cfg.is_none() && s.action != "wait_oob")
                    .count();
                let group = &steps[i..i + 1 + tail];
                let stop = run_loop_group(group, loop_cfg, def, &mut ctx)
                    .await
                    .map_err(|e| redact_error(e, def, step, &ctx))?;
                i += 1 + tail;
                stop
            } else {
                i += 1;
                execute_step(step, def, &mut ctx, None)
                    .await
                    .map_err(|e| redact_error(e, def, step, &ctx))?
            };

            if stop {
                info!(step = %step.id, "stop requested — halting test");
                break;
            }
        }

        info!(test = %def.uid, findings = ctx.findings.len(), "test complete");

        Ok(ctx.findings)
    }
}

/// Step errors bubble up to the scan manager's `test error` warn log, and some
/// (Rhai runtime errors, template errors) can quote variable values. When the
/// scan carries credentials, re-wrap the error with its text redacted.
fn redact_error(
    e: crate::error::NoctisError,
    def: &TestDef,
    step: &Step,
    ctx: &Context,
) -> crate::error::NoctisError {
    if !ctx.has_secrets() {
        return e;
    }
    crate::error::NoctisError::StepError {
        test: def.uid.to_string(),
        step: step.id.clone(),
        message: ctx.redact(&e.to_string()),
    }
}

/// `true` when `def` declares `requires_credentials: true` but the scan has none.
/// Such a feed is skipped cleanly — no finding, only a debug log.
pub fn skip_for_missing_credentials(def: &TestDef, has_credentials: bool) -> bool {
    if def.requires_credentials && !has_credentials {
        debug!(test = %def.uid, name = %def.name, "requires credentials, none supplied — skipped");
        return true;
    }
    false
}

async fn run_loop_group(
    steps: &[Step],
    cfg: &LoopConfig,
    def: &TestDef,
    ctx: &mut Context,
) -> Result<bool> {
    let items: Vec<Value> = if let Some(list) = &cfg.over {
        list.clone()
    } else if let Some(count) = cfg.count {
        (0..count).map(|i| Value::Number(i.into())).collect()
    } else {
        warn!(step = %steps[0].id, "loop has neither 'over' nor 'count'");
        return Ok(false);
    };

    let var = cfg.var.as_str();
    for item in items {
        for step in steps {
            // Pass the loop variable to every step in the group so templates like
            // {{current_path}} in evidence strings resolve to the current item.
            if execute_step(step, def, ctx, Some((var, item.clone()))).await? {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::severity::Severity;
    use crate::model::step::{FindingSpec, StepOutcome};
    use indexmap::IndexMap;
    use uuid::Uuid;

    /// A feed whose single `match` step matches the raw password (so the
    /// `matched` evidence is the secret itself) and echoes the credential vars
    /// in every finding text field.
    fn cred_def(requires: bool) -> TestDef {
        let step: Step = serde_json::from_value(serde_json::json!({
            "id": "s",
            "action": "match",
            "source": "cred_password",
            "pattern": ".+",
        }))
        .unwrap();
        let mut step = step;
        step.on_match = Some(StepOutcome {
            condition: None,
            set_vars: None,
            stop: false,
            finding: Some(FindingSpec {
                title: Some("login {{cred_username}} / {{cred_password}}".into()),
                description: Some("token {{cred_token}}".into()),
                remediation: Some("rotate {{cred_password}}".into()),
                confidence_delta: 0.0,
                severity: None,
                evidence: Some("pw={{cred_password}} tok={{cred_token}}".into()),
                qod: 75,
                cves: None,
                cvss: None,
            }),
        });
        TestDef {
            uid: Uuid::new_v4(),
            name: "cred".into(),
            description: None,
            severity: Severity::High,
            confidence_base: 0.5,
            tags: vec![],
            author: None,
            version: None,
            references: vec![],
            cves: vec![],
            cvss: None,
            category: None,
            services: vec![],
            requires_credentials: requires,
            includes: vec![],
            vars: IndexMap::new(),
            steps: vec![step],
        }
    }

    fn creds() -> Credentials {
        Credentials {
            username: Some("admin".into()),
            password: Some("hunter2-pw".into()),
            token: Some("tok-secret".into()),
        }
    }

    #[tokio::test]
    async fn requires_credentials_without_creds_is_skipped() {
        let f = Runner::new(None)
            .run(&cred_def(true), "127.0.0.1", Some(1), "http")
            .await
            .unwrap();
        assert!(f.is_empty());
    }

    #[tokio::test]
    async fn requires_credentials_with_creds_runs() {
        let f = Runner::new(None)
            .with_credentials(Some(creds()))
            .run(&cred_def(true), "127.0.0.1", Some(1), "http")
            .await
            .unwrap();
        assert_eq!(f.len(), 1);
    }

    #[tokio::test]
    async fn finding_redacts_password_and_token() {
        let f = Runner::new(None)
            .with_credentials(Some(creds()))
            .run(&cred_def(false), "127.0.0.1", Some(1), "http")
            .await
            .unwrap();
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("hunter2-pw"), "password leaked into finding");
        assert!(!json.contains("tok-secret"), "token leaked into finding");
        assert!(
            json.contains("login admin / <redacted>"),
            "expected redaction marker in finding"
        );
    }

    #[test]
    fn skip_helper_only_for_opted_in_feeds() {
        assert!(skip_for_missing_credentials(&cred_def(true), false));
        assert!(!skip_for_missing_credentials(&cred_def(true), true));
        assert!(!skip_for_missing_credentials(&cred_def(false), false));
    }

    #[tokio::test]
    async fn step_error_text_is_redacted_when_credentials_present() {
        // A script step whose runtime error quotes the token value.
        let yaml = r#"
uid: 7b0f1c62-3f0e-4c69-9a43-5d3a1f0c2e11
name: err-redact
severity: info
steps:
  - id: boom
    action: script
    code: "throw cred_token"
"#;
        let def: TestDef = serde_saphyr::from_str(yaml).expect("feed parses");
        let runner = Runner::new(None).with_credentials(Some(Credentials {
            username: None,
            password: None,
            token: Some("tok-very-secret".into()),
        }));
        let err = runner
            .run(&def, "127.0.0.1", Some(1), "http")
            .await
            .expect_err("script throws");
        let text = err.to_string();
        assert!(
            !text.contains("tok-very-secret"),
            "token leaked into step error"
        );
        assert!(text.contains("<redacted>"), "expected redaction marker");
    }
}

use crate::engine::context::Context;
use crate::engine::finding::handle_outcome;
use crate::error::Result;
use crate::model::step::Step;
use crate::model::test_def::TestDef;

pub async fn run_wait_oob(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let Some(oob) = ctx.oob_server.clone() else {
        tracing::debug!(step = %step.id, "wait_oob skipped — OOB server not configured");
        return Ok(false);
    };

    let deadline = std::time::Duration::from_secs(step.oob_timeout_secs);
    let token = ctx.oob_token.clone();

    tracing::debug!(step = %step.id, token = %token, "waiting for OOB callback");

    let received = tokio::time::timeout(deadline, oob.wait_for_token(&token))
        .await
        .ok()
        .flatten();

    match received {
        Some(data) => {
            if let Some(key) = &step.store_as { ctx.set(key.clone(), data.clone()); }
            handle_outcome(&step.on_success, step, def, ctx, Some(data.to_string()))
        }
        None => {
            tracing::warn!(
                step = %step.id,
                test = %def.name,
                target = %ctx.target_label(),
                timeout_secs = step.oob_timeout_secs,
                prior_findings = ctx.findings.len(),
                "OOB TIMEOUT — no callback received within {}s (firewall/EDR may have blocked the \
                 outbound request); {} prior finding(s) preserved",
                step.oob_timeout_secs,
                ctx.findings.len(),
            );
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

use crate::error::{NoctisError, Result};
use crate::expr;
use crate::model::step::Step;
use crate::model::test_def::TestDef;
use serde_json::Value;

use super::actions::{connect, http, logic, oob};
use super::context::Context;

/// Execute a single step (after loop unrolling and condition check).
/// Returns `true` if the test should stop (`stop: true` in outcome).
pub async fn execute_step(
    step: &Step,
    def: &TestDef,
    ctx: &mut Context,
    loop_var: Option<(&str, Value)>,
) -> Result<bool> {
    if let Some((var_name, val)) = loop_var {
        ctx.set(var_name.to_string(), val);
    }

    if let Some(cond) = &step.condition {
        let interp = expr::interpolate_lenient(cond, &ctx.vars);
        if !expr::eval_condition(&interp, &ctx.vars).unwrap_or(false) {
            tracing::debug!(step = %step.id, "condition false — skipping");
            return Ok(false);
        }
    }

    match step.action.as_str() {
        "http_request" => http::run(step, def, ctx).await,
        "tcp_connect"  => connect::run_tcp(step, def, ctx).await,
        "tls_check"    => connect::run_tls(step, def, ctx).await,
        "ssh_check"    => connect::run_ssh(step, def, ctx).await,
        "match"        => logic::run_match(step, def, ctx),
        "script"       => logic::run_script(step, ctx),
        "wait_oob"     => oob::run_wait_oob(step, def, ctx).await,
        "set_var"      => logic::run_set_var(step, ctx),
        unknown => Err(NoctisError::StepError {
            test: def.uid.to_string(),
            step: step.id.clone(),
            message: format!("unknown action: {unknown}"),
        }),
    }
}

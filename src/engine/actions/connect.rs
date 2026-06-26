use crate::checks::{ssh, tcp, tls};
use crate::engine::context::Context;
use crate::engine::finding::{handle_outcome, to_json};
use crate::error::{NoctisError, Result};
use crate::model::step::Step;
use crate::model::test_def::TestDef;

use super::http::resolve_port;

pub async fn run_tcp(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx).or(ctx.target_port).ok_or_else(|| NoctisError::MissingField {
        field: "port",
        action: "tcp_connect",
        step: step.id.clone(),
    })?;

    let send = match &step.send {
        Some(s) => Some(crate::expr::interpolate(s, &ctx.vars)?),
        None => None,
    };

    let use_tls = ctx.vars.get("scheme").and_then(|v| v.as_str()) == Some("https");

    match tcp::connect_and_grab(&ctx.target_host, port, send.as_deref(), step.timeout_secs, use_tls).await {
        Ok(r) => {
            if let Some(key) = &step.store_as { ctx.set(key.clone(), to_json(&r, step, def)?); }
            if r.connected {
                handle_outcome(&step.on_success, step, def, ctx, None)
            } else {
                handle_outcome(&step.on_failure, step, def, ctx, None)
            }
        }
        Err(e) => {
            tracing::warn!(step = %step.id, "tcp error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

pub async fn run_tls(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx).or(ctx.target_port).unwrap_or(443);

    match tls::inspect(&ctx.target_host, port, step.timeout_secs).await {
        Ok(r) => {
            if let Some(key) = &step.store_as { ctx.set(key.clone(), to_json(&r, step, def)?); }
            if r.connected {
                handle_outcome(&step.on_success, step, def, ctx, None)
            } else {
                handle_outcome(&step.on_failure, step, def, ctx, None)
            }
        }
        Err(e) => {
            tracing::warn!(step = %step.id, "tls error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

pub async fn run_ssh(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx).or(ctx.target_port).unwrap_or(22);

    match ssh::inspect(&ctx.target_host, port, "probe", step.timeout_secs).await {
        Ok(r) => {
            if let Some(key) = &step.store_as { ctx.set(key.clone(), to_json(&r, step, def)?); }
            handle_outcome(&step.on_success, step, def, ctx, None)
        }
        Err(e) => {
            tracing::warn!(step = %step.id, "ssh error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

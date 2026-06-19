use indexmap::IndexMap;

use crate::checks::http::HttpCheck;
use crate::engine::context::Context;
use crate::engine::finding::{handle_outcome, to_json};
use crate::error::Result;
use crate::expr;
use crate::model::step::Step;
use crate::model::test_def::TestDef;

pub(super) fn resolve_port(port: &Option<String>, ctx: &Context) -> Option<u16> {
    let s = port.as_deref()?;
    let resolved = expr::interpolate_lenient(s, &ctx.vars);
    resolved.trim().parse().ok().or(ctx.target_port)
}

pub async fn run(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let method = step.method.as_deref().unwrap_or("GET");
    let path = step.path.as_deref().unwrap_or("/");
    let port = resolve_port(&step.port, ctx).unwrap_or(if step.tls_insecure { 80 } else { 443 });
    let scheme = if step.tls_insecure || port == 80 { "http" } else { "https" };

    let url = expr::interpolate(
        &format!("{scheme}://{}:{}{}", ctx.target_host, port, path),
        &ctx.vars,
    )?;

    let mut headers = IndexMap::new();
    if let Some(h) = &step.headers {
        for (k, v) in h {
            headers.insert(expr::interpolate(k, &ctx.vars)?, expr::interpolate(v, &ctx.vars)?);
        }
    }

    let body = match &step.body {
        Some(b) => Some(expr::interpolate(b, &ctx.vars)?),
        None => None,
    };

    let checker = HttpCheck::new(step.follow_redirects.unwrap_or(true), step.tls_insecure, step.timeout_secs)?;

    match checker.run(method, &url, &headers, body.as_deref()).await {
        Ok(resp) => {
            if let Some(key) = &step.store_as { ctx.set(key.clone(), to_json(&resp, step, def)?); }
            handle_outcome(&step.on_success, step, def, ctx, None)
        }
        Err(e) => {
            tracing::warn!(step = %step.id, "http error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

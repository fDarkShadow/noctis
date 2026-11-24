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

/// Interpolate a step's `method:` (default `GET`). An undefined variable is an error, never
/// a request sent with the literal `{{...}}` text as its method.
pub(super) fn resolve_method(method: Option<&str>, ctx: &Context) -> Result<String> {
    let raw = method.unwrap_or("GET");
    Ok(expr::interpolate(raw, &ctx.vars)?.trim().to_string())
}

pub async fn run(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    // `method` is templated like `path` / `headers` / `body`, so shared includes such as
    // tests/common/http_base.yaml can take it from a var (`method: "{{http_method}}"`).
    let method = resolve_method(step.method.as_deref(), ctx)?;
    let method = method.as_str();
    let path = step.path.as_deref().unwrap_or("/");

    // Scheme comes from {{scheme}} injected by the runner (derived from the discovered service
    // name: "http" or "https"). tls_insecure only controls certificate validation.
    let scheme = ctx
        .vars
        .get("scheme")
        .and_then(|v| v.as_str())
        .unwrap_or("http");
    let port = resolve_port(&step.port, ctx).unwrap_or(if scheme == "https" { 443 } else { 80 });

    let url = expr::interpolate(
        &format!("{scheme}://{}:{}{}", ctx.target_host, port, path),
        &ctx.vars,
    )?;

    let mut headers = IndexMap::new();
    if let Some(h) = &step.headers {
        for (k, v) in h {
            headers.insert(
                expr::interpolate(k, &ctx.vars)?,
                expr::interpolate(v, &ctx.vars)?,
            );
        }
    }

    let body = match &step.body {
        Some(b) => Some(expr::interpolate(b, &ctx.vars)?),
        None => None,
    };

    let checker = HttpCheck::new(
        step.follow_redirects.unwrap_or(true),
        step.tls_insecure,
        step.timeout_secs,
    )?;

    // Never log a credential that a feed templated into the URL.
    let logged_url = ctx.redact(&url);

    match checker.run(method, &url, &headers, body.as_deref()).await {
        Ok(resp) => {
            tracing::debug!(
                step = %step.id,
                method,
                url = %logged_url,
                status = resp.status,
                duration_ms = resp.duration_ms,
                "http"
            );
            if let Some(key) = &step.store_as {
                ctx.set(key.clone(), to_json(&resp, step, def)?);
            }
            handle_outcome(&step.on_success, step, def, ctx, None)
        }
        Err(e) => {
            tracing::warn!(step = %step.id, url = %logged_url, "http error: {}", ctx.redact(&e.to_string()));
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context::new("127.0.0.1", Some(8080), "http", None)
    }

    #[test]
    fn method_defaults_to_get() {
        assert_eq!(resolve_method(None, &ctx()).unwrap(), "GET");
    }

    #[test]
    fn method_literal_is_kept() {
        assert_eq!(resolve_method(Some("POST"), &ctx()).unwrap(), "POST");
    }

    #[test]
    fn method_template_is_interpolated() {
        // tests/common/http_base.yaml declares `method: "{{http_method}}"`.
        let mut c = ctx();
        c.set("http_method", serde_json::Value::String("GET".into()));
        assert_eq!(resolve_method(Some("{{http_method}}"), &c).unwrap(), "GET");
    }

    #[test]
    fn method_with_undefined_var_is_an_error() {
        assert!(resolve_method(Some("{{nope}}"), &ctx()).is_err());
    }
}

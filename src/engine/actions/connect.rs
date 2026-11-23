use crate::checks::raw_socket::{Conn, OpenResult, SendResult};
use crate::checks::{dialogue, snmp, ssh, synscan, tcp, tls, udp};
use crate::engine::context::Context;
use crate::engine::finding::{handle_outcome, to_json};
use crate::error::{NoctisError, Result};
use crate::model::step::Step;
use crate::model::test_def::TestDef;

use super::http::resolve_port;

pub async fn run_tcp(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx)
        .or(ctx.target_port)
        .ok_or_else(|| NoctisError::MissingField {
            field: "port",
            action: "tcp_connect",
            step: step.id.clone(),
        })?;

    let send = match &step.send {
        Some(s) => Some(crate::expr::interpolate(s, &ctx.vars)?),
        None => None,
    };

    let use_tls = ctx.vars.get("scheme").and_then(|v| v.as_str()) == Some("https");

    match tcp::connect_and_grab(
        &ctx.target_host,
        port,
        send.as_deref(),
        step.timeout_secs,
        use_tls,
    )
    .await
    {
        Ok(r) => {
            tracing::debug!(
                step = %step.id,
                host = %ctx.target_host,
                port,
                tls = use_tls,
                connected = r.connected,
                duration_ms = r.duration_ms,
                "tcp"
            );
            if let Some(key) = &step.store_as {
                ctx.set(key.clone(), to_json(&r, step, def)?);
            }
            if r.connected {
                handle_outcome(&step.on_success, step, def, ctx, None)
            } else {
                handle_outcome(&step.on_failure, step, def, ctx, None)
            }
        }
        Err(e) => {
            tracing::warn!(step = %step.id, host = %ctx.target_host, port, "tcp error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

pub async fn run_tls(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx)
        .or(ctx.target_port)
        .unwrap_or(443);

    match tls::inspect(&ctx.target_host, port, step.timeout_secs).await {
        Ok(r) => {
            tracing::debug!(
                step = %step.id,
                host = %ctx.target_host,
                port,
                connected = r.connected,
                "tls"
            );
            if let Some(key) = &step.store_as {
                ctx.set(key.clone(), to_json(&r, step, def)?);
            }
            if r.connected {
                handle_outcome(&step.on_success, step, def, ctx, None)
            } else {
                handle_outcome(&step.on_failure, step, def, ctx, None)
            }
        }
        Err(e) => {
            tracing::warn!(step = %step.id, host = %ctx.target_host, port, "tls error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

pub async fn run_ssh(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx)
        .or(ctx.target_port)
        .unwrap_or(22);

    match ssh::inspect(&ctx.target_host, port, "probe", step.timeout_secs).await {
        Ok(r) => {
            tracing::debug!(
                step = %step.id,
                host = %ctx.target_host,
                port,
                banner = r.banner.as_deref().unwrap_or(""),
                "ssh"
            );
            if let Some(key) = &step.store_as {
                ctx.set(key.clone(), to_json(&r, step, def)?);
            }
            handle_outcome(&step.on_success, step, def, ctx, None)
        }
        Err(e) => {
            tracing::warn!(step = %step.id, host = %ctx.target_host, port, "ssh error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

/// Build the `(user, password)` list from the step: the explicit `credentials`
/// list ("user:password" each), falling back to a single `username`/`password`.
fn ssh_credentials(step: &Step, ctx: &Context) -> Result<Vec<(String, String)>> {
    let mut creds = Vec::new();
    if !step.credentials.is_empty() {
        for raw in &step.credentials {
            let pair = crate::expr::interpolate(raw, &ctx.vars)?;
            let (u, p) = pair.split_once(':').unwrap_or((pair.as_str(), ""));
            creds.push((u.to_string(), p.to_string()));
        }
    } else if let Some(user) = &step.username {
        let u = crate::expr::interpolate(user, &ctx.vars)?;
        let p = match &step.password {
            Some(pw) => crate::expr::interpolate(pw, &ctx.vars)?,
            None => String::new(),
        };
        creds.push((u, p));
    }
    Ok(creds)
}

pub async fn run_ssh_exec(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx)
        .or(ctx.target_port)
        .unwrap_or(22);
    let creds = ssh_credentials(step, ctx)?;
    let command = match &step.command {
        Some(c) => Some(crate::expr::interpolate(c, &ctx.vars)?),
        None => None,
    };

    match ssh::exec(&ctx.target_host, port, creds, command, step.timeout_secs).await {
        Ok(r) => {
            tracing::debug!(
                step = %step.id,
                host = %ctx.target_host,
                port,
                authenticated = r.authenticated,
                "ssh_exec"
            );
            if let Some(key) = &step.store_as {
                ctx.set(key.clone(), to_json(&r, step, def)?);
            }
            if r.authenticated {
                handle_outcome(&step.on_success, step, def, ctx, None)
            } else {
                handle_outcome(&step.on_failure, step, def, ctx, None)
            }
        }
        Err(e) => {
            tracing::warn!(step = %step.id, host = %ctx.target_host, port, "ssh_exec error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

pub async fn run_snmp_get(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx)
        .or(ctx.target_port)
        .unwrap_or(161);

    let mut communities = Vec::new();
    if !step.communities.is_empty() {
        for c in &step.communities {
            communities.push(crate::expr::interpolate(c, &ctx.vars)?);
        }
    } else {
        communities.push(match &step.community {
            Some(c) => crate::expr::interpolate(c, &ctx.vars)?,
            None => "public".to_string(),
        });
    }

    let mut oids = Vec::new();
    for o in &step.oids {
        oids.push(crate::expr::interpolate(o, &ctx.vars)?);
    }

    match snmp::get(&ctx.target_host, port, communities, oids, step.timeout_secs).await {
        Ok(r) => {
            tracing::debug!(
                step = %step.id,
                host = %ctx.target_host,
                port,
                responded = r.responded,
                "snmp_get"
            );
            if let Some(key) = &step.store_as {
                ctx.set(key.clone(), to_json(&r, step, def)?);
            }
            if r.responded {
                handle_outcome(&step.on_success, step, def, ctx, None)
            } else {
                handle_outcome(&step.on_failure, step, def, ctx, None)
            }
        }
        Err(e) => {
            tracing::warn!(step = %step.id, host = %ctx.target_host, port, "snmp error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

pub async fn run_tcp_dialogue(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx)
        .or(ctx.target_port)
        .ok_or_else(|| NoctisError::MissingField {
            field: "port",
            action: "tcp_dialogue",
            step: step.id.clone(),
        })?;

    // TLS: explicit `tls:` wins, else auto-detect from an https scheme (like tcp_connect).
    let use_tls = step
        .tls
        .unwrap_or_else(|| ctx.vars.get("scheme").and_then(|v| v.as_str()) == Some("https"));
    let read_banner = step.read_banner.unwrap_or(true);
    let line_ending = match &step.line_ending {
        Some(s) => crate::expr::interpolate(s, &ctx.vars)?,
        None => "\r\n".to_string(),
    };
    let mut commands = Vec::new();
    for c in &step.commands {
        commands.push(crate::expr::interpolate(c, &ctx.vars)?);
    }

    // Binary mode: a raw hex frame sent verbatim (e.g. a length-prefixed MongoDB
    // wire-protocol message). Templated first, then decoded from hex.
    let send_hex = match &step.send_hex {
        Some(hex) => Some(udp::decode_hex(&crate::expr::interpolate(hex, &ctx.vars)?)?),
        None => None,
    };

    match dialogue::run(
        &ctx.target_host,
        port,
        use_tls,
        read_banner,
        commands,
        line_ending,
        send_hex,
        step.timeout_secs,
    )
    .await
    {
        Ok(r) => {
            tracing::debug!(
                step = %step.id,
                host = %ctx.target_host,
                port,
                tls = use_tls,
                connected = r.connected,
                replies = r.responses.len(),
                "tcp_dialogue"
            );
            if let Some(key) = &step.store_as {
                ctx.set(key.clone(), to_json(&r, step, def)?);
            }
            if r.connected {
                handle_outcome(&step.on_success, step, def, ctx, None)
            } else {
                handle_outcome(&step.on_failure, step, def, ctx, None)
            }
        }
        Err(e) => {
            tracing::warn!(step = %step.id, host = %ctx.target_host, port, "tcp_dialogue error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

/// Handle name for a persistent socket step, defaulting to `"sock"`.
fn socket_handle(step: &Step, ctx: &Context) -> Result<String> {
    match &step.handle {
        Some(h) => crate::expr::interpolate(h, &ctx.vars),
        None => Ok("sock".to_string()),
    }
}

/// `tcp_open` — open a persistent TCP/TLS socket and keep it in the context
/// under `handle` (default `"sock"`) for later `tcp_send` / `tcp_close` steps.
/// Reads the greeting first when `read_banner: true` (default false).
pub async fn run_tcp_open(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx)
        .or(ctx.target_port)
        .ok_or_else(|| NoctisError::MissingField {
            field: "port",
            action: "tcp_open",
            step: step.id.clone(),
        })?;

    let handle = socket_handle(step, ctx)?;
    let use_tls = step
        .tls
        .unwrap_or_else(|| ctx.vars.get("scheme").and_then(|v| v.as_str()) == Some("https"));
    let read_banner = step.read_banner.unwrap_or(false);
    let start = std::time::Instant::now();

    match Conn::open(&ctx.target_host, port, use_tls, step.timeout_secs).await {
        Ok(mut conn) => {
            let (banner, banner_hex) = if read_banner {
                let bytes = conn.read_reply().await;
                if bytes.is_empty() {
                    (None, None)
                } else {
                    (
                        Some(String::from_utf8_lossy(&bytes).trim_end().to_string()),
                        Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
                    )
                }
            } else {
                (None, None)
            };
            let result = OpenResult {
                connected: true,
                banner,
                banner_hex,
                duration_ms: start.elapsed().as_millis() as u64,
            };
            tracing::debug!(step = %step.id, host = %ctx.target_host, port, tls = use_tls, %handle, "tcp_open");
            ctx.connections.insert(handle, conn);
            if let Some(key) = &step.store_as {
                ctx.set(key.clone(), to_json(&result, step, def)?);
            }
            handle_outcome(&step.on_success, step, def, ctx, None)
        }
        Err(e) => {
            tracing::warn!(step = %step.id, host = %ctx.target_host, port, "tcp_open error: {e}");
            if let Some(key) = &step.store_as {
                let result = OpenResult {
                    connected: false,
                    banner: None,
                    banner_hex: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                };
                ctx.set(key.clone(), to_json(&result, step, def)?);
            }
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

/// `tcp_send` — write a frame on an already-open `handle` and read one reply.
/// Payload: `send_hex` (binary, templated then hex-decoded) wins over `send`
/// (text, templated). Because templates resolve at send time, a frame can be
/// built from a value a previous reply produced (e.g. a computed digest).
pub async fn run_tcp_send(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let handle = socket_handle(step, ctx)?;
    let start = std::time::Instant::now();

    // Payload: `send_hex` (binary) wins over `send` (text); either templated first.
    let payload: Vec<u8> = if let Some(hex) = &step.send_hex {
        udp::decode_hex(&crate::expr::interpolate(hex, &ctx.vars)?)?
    } else if let Some(text) = &step.send {
        crate::expr::interpolate(text, &ctx.vars)?.into_bytes()
    } else {
        Vec::new()
    };

    let store_result = |ctx: &mut Context, result: SendResult| -> Result<()> {
        if let Some(key) = &step.store_as {
            let v = to_json(&result, step, def)?;
            ctx.set(key.clone(), v);
        }
        Ok(())
    };

    let Some(conn) = ctx.connections.get_mut(&handle) else {
        tracing::warn!(step = %step.id, %handle, "tcp_send: no such open handle");
        store_result(
            ctx,
            SendResult {
                sent: false,
                responded: false,
                response: None,
                response_hex: None,
                length: 0,
                duration_ms: start.elapsed().as_millis() as u64,
            },
        )?;
        return handle_outcome(&step.on_failure, step, def, ctx, None);
    };

    if let Err(e) = conn.send(&payload).await {
        tracing::warn!(step = %step.id, %handle, "tcp_send error: {e}");
        store_result(
            ctx,
            SendResult {
                sent: false,
                responded: false,
                response: None,
                response_hex: None,
                length: 0,
                duration_ms: start.elapsed().as_millis() as u64,
            },
        )?;
        return handle_outcome(&step.on_failure, step, def, ctx, None);
    }

    let reply = conn.read_reply().await;
    let responded = !reply.is_empty();
    let result = SendResult {
        sent: true,
        responded,
        response: if responded {
            Some(String::from_utf8_lossy(&reply).trim_end().to_string())
        } else {
            None
        },
        response_hex: if responded {
            Some(reply.iter().map(|b| format!("{b:02x}")).collect())
        } else {
            None
        },
        length: reply.len(),
        duration_ms: start.elapsed().as_millis() as u64,
    };
    tracing::debug!(step = %step.id, %handle, responded, len = reply.len(), "tcp_send");
    store_result(ctx, result)?;

    if responded {
        handle_outcome(&step.on_success, step, def, ctx, None)
    } else {
        handle_outcome(&step.on_failure, step, def, ctx, None)
    }
}

/// `tcp_close` — drop a persistent socket opened by `tcp_open`. Idempotent:
/// closing an unknown or already-closed handle is not an error.
pub async fn run_tcp_close(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let handle = socket_handle(step, ctx)?;
    let existed = ctx.connections.remove(&handle).is_some();
    tracing::debug!(step = %step.id, %handle, existed, "tcp_close");
    handle_outcome(&step.on_success, step, def, ctx, None)
}

pub async fn run_tcp_syn(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx)
        .or(ctx.target_port)
        .ok_or_else(|| NoctisError::MissingField {
            field: "port",
            action: "tcp_syn",
            step: step.id.clone(),
        })?;

    match synscan::syn_probe(&ctx.target_host, port, step.timeout_secs).await {
        Ok(r) => {
            tracing::debug!(
                step = %step.id,
                host = %ctx.target_host,
                port,
                state = %r.state,
                "tcp_syn"
            );
            let ran = matches!(r.state.as_str(), "open" | "closed" | "filtered");
            if let Some(key) = &step.store_as {
                ctx.set(key.clone(), to_json(&r, step, def)?);
            }
            if ran {
                handle_outcome(&step.on_success, step, def, ctx, None)
            } else {
                // unprivileged / error: the probe could not run
                handle_outcome(&step.on_failure, step, def, ctx, None)
            }
        }
        Err(e) => {
            tracing::warn!(step = %step.id, host = %ctx.target_host, port, "tcp_syn error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

pub async fn run_udp_probe(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let port = resolve_port(&step.port, ctx)
        .or(ctx.target_port)
        .ok_or_else(|| NoctisError::MissingField {
            field: "port",
            action: "udp_probe",
            step: step.id.clone(),
        })?;

    // Payload: `send_hex` (binary) wins over `send` (text); either is templated first.
    let payload: Vec<u8> = if let Some(hex) = &step.send_hex {
        udp::decode_hex(&crate::expr::interpolate(hex, &ctx.vars)?)?
    } else if let Some(text) = &step.send {
        crate::expr::interpolate(text, &ctx.vars)?.into_bytes()
    } else {
        Vec::new()
    };

    match udp::probe(&ctx.target_host, port, &payload, step.timeout_secs).await {
        Ok(r) => {
            tracing::debug!(
                step = %step.id,
                host = %ctx.target_host,
                port,
                responded = r.responded,
                len = r.length,
                "udp_probe"
            );
            let responded = r.responded;
            if let Some(key) = &step.store_as {
                ctx.set(key.clone(), to_json(&r, step, def)?);
            }
            if responded {
                handle_outcome(&step.on_success, step, def, ctx, None)
            } else {
                handle_outcome(&step.on_failure, step, def, ctx, None)
            }
        }
        Err(e) => {
            tracing::warn!(step = %step.id, host = %ctx.target_host, port, "udp_probe error: {e}");
            handle_outcome(&step.on_failure, step, def, ctx, None)
        }
    }
}

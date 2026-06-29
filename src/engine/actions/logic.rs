use regex::RegexBuilder;
use serde_json::Value;

use crate::checks::MatchResult;
use crate::engine::context::Context;
use crate::engine::finding::{handle_outcome, to_json};
use crate::error::{NoctisError, Result};
use crate::expr;
use crate::model::step::Step;
use crate::model::test_def::TestDef;

pub fn run_match(step: &Step, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let source_key = step
        .source
        .as_deref()
        .ok_or_else(|| NoctisError::MissingField {
            field: "source",
            action: "match",
            step: step.id.clone(),
        })?;
    let pattern = step
        .pattern
        .as_deref()
        .ok_or_else(|| NoctisError::MissingField {
            field: "pattern",
            action: "match",
            step: step.id.clone(),
        })?;

    let source_val = expr::interpolate_lenient(&format!("{{{{{source_key}}}}}"), &ctx.vars);

    let re = RegexBuilder::new(pattern)
        .case_insensitive(step.case_insensitive)
        .build()
        .map_err(NoctisError::Regex)?;

    let matched = re.is_match(&source_val);
    let captures: Vec<String> = re
        .captures(&source_val)
        .map(|c| {
            c.iter()
                .skip(1)
                .filter_map(|m| m.map(|m| m.as_str().to_string()))
                .collect()
        })
        .unwrap_or_default();

    let result = MatchResult { matched, captures };
    let effective_match = if step.negate { !matched } else { matched };

    if let Some(key) = &step.store_as {
        ctx.set(key.clone(), to_json(&result, step, def)?);
    }

    if effective_match {
        let evidence = if matched { Some(source_val) } else { None };
        handle_outcome(&step.on_match, step, def, ctx, evidence)
    } else {
        handle_outcome(&step.on_failure, step, def, ctx, None)
    }
}

pub fn run_script(step: &Step, ctx: &mut Context) -> Result<bool> {
    let code = step
        .code
        .as_deref()
        .ok_or_else(|| NoctisError::MissingField {
            field: "code",
            action: "script",
            step: step.id.clone(),
        })?;

    let result = expr::eval_script(code, &mut ctx.vars, &step.id)?;
    if let Some(key) = &step.store_as {
        ctx.set(key.clone(), result);
    }
    Ok(false)
}

pub fn run_set_var(step: &Step, ctx: &mut Context) -> Result<bool> {
    let name = step
        .var_name
        .as_deref()
        .ok_or_else(|| NoctisError::MissingField {
            field: "var_name",
            action: "set_var",
            step: step.id.clone(),
        })?;

    let val = match &step.var_value {
        Some(v) => {
            let s = serde_json::to_string(v).unwrap_or_default();
            let interp = expr::interpolate_lenient(&s, &ctx.vars);
            serde_json::from_str(&interp).unwrap_or(Value::String(interp))
        }
        None => Value::Null,
    };

    ctx.set(name.to_string(), val);
    Ok(false)
}

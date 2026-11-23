use std::collections::HashMap;

use rhai::{Dynamic, Engine, Scope};

use crate::error::{NoctisError, Result};

pub fn eval_condition(expr: &str, vars: &HashMap<String, serde_json::Value>) -> Result<bool> {
    let engine = build_engine();
    let mut scope = Scope::new();

    for (key, val) in vars {
        scope.push_dynamic(key.replace('.', "_"), json_to_dynamic(val));
    }

    let result: Dynamic = engine
        .eval_expression_with_scope::<Dynamic>(&mut scope, expr)
        .map_err(|e| NoctisError::ExprError {
            step: "<condition>".to_string(),
            message: e.to_string(),
        })?;

    Ok(result.as_bool().unwrap_or(false))
}

pub fn eval_script(
    code: &str,
    vars: &mut HashMap<String, serde_json::Value>,
    step_id: &str,
) -> Result<serde_json::Value> {
    let engine = build_engine();
    let mut scope = Scope::new();

    for (key, val) in vars.iter() {
        scope.push_dynamic(key.replace('.', "_"), json_to_dynamic(val));
    }

    let result: Dynamic = engine
        .eval_with_scope::<Dynamic>(&mut scope, code)
        .map_err(|e| NoctisError::ExprError {
            step: step_id.to_string(),
            message: e.to_string(),
        })?;

    for (key, val) in vars.iter_mut() {
        let rhai_name = key.replace('.', "_");
        if let Some(dyn_val) = scope.get_value::<Dynamic>(&rhai_name) {
            *val = dynamic_to_json(dyn_val);
        }
    }

    Ok(dynamic_to_json(result))
}

fn build_engine() -> Engine {
    let mut engine = Engine::new();
    engine.set_max_operations(100_000);
    engine.set_max_string_size(1024 * 1024);
    super::builtins::register(&mut engine);
    super::crypto::register(&mut engine);
    super::binpack::register(&mut engine);
    engine
}

pub(crate) fn json_to_dynamic(v: &serde_json::Value) -> Dynamic {
    match v {
        serde_json::Value::Null => Dynamic::UNIT,
        serde_json::Value::Bool(b) => Dynamic::from(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Dynamic::from(i)
            } else if let Some(f) = n.as_f64() {
                Dynamic::from(f)
            } else {
                Dynamic::UNIT
            }
        }
        serde_json::Value::String(s) => Dynamic::from(s.clone()),
        serde_json::Value::Array(arr) => {
            let v: rhai::Array = arr.iter().map(json_to_dynamic).collect();
            Dynamic::from(v)
        }
        serde_json::Value::Object(map) => {
            let mut m = rhai::Map::new();
            for (k, v) in map {
                m.insert(k.clone().into(), json_to_dynamic(v));
            }
            Dynamic::from(m)
        }
    }
}

pub(crate) fn dynamic_to_json(d: Dynamic) -> serde_json::Value {
    if d.is_unit() {
        serde_json::Value::Null
    } else if let Some(b) = d.clone().try_cast::<bool>() {
        serde_json::Value::Bool(b)
    } else if let Some(i) = d.clone().try_cast::<i64>() {
        serde_json::Value::Number(i.into())
    } else if let Some(f) = d.clone().try_cast::<f64>() {
        serde_json::json!(f)
    } else if let Some(s) = d.clone().try_cast::<String>() {
        serde_json::Value::String(s)
    } else {
        serde_json::Value::String(d.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    // ── eval_condition ────────────────────────────────────────────────────

    #[test]
    fn condition_literal_true() {
        assert!(eval_condition("true", &HashMap::new()).unwrap());
    }

    #[test]
    fn condition_literal_false() {
        assert!(!eval_condition("false", &HashMap::new()).unwrap());
    }

    #[test]
    fn condition_integer_var_eq() {
        let vars = v(&[("status", json!(200i64))]);
        assert!(eval_condition("status == 200", &vars).unwrap());
        assert!(!eval_condition("status == 404", &vars).unwrap());
    }

    #[test]
    fn condition_bool_var() {
        let vars = v(&[("oob_enabled", json!(true))]);
        assert!(eval_condition("oob_enabled", &vars).unwrap());
    }

    #[test]
    fn condition_bool_var_false() {
        let vars = v(&[("oob_enabled", json!(false))]);
        assert!(!eval_condition("oob_enabled", &vars).unwrap());
    }

    #[test]
    fn condition_non_bool_result_coerces_false() {
        // Expression returns integer — as_bool() returns None → false
        assert!(!eval_condition("42", &HashMap::new()).unwrap());
    }

    #[test]
    fn condition_dot_key_flattened_to_underscore() {
        let vars = v(&[("resp.status", json!(200i64))]);
        assert!(eval_condition("resp_status == 200", &vars).unwrap());
    }

    #[test]
    fn condition_syntax_error() {
        assert!(eval_condition("@!@#$", &HashMap::new()).is_err());
    }

    // ── eval_script ───────────────────────────────────────────────────────

    #[test]
    fn script_returns_last_expression() {
        let mut vars = HashMap::new();
        assert_eq!(eval_script("1 + 1", &mut vars, "s").unwrap(), json!(2i64));
    }

    #[test]
    fn script_mutates_existing_var() {
        let mut vars = v(&[("x", json!(10i64))]);
        eval_script("x = x * 2", &mut vars, "s").unwrap();
        assert_eq!(vars["x"], json!(20i64));
    }

    #[test]
    fn script_string_result() {
        let mut vars = HashMap::new();
        assert_eq!(
            eval_script(r#""hello""#, &mut vars, "s").unwrap(),
            json!("hello")
        );
    }

    #[test]
    fn script_syntax_error() {
        let mut vars = HashMap::new();
        assert!(eval_script("let @@@ = 1;", &mut vars, "s").is_err());
    }

    #[test]
    fn script_reads_nested_result_map_property() {
        // A stored step result is a nested object; the script reaches into it as
        // a Rhai map property (how feeds consume `tcp_send`/`http_request` output).
        let mut vars = v(&[("resp", json!({"response_hex": "0102030405"}))]);
        let out = eval_script("substr(resp.response_hex, 2, 5)", &mut vars, "s").unwrap();
        assert_eq!(out, json!("0203"));
    }

    #[test]
    fn script_cve_2022_24706_challenge_digest() {
        // Regression for the CVE-2022-24706 feed: parse the big-endian u32
        // challenge at byte offset 9 (hex offset 18) of the Erlang 'n' reply,
        // then build the challenge-reply frame from MD5("monster"+challenge).
        let reply_hex = "00166e000500000000010203046e6f63746973406d6f636b";
        let mut vars = v(&[("name_reply", json!({"response_hex": reply_hex}))]);
        let code = r#"
            let challenge = u32be(substr(name_reply.response_hex, 18, 25));
            let digest = md5("monster" + challenge.to_string());
            "00157200000000" + digest
        "#;
        let out = eval_script(code, &mut vars, "s").unwrap();
        // challenge 0x01020304 = 16909060; MD5("monster16909060") is fixed.
        assert_eq!(out, json!("00157200000000b4ae6978053f3042dd26b037a0851ba4"));
    }

    // ── json_to_dynamic / dynamic_to_json ─────────────────────────────────

    #[test]
    fn null_roundtrip() {
        let d = json_to_dynamic(&serde_json::Value::Null);
        assert_eq!(dynamic_to_json(d), serde_json::Value::Null);
    }

    #[test]
    fn bool_roundtrip() {
        let d = json_to_dynamic(&json!(true));
        assert_eq!(dynamic_to_json(d), json!(true));
    }

    #[test]
    fn integer_roundtrip() {
        let d = json_to_dynamic(&json!(42i64));
        assert_eq!(dynamic_to_json(d), json!(42i64));
    }

    #[test]
    fn string_roundtrip() {
        let d = json_to_dynamic(&json!("hello"));
        assert_eq!(dynamic_to_json(d), json!("hello"));
    }

    #[test]
    fn float_dynamic_to_json_is_number() {
        let d = Dynamic::from(3.14f64);
        assert!(dynamic_to_json(d).is_number());
    }

    #[test]
    fn array_roundtrip() {
        let d = json_to_dynamic(&json!([1i64, 2i64, 3i64]));
        // Arrays become rhai::Array — dynamic_to_json falls through to to_string
        // We just verify it doesn't panic
        let _ = dynamic_to_json(d);
    }
}

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

    // Write back only the variables the script actually changed. An untouched
    // var keeps its original JSON value, so nested stored results (e.g. a
    // `store_as` object read later as `{{vnc.response_hex}}`) survive (#393).
    for (key, val) in vars.iter_mut() {
        let rhai_name = key.replace('.', "_");
        if let Some(dyn_val) = scope.get_value::<Dynamic>(&rhai_name) {
            let new_val = dynamic_to_json(dyn_val);
            if new_val != dynamic_to_json(json_to_dynamic(val)) {
                *val = new_val;
            }
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
    } else if let Some(arr) = d.clone().try_cast::<rhai::Array>() {
        serde_json::Value::Array(arr.into_iter().map(dynamic_to_json).collect())
    } else if let Some(map) = d.clone().try_cast::<rhai::Map>() {
        serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k.to_string(), dynamic_to_json(v)))
                .collect(),
        )
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
        let v = json!([1i64, "a", [true, null]]);
        assert_eq!(dynamic_to_json(json_to_dynamic(&v)), v);
    }

    #[test]
    fn object_roundtrip() {
        let v = json!({"connected": true, "responses": ["x"], "nested": {"n": 1i64}});
        assert_eq!(dynamic_to_json(json_to_dynamic(&v)), v);
    }

    // ── #393: script must not clobber stored-result objects ──────────────

    #[test]
    fn script_preserves_untouched_stored_object() {
        let stored = json!({
            "connected": true,
            "response_hex": "524642",
            "responses": ["RFB 003.008"],
            "banner": null,
            "port": 18446744073709551615u64
        });
        let mut vars = v(&[("vnc", stored.clone()), ("x", json!(1i64))]);
        eval_script("let y = 42; y", &mut vars, "s").unwrap();
        assert_eq!(vars["vnc"], stored);
        assert_eq!(
            crate::expr::interpolate("{{vnc.response_hex}}", &vars).unwrap(),
            "524642"
        );
        assert!(eval_condition("vnc.connected == true", &vars).unwrap());
    }

    #[test]
    fn script_mutated_object_written_back_as_object() {
        let mut vars = v(&[("r", json!({"a": 1i64}))]);
        eval_script("r.b = 2; r", &mut vars, "s").unwrap();
        assert_eq!(vars["r"], json!({"a": 1i64, "b": 2i64}));
    }
}

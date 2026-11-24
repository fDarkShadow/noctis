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

    /// Run the shipped `general/smb-signing-not-required` feed's parse script
    /// against a canned SMB2 NEGOTIATE reply (hex) — the feed's own code, so a
    /// broken offset in the YAML fails here, not only end-to-end.
    fn smb2_parse(reply_hex: serde_json::Value) -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vulnerabilities/general/smb-signing-not-required.yaml");
        let def = crate::loader::load(&path).unwrap();
        let step = def
            .steps
            .iter()
            .find(|s| s.id == "parse-negotiate")
            .expect("parse-negotiate step");
        let mut vars = v(&[("smb", json!({"connected": true, "response_hex": reply_hex}))]);
        eval_script(step.code.as_deref().unwrap(), &mut vars, "s").unwrap()
    }

    // SMB2 NEGOTIATE response prefix: NBSS + 64-byte SMB2 header (status 0,
    // command NEGOTIATE) + StructureSize 65; then SecurityMode + DialectRevision.
    const SMB2_HDR: &str = "000000aefe534d42400000000000000000000100010000000000000000000000\
                            0000000000000000000000000000000000000000000000000000000000000000\
                            000000004100";

    #[test]
    fn script_smb2_negotiate_signing_not_required() {
        let out = smb2_parse(json!(format!("{SMB2_HDR}0100110301006e6f6374")));
        assert_eq!(out["smb2"], json!(true));
        assert_eq!(out["dialect"], json!("3.1.1"));
        assert_eq!(out["dialect_hex"], json!("0311"));
        assert_eq!(out["security_mode"], json!(1));
        assert_eq!(out["signing_required"], json!(false));
        assert_eq!(out["legacy_only"], json!(false));
    }

    #[test]
    fn script_smb2_negotiate_signing_required() {
        let out = smb2_parse(json!(format!("{SMB2_HDR}0300020300006e6f6374")));
        assert_eq!(out["smb2"], json!(true));
        assert_eq!(out["dialect"], json!("3.0.2"));
        assert_eq!(out["signing_required"], json!(true));
    }

    #[test]
    fn script_smb2_negotiate_legacy_only_dialect() {
        let out = smb2_parse(json!(format!("{SMB2_HDR}0100100200006e6f6374")));
        assert_eq!(out["dialect"], json!("2.1"));
        assert_eq!(out["legacy_only"], json!(true));
        assert_eq!(out["signing_required"], json!(false));
    }

    #[test]
    fn script_smb2_negotiate_rejects_non_smb2_replies() {
        // SMB1 reply, short reply, error status, and no reply at all.
        let smb1 = "00000023ff534d4272000000009853c800000000000000000000000000002f4b00000000010000";
        let err_status = SMB2_HDR.replacen("4000000000000000", "4000000022000000", 1);
        // Our own NEGOTIATE request echoed back (an echo service on an "smb" port):
        // SMB2 signature, status 0, command 0 — but no SERVER_TO_REDIR flag and a
        // request StructureSize of 36, so it must not count as a response.
        let echo = "0000009efe534d42400000000000000000000100000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    000000002400050001000000000000006e6f637469732d736d622d70726f6265\
                    700000000100000002021002000302031103000001002600000000000100200001\
                    006e6f637469732d707265617574682d696e746567726974792d73616c742d3332";
        // A response-shaped reply with an unknown dialect.
        let unknown_dialect = format!("{SMB2_HDR}0100ffff01006e6f6374");
        for reply in [
            json!(smb1),
            json!("0000"),
            json!(format!("{err_status}0100110301006e6f6374")),
            json!(null),
            json!(echo),
            json!(unknown_dialect),
        ] {
            assert_eq!(smb2_parse(reply.clone())["smb2"], json!(false), "{reply}");
        }
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

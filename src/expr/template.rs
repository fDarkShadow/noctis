use std::collections::HashMap;

use crate::error::{NoctisError, Result};

static TEMPLATE_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"\{\{([^}]+)\}\}").expect("static regex"));

pub fn interpolate(template: &str, vars: &HashMap<String, serde_json::Value>) -> Result<String> {
    let re = &*TEMPLATE_RE;
    let mut result = template.to_string();

    for cap in re.captures_iter(template) {
        let placeholder = &cap[0];
        let key = cap[1].trim();

        let value = resolve_path(key, vars)
            .ok_or_else(|| NoctisError::Template(format!("undefined variable: {key}")))?;

        let replacement = match &value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };

        result = result.replacen(placeholder, &replacement, 1);
    }

    Ok(result)
}

pub fn interpolate_lenient(template: &str, vars: &HashMap<String, serde_json::Value>) -> String {
    interpolate(template, vars).unwrap_or_else(|_| template.to_string())
}

fn resolve_path(
    path: &str,
    vars: &HashMap<String, serde_json::Value>,
) -> Option<serde_json::Value> {
    if let Some(v) = vars.get(path) {
        return Some(v.clone());
    }

    let parts: Vec<&str> = path.splitn(2, '.').collect();
    if parts.len() == 2 {
        if let Some(parent) = vars.get(parts[0]) {
            return json_path(parent, parts[1]);
        }
    }

    None
}

fn json_path(root: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = path.splitn(2, '.').collect();
    match root {
        serde_json::Value::Object(map) => {
            let child = map.get(parts[0])?;
            if parts.len() == 1 {
                Some(child.clone())
            } else {
                json_path(child, parts[1])
            }
        }
        _ => None,
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

    #[test]
    fn no_placeholder_passthrough() {
        assert_eq!(
            interpolate("plain text", &HashMap::new()).unwrap(),
            "plain text"
        );
    }

    #[test]
    fn single_string_var() {
        let vars = v(&[("host", json!("example.com"))]);
        assert_eq!(
            interpolate("http://{{host}}/", &vars).unwrap(),
            "http://example.com/"
        );
    }

    #[test]
    fn multiple_vars() {
        let vars = v(&[("scheme", json!("https")), ("host", json!("example.com"))]);
        assert_eq!(
            interpolate("{{scheme}}://{{host}}", &vars).unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn number_to_string() {
        let vars = v(&[("port", json!(8080))]);
        assert_eq!(interpolate("port={{port}}", &vars).unwrap(), "port=8080");
    }

    #[test]
    fn bool_to_string() {
        let vars = v(&[("flag", json!(true))]);
        assert_eq!(interpolate("val={{flag}}", &vars).unwrap(), "val=true");
    }

    #[test]
    fn undefined_var_error() {
        let err = interpolate("{{nope}}", &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("undefined variable"));
    }

    #[test]
    fn lenient_preserves_undefined() {
        assert_eq!(interpolate_lenient("{{nope}}", &HashMap::new()), "{{nope}}");
    }

    #[test]
    fn lenient_resolves_defined() {
        let vars = v(&[("x", json!("ok"))]);
        assert_eq!(interpolate_lenient("{{x}}", &vars), "ok");
    }

    #[test]
    fn whitespace_trimmed_in_key() {
        let vars = v(&[("host", json!("example.com"))]);
        assert_eq!(interpolate("{{ host }}", &vars).unwrap(), "example.com");
    }

    #[test]
    fn dot_notation_one_level() {
        let vars = v(&[("resp", json!({"status": 200}))]);
        assert_eq!(interpolate("{{resp.status}}", &vars).unwrap(), "200");
    }

    #[test]
    fn dot_notation_two_levels() {
        let vars = v(&[("a", json!({"b": {"c": "deep"}}))]);
        assert_eq!(interpolate("{{a.b.c}}", &vars).unwrap(), "deep");
    }

    #[test]
    fn flat_key_beats_dot_traversal() {
        let mut vars = HashMap::new();
        vars.insert("a.b".to_string(), json!("flat"));
        vars.insert("a".to_string(), json!({"b": "nested"}));
        assert_eq!(interpolate("{{a.b}}", &vars).unwrap(), "flat");
    }

    #[test]
    fn dot_path_missing_child_is_error() {
        let vars = v(&[("resp", json!({"status": 200}))]);
        assert!(interpolate("{{resp.missing}}", &vars).is_err());
    }

    #[test]
    fn dot_path_on_non_object_is_error() {
        let vars = v(&[("resp", json!("a string"))]);
        assert!(interpolate("{{resp.field}}", &vars).is_err());
    }
}

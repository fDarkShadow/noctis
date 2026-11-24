use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::checks::raw_socket::Conn;
use crate::model::finding::Finding;
use crate::oob::OobServer;
use crate::scan::request::Credentials;

/// Placeholder substituted for a credential secret in findings and logs.
pub const REDACTED: &str = "<redacted>";

/// Execution context for a single test run.
///
/// Variables are a flat JSON map:
///   - Scalars:  `vars["timeout"] = 5`
///   - Nested:   `vars["response"] = {"status": 200, "body": "..."}`
///
/// Template access `{{response.status}}` resolves via dot-traversal.
pub struct Context {
    pub target_host: String,
    pub target_port: Option<u16>,

    /// All variables (static + dynamic from steps)
    pub vars: HashMap<String, Value>,

    /// Accumulated findings from this test run
    pub findings: Vec<Finding>,

    /// Test-scoped OOB token (auto-generated, available as `{{oob_token}}`)
    pub oob_token: String,

    /// Shared OOB server (None if OOB disabled)
    pub oob_server: Option<Arc<OobServer>>,

    /// Live TCP/TLS connections kept open across steps, keyed by handle name.
    /// Populated by `tcp_open`, written/read by `tcp_send`, dropped by
    /// `tcp_close`. Not serialized and never exposed to the Rhai/template layer.
    pub connections: HashMap<String, Conn>,

    /// Secret values (credential password / token) scrubbed from every finding
    /// field and from logged URLs via [`Context::redact`]. Never exposed.
    secrets: Vec<String>,
    /// One alternation over `secrets` (longest first), so redaction is a single
    /// pass and a short secret can never match inside an inserted `<redacted>`.
    secret_re: Option<regex::Regex>,
}

impl Context {
    pub fn new(
        target_host: impl Into<String>,
        target_port: Option<u16>,
        target_service: &str,
        oob_server: Option<Arc<OobServer>>,
    ) -> Self {
        let oob_token = uuid::Uuid::new_v4().to_string();
        let target_host = target_host.into();

        let scheme = match target_service {
            "https" | "ssl" => "https",
            _ => "http",
        };

        let mut vars = HashMap::new();
        vars.insert(
            "target_host".to_string(),
            Value::String(target_host.clone()),
        );
        vars.insert("scheme".to_string(), Value::String(scheme.to_string()));
        if let Some(p) = target_port {
            vars.insert("target_port".to_string(), Value::Number(p.into()));
            // "port" est le nom conventionnel dans les feeds — prend le dessus sur les vars YAML
            vars.insert("port".to_string(), Value::Number(p.into()));
        }
        vars.insert("oob_token".to_string(), Value::String(oob_token.clone()));
        vars.insert("oob_enabled".to_string(), Value::Bool(oob_server.is_some()));
        if let Some(ref srv) = oob_server {
            vars.insert("oob_host".to_string(), Value::String(srv.host.clone()));
            vars.insert("oob_port".to_string(), Value::Number(srv.port.into()));
            vars.insert(
                "oob_url".to_string(),
                Value::String(format!("http://{}:{}/{}", srv.host, srv.port, oob_token)),
            );
        }

        Self {
            target_host,
            target_port,
            vars,
            findings: Vec::new(),
            oob_token,
            oob_server,
            connections: HashMap::new(),
            secrets: Vec::new(),
            secret_re: None,
        }
    }

    /// Inject scan credentials as context vars, mirroring the OOB vars:
    /// `cred_enabled` is always set (false until credentials are injected);
    /// `cred_username` / `cred_password` / `cred_token` only for the fields supplied.
    /// Call before `seed_vars()` so a feed's `vars:` cannot shadow them.
    pub fn inject_credentials(&mut self, creds: Option<&Credentials>) {
        let Some(c) = creds else {
            self.vars
                .insert("cred_enabled".to_string(), Value::Bool(false));
            return;
        };
        self.vars
            .insert("cred_enabled".to_string(), Value::Bool(true));
        for (key, val) in [
            ("cred_username", &c.username),
            ("cred_password", &c.password),
            ("cred_token", &c.token),
        ] {
            if let Some(v) = val {
                self.vars.insert(key.to_string(), Value::String(v.clone()));
            }
        }
        self.secrets = c.secrets();
        // Longest first so a secret that contains another is masked whole.
        self.secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        self.secret_re = if self.secrets.is_empty() {
            None
        } else {
            let alt = self
                .secrets
                .iter()
                .map(|s| regex::escape(s))
                .collect::<Vec<_>>()
                .join("|");
            regex::Regex::new(&alt).ok()
        };
    }

    /// `true` when credentials with at least one secret value were injected.
    pub fn has_secrets(&self) -> bool {
        !self.secrets.is_empty()
    }

    /// Replace every credential secret (password, token) in `s` with `<redacted>`.
    /// Applied to all finding text and to logged URLs so a feed that echoes a
    /// response (or templates a secret into a URL) never leaks it.
    pub fn redact(&self, s: &str) -> String {
        match &self.secret_re {
            Some(re) => re.replace_all(s, REDACTED).into_owned(),
            // Regex construction cannot realistically fail on escaped literals;
            // fall back to sequential replacement rather than leaking.
            None => {
                let mut out = s.to_string();
                for secret in &self.secrets {
                    out = out.replace(secret.as_str(), REDACTED);
                }
                out
            }
        }
    }

    /// Merge YAML static vars into the context (already-set keys are kept).
    pub fn seed_vars(&mut self, yaml_vars: &indexmap::IndexMap<String, Value>) {
        for (k, v) in yaml_vars {
            self.vars.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    /// Set or update a variable.
    pub fn set(&mut self, key: impl Into<String>, value: Value) {
        self.vars.insert(key.into(), value);
    }

    pub fn add_finding(&mut self, f: Finding) {
        self.findings.push(f);
    }

    pub fn target_label(&self) -> String {
        match self.target_port {
            Some(p) => format!("{}:{}", self.target_host, p),
            None => self.target_host.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(user: Option<&str>, pw: Option<&str>, tok: Option<&str>) -> Credentials {
        Credentials {
            username: user.map(str::to_string),
            password: pw.map(str::to_string),
            token: tok.map(str::to_string),
        }
    }

    #[test]
    fn no_credentials_sets_cred_enabled_false_only() {
        let mut ctx = Context::new("h", Some(80), "http", None);
        ctx.inject_credentials(None);
        assert_eq!(ctx.vars["cred_enabled"], Value::Bool(false));
        assert!(!ctx.vars.contains_key("cred_username"));
        assert!(!ctx.vars.contains_key("cred_password"));
        assert!(!ctx.vars.contains_key("cred_token"));
    }

    #[test]
    fn credentials_injected_as_vars() {
        let mut ctx = Context::new("h", Some(80), "http", None);
        ctx.inject_credentials(Some(&creds(Some("admin"), Some("pw"), None)));
        assert_eq!(ctx.vars["cred_enabled"], Value::Bool(true));
        assert_eq!(ctx.vars["cred_username"], Value::String("admin".into()));
        assert_eq!(ctx.vars["cred_password"], Value::String("pw".into()));
        assert!(!ctx.vars.contains_key("cred_token"));
        let rendered =
            crate::expr::interpolate("{{cred_username}}:{{cred_password}}", &ctx.vars).unwrap();
        assert_eq!(rendered, "admin:pw");
    }

    #[test]
    fn credentials_vars_win_over_yaml_vars() {
        let mut ctx = Context::new("h", Some(80), "http", None);
        ctx.inject_credentials(Some(&creds(Some("admin"), None, Some("tok"))));
        let mut yaml = indexmap::IndexMap::new();
        yaml.insert("cred_token".to_string(), Value::String("from-yaml".into()));
        yaml.insert("cred_enabled".to_string(), Value::Bool(false));
        ctx.seed_vars(&yaml);
        assert_eq!(ctx.vars["cred_token"], Value::String("tok".into()));
        assert_eq!(ctx.vars["cred_enabled"], Value::Bool(true));
    }

    #[test]
    fn cred_enabled_usable_in_condition() {
        let mut ctx = Context::new("h", Some(80), "http", None);
        ctx.inject_credentials(Some(&creds(Some("admin"), None, None)));
        assert!(crate::expr::eval_condition("cred_enabled", &ctx.vars).unwrap());
    }

    #[test]
    fn redact_masks_password_and_token_not_username() {
        let mut ctx = Context::new("h", Some(80), "http", None);
        ctx.inject_credentials(Some(&creds(Some("admin"), Some("hunter2"), Some("tok-1"))));
        assert_eq!(
            ctx.redact("user=admin pass=hunter2 auth=Bearer tok-1"),
            "user=admin pass=<redacted> auth=Bearer <redacted>"
        );
    }

    #[test]
    fn redact_without_credentials_is_identity() {
        let ctx = Context::new("h", Some(80), "http", None);
        assert_eq!(ctx.redact("hunter2"), "hunter2");
    }

    #[test]
    fn redact_is_single_pass_for_short_secrets() {
        let mut ctx = Context::new("h", Some(80), "http", None);
        // "d" must not match inside the "<redacted>" inserted for "dd".
        ctx.inject_credentials(Some(&creds(Some("u"), Some("d"), Some("dd"))));
        assert_eq!(ctx.redact("x dd y"), "x <redacted> y");
        assert!(ctx.has_secrets());
    }
}

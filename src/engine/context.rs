use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::checks::raw_socket::Conn;
use crate::model::finding::Finding;
use crate::oob::OobServer;

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

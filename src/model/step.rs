use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::severity::Severity;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Step {
    pub id: String,

    /// Action type: http_request | tcp_connect | tls_check | ssh_check |
    ///              match | script | wait_oob | set_var
    pub action: String,

    /// Rhai expression — step is skipped if it evaluates to false
    #[serde(default)]
    pub condition: Option<String>,

    #[serde(rename = "loop", default)]
    pub loop_cfg: Option<LoopConfig>,

    #[serde(default)]
    pub store_as: Option<String>,

    #[serde(default)]
    pub on_success: Option<StepOutcome>,
    #[serde(default)]
    pub on_failure: Option<StepOutcome>,
    #[serde(default)]
    pub on_match: Option<StepOutcome>,

    // ── HTTP ──────────────────────────────────────────────────────────────
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Option<IndexMap<String, String>>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub follow_redirects: Option<bool>,
    #[serde(default)]
    pub tls_insecure: bool,

    // ── TCP / SSH ─────────────────────────────────────────────────────────
    // String pour permettre les templates : port: "{{port}}"
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub send: Option<String>,
    #[serde(default)]
    pub auth_methods: Vec<String>,

    // ── Match ─────────────────────────────────────────────────────────────
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub negate: bool,
    #[serde(default)]
    pub case_insensitive: bool,

    // ── Script ────────────────────────────────────────────────────────────
    #[serde(default)]
    pub code: Option<String>,

    // ── wait_oob ──────────────────────────────────────────────────────────
    #[serde(default = "default_oob_timeout")]
    pub oob_timeout_secs: u64,

    // ── set_var ───────────────────────────────────────────────────────────
    #[serde(default)]
    pub var_name: Option<String>,
    #[serde(default)]
    pub var_value: Option<serde_yaml::Value>,

    // ── Common ────────────────────────────────────────────────────────────
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    10
}
fn default_oob_timeout() -> u64 {
    15
}

// ── Loop ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoopConfig {
    #[serde(default)]
    pub over: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    pub count: Option<u64>,
    pub var: String,
}

// ── Step outcome ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StepOutcome {
    #[serde(default)]
    pub finding: Option<FindingSpec>,
    #[serde(default)]
    pub set_vars: Option<IndexMap<String, serde_yaml::Value>>,
    #[serde(default)]
    pub stop: bool,
    #[serde(default)]
    pub condition: Option<String>,
}

// ── Finding spec ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FindingSpec {
    #[serde(default)]
    pub cve: Option<String>,
    #[serde(default)]
    pub cvss: Option<f32>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub confidence_delta: f32,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default = "crate::model::finding::qod::default")]
    pub qod: u8,
}

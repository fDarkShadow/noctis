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
    /// Binary payload as a hex string. For `udp_probe` it is the datagram and
    /// takes precedence over `send`; for `tcp_dialogue` it is a raw frame sent
    /// verbatim (binary mode) instead of `commands`.
    #[serde(default)]
    pub send_hex: Option<String>,
    #[serde(default)]
    pub auth_methods: Vec<String>,

    // ── ssh_exec ──────────────────────────────────────────────────────────
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Explicit credential list to try, each "user:password"; first success wins.
    #[serde(default)]
    pub credentials: Vec<String>,
    /// Command to run once a credential authenticates (stdout/stderr captured).
    #[serde(default)]
    pub command: Option<String>,

    // ── tcp_dialogue ──────────────────────────────────────────────────────
    /// Commands sent in order, each followed by a reply read (line protocols).
    #[serde(default)]
    pub commands: Vec<String>,
    /// Read the server greeting before sending commands (default true).
    #[serde(default)]
    pub read_banner: Option<bool>,
    /// Wrap the connection in TLS (FTPS/SMTPS/IMAPS); default false.
    #[serde(default)]
    pub tls: Option<bool>,
    /// Line terminator appended to each command (default "\r\n").
    #[serde(default)]
    pub line_ending: Option<String>,

    /// `sleep` action: how long to pause, in milliseconds (capped in the runner).
    /// Lets a feed wait between steps (e.g. a write-then-read propagation gap).
    #[serde(default)]
    pub duration_ms: Option<u64>,

    // ── snmp_get (v2c) ────────────────────────────────────────────────────
    #[serde(default)]
    pub community: Option<String>,
    /// Explicit community list to try, first that responds wins.
    #[serde(default)]
    pub communities: Vec<String>,
    /// OIDs to GET (default sysDescr).
    #[serde(default)]
    pub oids: Vec<String>,

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
    pub var_value: Option<serde_json::Value>,

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
    pub over: Option<Vec<serde_json::Value>>,
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
    pub set_vars: Option<IndexMap<String, serde_json::Value>>,
    #[serde(default)]
    pub stop: bool,
    #[serde(default)]
    pub condition: Option<String>,
}

// ── Finding spec ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FindingSpec {
    /// Overrides the feed-level `cves` list for this specific finding. `None` inherits.
    #[serde(default)]
    pub cves: Option<Vec<String>>,
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

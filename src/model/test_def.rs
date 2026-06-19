use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::severity::Severity;
use super::step::Step;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestDef {
    /// Identifiant stable (UUID v4) — obligatoire dans le YAML.
    pub uid: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub kind: TestKind,
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub confidence_base: f32,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,

    #[serde(default)]
    pub cve: Option<String>,
    #[serde(default)]
    pub cvss: Option<f32>,
    #[serde(default)]
    pub category: Option<String>,

    /// Service names this test applies to (e.g. ["http", "https"]).
    /// Empty = run against every discovered port (or the single --port if no discovery).
    #[serde(default)]
    pub services: Vec<String>,

    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(default)]
    pub vars: IndexMap<String, serde_yaml::Value>,

    pub steps: Vec<Step>,
}

fn default_confidence() -> f32 { 0.75 }

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestKind {
    Cve,
    Misconfig,
}

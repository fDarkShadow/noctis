use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::model::test_def::TestDef;

/// A single open port with its detected service name, as returned by nmap -sV or equivalent.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoveredService {
    pub port: u16,
    /// Service name as reported by nmap: "http", "https", "ssh", "ftp", etc.
    pub service: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct ScanRequest {
    #[validate(length(min = 1, message = "host must not be empty"))]
    pub host: String,

    /// Discovered services to scan — at least one entry required.
    /// Each entry is matched against the `services:` field declared in test feeds.
    #[validate(length(min = 1, message = "at least one service entry is required"))]
    pub services: Vec<DiscoveredService>,

    #[validate(length(min = 1, message = "at least one test path is required"))]
    pub tests: Vec<String>,

    #[validate(range(min = 1, max = 100, message = "concurrency must be between 1 and 100"))]
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    #[validate(url(message = "webhook_url must be a valid URL"))]
    #[serde(default)]
    pub webhook_url: Option<String>,

    #[validate(nested)]
    #[serde(default)]
    pub oob: Option<OobConfig>,

    #[validate(nested)]
    #[serde(default)]
    pub filters: Option<ScanFilters>,
}

fn default_concurrency() -> usize { 5 }

// ── OOB ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct OobConfig {
    pub enabled: bool,

    #[validate(length(min = 1, message = "oob.host must not be empty"))]
    pub host: String,

    #[validate(range(min = 1, max = 65535, message = "oob.port must be between 1 and 65535"))]
    #[serde(default = "default_oob_port")]
    pub port: u16,
}

fn default_oob_port() -> u16 { 9090 }

// ── Exclusion filters ─────────────────────────────────────────────────────

/// Filters applied after YAML files are loaded, before execution.
/// All criteria are exclusions (logical OR between them).
#[derive(Debug, Clone, Default, Deserialize, Serialize, Validate)]
pub struct ScanFilters {
    /// Exclude by `uid` (stable UUID defined in the YAML) — reliable identification.
    #[serde(default)]
    pub exclude_uids: Vec<Uuid>,

    /// Exclude CVE tests whose `cve` field matches.
    #[serde(default)]
    pub exclude_cve: Vec<String>,

    /// Exclude by `category` (misconfig YAML field).
    #[serde(default)]
    pub exclude_categories: Vec<String>,

    /// Exclude if at least one of the test's `tags` appears in this list.
    #[serde(default)]
    pub exclude_tags: Vec<String>,
}

impl ScanFilters {
    pub fn is_excluded(&self, def: &TestDef) -> bool {
        if self.exclude_uids.contains(&def.uid) {
            return true;
        }
        if let Some(cve) = &def.cve {
            if self.exclude_cve.contains(cve) {
                return true;
            }
        }
        if let Some(cat) = &def.category {
            if self.exclude_categories.contains(cat) {
                return true;
            }
        }
        if self.exclude_tags.iter().any(|t| def.tags.contains(t)) {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::severity::Severity;
    use crate::model::test_def::{TestDef, TestKind};
    use indexmap::IndexMap;

    fn make_def() -> TestDef {
        TestDef {
            uid: Uuid::new_v4(),
            name: "Test".to_string(),
            description: None,
            kind: TestKind::Misconfig,
            severity: Severity::Info,
            confidence_base: 0.7,
            tags: vec![],
            author: None,
            version: None,
            references: vec![],
            cve: None,
            cvss: None,
            category: None,
            services: vec![],
            includes: vec![],
            vars: IndexMap::new(),
            steps: vec![],
        }
    }

    #[test]
    fn empty_filters_never_exclude() {
        assert!(!ScanFilters::default().is_excluded(&make_def()));
    }

    #[test]
    fn exclude_by_uid_match() {
        let uid = Uuid::new_v4();
        let mut def = make_def();
        def.uid = uid;
        let f = ScanFilters { exclude_uids: vec![uid], ..Default::default() };
        assert!(f.is_excluded(&def));
    }

    #[test]
    fn exclude_by_uid_no_match() {
        let def = make_def();
        let f = ScanFilters { exclude_uids: vec![Uuid::new_v4()], ..Default::default() };
        assert!(!f.is_excluded(&def));
    }

    #[test]
    fn exclude_by_cve_match() {
        let mut def = make_def();
        def.cve = Some("CVE-2021-44228".to_string());
        let f = ScanFilters { exclude_cve: vec!["CVE-2021-44228".to_string()], ..Default::default() };
        assert!(f.is_excluded(&def));
    }

    #[test]
    fn no_cve_field_not_excluded_by_cve_filter() {
        let f = ScanFilters { exclude_cve: vec!["CVE-2021-44228".to_string()], ..Default::default() };
        assert!(!f.is_excluded(&make_def()));
    }

    #[test]
    fn exclude_by_category_match() {
        let mut def = make_def();
        def.category = Some("authentication".to_string());
        let f = ScanFilters { exclude_categories: vec!["authentication".to_string()], ..Default::default() };
        assert!(f.is_excluded(&def));
    }

    #[test]
    fn no_category_not_excluded_by_category_filter() {
        let f = ScanFilters { exclude_categories: vec!["authentication".to_string()], ..Default::default() };
        assert!(!f.is_excluded(&make_def()));
    }

    #[test]
    fn exclude_by_tag_match() {
        let mut def = make_def();
        def.tags = vec!["slow".to_string(), "destructive".to_string()];
        let f = ScanFilters { exclude_tags: vec!["slow".to_string()], ..Default::default() };
        assert!(f.is_excluded(&def));
    }

    #[test]
    fn exclude_by_tag_no_overlap() {
        let mut def = make_def();
        def.tags = vec!["fast".to_string()];
        let f = ScanFilters { exclude_tags: vec!["slow".to_string()], ..Default::default() };
        assert!(!f.is_excluded(&def));
    }
}

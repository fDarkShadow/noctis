use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationError};

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

    /// Credentials for authenticated feeds (`requires_credentials: true`).
    /// Write-only: never serialized back out (GET /scans, webhooks) and
    /// redacted in `Debug` output.
    #[validate(nested)]
    #[serde(default, skip_serializing)]
    pub credentials: Option<Credentials>,
}

fn default_concurrency() -> usize {
    5
}

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

fn default_oob_port() -> u16 {
    9090
}

// ── Credentials ───────────────────────────────────────────────────────────

/// Credentials supplied with a scan, exposed to feeds as `{{cred_username}}`,
/// `{{cred_password}}` and `{{cred_token}}` (plus the boolean `cred_enabled`).
///
/// Every field is optional so token-only auth fits the same shape, but at least
/// one of `username` / `token` must be given, and a `password` needs a `username`.
///
/// Secret hygiene: this type is deliberately **not** `Serialize`, and its `Debug`
/// impl only reports which fields are present — never their values.
#[derive(Clone, Default, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
#[validate(schema(function = "validate_credentials"))]
pub struct Credentials {
    #[validate(length(min = 1, message = "credentials.username must not be empty"))]
    #[serde(default)]
    pub username: Option<String>,

    #[serde(default)]
    pub password: Option<String>,

    /// Bearer / API token — for feeds that authenticate without a username.
    #[validate(length(min = 1, message = "credentials.token must not be empty"))]
    #[serde(default)]
    pub token: Option<String>,
}

fn validate_credentials(c: &Credentials) -> Result<(), ValidationError> {
    if c.username.is_none() && c.token.is_none() {
        return Err(ValidationError::new("credentials_empty")
            .with_message("credentials must set a username or a token".into()));
    }
    if c.password.is_some() && c.username.is_none() {
        return Err(
            ValidationError::new("credentials_password_without_username")
                .with_message("credentials.password requires credentials.username".into()),
        );
    }
    Ok(())
}

impl Credentials {
    /// Values that must never leak into findings or logs: the password and
    /// token as given, their percent-encoded forms (as they appear once
    /// templated into a URL or form body), and the base64 of
    /// `username:password` (an HTTP Basic `Authorization` header). The
    /// username itself is not treated as a secret for scrubbing purposes.
    pub fn secrets(&self) -> Vec<String> {
        use base64::Engine as _;
        let mut out: Vec<String> = Vec::new();
        for raw in [&self.password, &self.token].into_iter().flatten() {
            if raw.is_empty() {
                continue;
            }
            out.push(raw.clone());
            for enc in [percent_encode(raw, false), percent_encode(raw, true)] {
                if enc != *raw {
                    out.push(enc);
                }
            }
        }
        if let (Some(u), Some(p)) = (&self.username, &self.password) {
            if !p.is_empty() {
                out.push(base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")));
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

/// RFC 3986 percent-encoding of everything but unreserved characters;
/// `plus_space` encodes a space as `+` (application/x-www-form-urlencoded).
fn percent_encode(s: &str, plus_space: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b' ' if plus_space => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn mask(v: &Option<String>) -> &'static str {
            if v.is_some() {
                "<redacted>"
            } else {
                "<none>"
            }
        }
        f.debug_struct("Credentials")
            .field("username", &format_args!("{}", mask(&self.username)))
            .field("password", &format_args!("{}", mask(&self.password)))
            .field("token", &format_args!("{}", mask(&self.token)))
            .finish()
    }
}

// ── Exclusion filters ─────────────────────────────────────────────────────

/// Filters applied after YAML files are loaded, before execution.
/// All criteria are exclusions (logical OR between them).
#[derive(Debug, Clone, Default, Deserialize, Serialize, Validate)]
pub struct ScanFilters {
    /// Exclude by `uid` (stable UUID defined in the YAML) — reliable identification.
    #[serde(default)]
    pub exclude_uids: Vec<Uuid>,

    /// Exclude tests whose `cves` list contains any of these CVE IDs.
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
        if self.exclude_cve.iter().any(|c| def.cves.contains(c)) {
            return true;
        }
        if let Some(cat) = &def.category {
            if self.exclude_categories.contains(cat) {
                return true;
            }
        }
        self.exclude_tags.iter().any(|t| def.tags.contains(t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::severity::Severity;
    use crate::model::test_def::TestDef;
    use indexmap::IndexMap;

    fn make_def() -> TestDef {
        TestDef {
            uid: Uuid::new_v4(),
            name: "Test".to_string(),
            description: None,
            severity: Severity::Info,
            confidence_base: 0.7,
            tags: vec![],
            author: None,
            version: None,
            references: vec![],
            cves: vec![],
            cvss: None,
            category: None,
            services: vec![],
            requires_credentials: false,
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
        let f = ScanFilters {
            exclude_uids: vec![uid],
            ..Default::default()
        };
        assert!(f.is_excluded(&def));
    }

    #[test]
    fn exclude_by_uid_no_match() {
        let def = make_def();
        let f = ScanFilters {
            exclude_uids: vec![Uuid::new_v4()],
            ..Default::default()
        };
        assert!(!f.is_excluded(&def));
    }

    #[test]
    fn exclude_by_cve_match() {
        let mut def = make_def();
        def.cves = vec!["CVE-2021-44228".to_string()];
        let f = ScanFilters {
            exclude_cve: vec!["CVE-2021-44228".to_string()],
            ..Default::default()
        };
        assert!(f.is_excluded(&def));
    }

    #[test]
    fn no_cve_field_not_excluded_by_cve_filter() {
        let f = ScanFilters {
            exclude_cve: vec!["CVE-2021-44228".to_string()],
            ..Default::default()
        };
        assert!(!f.is_excluded(&make_def()));
    }

    #[test]
    fn exclude_by_category_match() {
        let mut def = make_def();
        def.category = Some("authentication".to_string());
        let f = ScanFilters {
            exclude_categories: vec!["authentication".to_string()],
            ..Default::default()
        };
        assert!(f.is_excluded(&def));
    }

    #[test]
    fn no_category_not_excluded_by_category_filter() {
        let f = ScanFilters {
            exclude_categories: vec!["authentication".to_string()],
            ..Default::default()
        };
        assert!(!f.is_excluded(&make_def()));
    }

    #[test]
    fn exclude_by_tag_match() {
        let mut def = make_def();
        def.tags = vec!["slow".to_string(), "destructive".to_string()];
        let f = ScanFilters {
            exclude_tags: vec!["slow".to_string()],
            ..Default::default()
        };
        assert!(f.is_excluded(&def));
    }

    #[test]
    fn exclude_by_tag_no_overlap() {
        let mut def = make_def();
        def.tags = vec!["fast".to_string()];
        let f = ScanFilters {
            exclude_tags: vec!["slow".to_string()],
            ..Default::default()
        };
        assert!(!f.is_excluded(&def));
    }

    // ── Credentials ──────────────────────────────────────────────────────

    const BASE: &str = r#""host":"h","services":[{"port":80,"service":"http"}],"tests":["t"]"#;

    fn parse(extra: &str) -> ScanRequest {
        serde_json::from_str(&format!("{{{BASE}{extra}}}")).unwrap()
    }

    #[test]
    fn credentials_absent_by_default() {
        let r = parse("");
        assert!(r.credentials.is_none());
        assert!(r.validate().is_ok());
    }

    #[test]
    fn credentials_deserialize_username_password() {
        let r = parse(r#","credentials":{"username":"admin","password":"s3cr3t"}"#);
        let c = r.credentials.as_ref().unwrap();
        assert_eq!(c.username.as_deref(), Some("admin"));
        assert_eq!(c.password.as_deref(), Some("s3cr3t"));
        assert!(c.token.is_none());
        assert!(r.validate().is_ok());
    }

    #[test]
    fn credentials_token_only_is_valid() {
        let r = parse(r#","credentials":{"token":"tok"}"#);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn credentials_unknown_field_rejected() {
        let raw = format!(r#"{{{BASE},"credentials":{{"user":"admin"}}}}"#);
        assert!(serde_json::from_str::<ScanRequest>(&raw).is_err());
    }

    #[test]
    fn credentials_empty_username_rejected() {
        let r = parse(r#","credentials":{"username":"","password":"x"}"#);
        assert!(r.validate().is_err());
    }

    #[test]
    fn credentials_empty_object_rejected() {
        let r = parse(r#","credentials":{}"#);
        assert!(r.validate().is_err());
    }

    #[test]
    fn credentials_password_without_username_rejected() {
        let r = parse(r#","credentials":{"password":"x","token":"t"}"#);
        assert!(r.validate().is_err());
    }

    #[test]
    fn credentials_empty_token_rejected() {
        let r = parse(r#","credentials":{"token":""}"#);
        assert!(r.validate().is_err());
    }

    #[test]
    fn credentials_validation_error_does_not_echo_values() {
        let r = parse(r#","credentials":{"username":"","password":"s3cr3t-pw"}"#);
        let err = serde_json::to_string(&r.validate().unwrap_err()).unwrap();
        assert!(
            !err.contains("s3cr3t-pw"),
            "password echoed in validation error"
        );
    }

    #[test]
    fn credentials_secrets_cover_encoded_forms() {
        let c = Credentials {
            username: Some("admin".into()),
            password: Some("p w\"d".into()),
            token: None,
        };
        let s = c.secrets();
        assert!(s.contains(&"p w\"d".to_string()));
        assert!(s.contains(&"p%20w%22d".to_string()));
        assert!(s.contains(&"p+w%22d".to_string()));
        // base64("admin:p w\"d") — HTTP Basic auth header value.
        assert!(s.contains(&"YWRtaW46cCB3ImQ=".to_string()));
        assert!(!s.contains(&"admin".to_string()));
    }

    #[test]
    fn credentials_debug_is_redacted() {
        let r = parse(
            r#","credentials":{"username":"admin-user","password":"s3cr3t-pw","token":"tok-xyz"}"#,
        );
        let dbg = format!("{r:?}");
        for secret in ["admin-user", "s3cr3t-pw", "tok-xyz"] {
            assert!(!dbg.contains(secret), "a credential value leaked in Debug");
        }
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn credentials_never_serialized() {
        let r = parse(r#","credentials":{"username":"admin-user","password":"s3cr3t-pw"}"#);
        let out = serde_json::to_string(&r).unwrap();
        assert!(!out.contains("credentials"), "credentials key serialized");
        assert!(!out.contains("s3cr3t-pw"), "password serialized");
        assert!(!out.contains("admin-user"), "username serialized");
    }

    #[test]
    fn credentials_secrets_are_password_and_token() {
        let c = Credentials {
            username: Some("u".into()),
            password: Some("p".into()),
            token: Some(String::new()),
        };
        // password + base64("u:p") for Basic auth; empty token and the
        // username itself are not secrets.
        assert_eq!(c.secrets(), vec!["dTpw".to_string(), "p".to_string()]);
    }
}

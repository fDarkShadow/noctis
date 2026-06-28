use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::severity::Severity;

/// Quality of Detection — aligned with OpenVAS values.
///
/// Reference values:
///   97  remote_app      — OOB callback received (target initiated an outbound connection)
///   75  remote_analysis — response analysis (timing, specific error)
///   70  remote_banner   — version detected in headers / banner
///   50  general         — weak heuristic, generic pattern match
#[allow(dead_code)]
pub mod qod {
    pub const EXPLOIT: u8 = 100;
    pub const REMOTE_APP: u8 = 97;
    pub const REMOTE_ANALYSIS: u8 = 75;
    pub const REMOTE_BANNER: u8 = 70;
    pub const GENERAL: u8 = 50;

    pub fn default() -> u8 {
        REMOTE_BANNER
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingKind {
    Cve {
        cve_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cvss: Option<f32>,
    },
    Misconfig {
        category: String,
        title: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        remediation: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_excerpt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub test_uid: Uuid,
    pub step_id: String,
    #[serde(flatten)]
    pub kind: FindingKind,
    pub severity: Severity,
    /// Confidence score for this finding instance (0.0–1.0)
    pub confidence: f32,
    /// Quality of the detection method (0–100, OpenVAS style)
    pub qod: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    pub target: String,
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        test_uid: Uuid,
        step_id: impl Into<String>,
        kind: FindingKind,
        severity: Severity,
        confidence: f32,
        qod: u8,
        target: impl Into<String>,
        evidence: Option<Evidence>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            test_uid,
            step_id: step_id.into(),
            kind,
            severity,
            confidence: confidence.clamp(0.0, 1.0),
            qod: qod.clamp(0, 100),
            evidence,
            target: target.into(),
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cve_finding(confidence: f32, qod: u8) -> Finding {
        Finding::new(
            Uuid::new_v4(),
            "step-1",
            FindingKind::Cve { cve_id: "CVE-2021-44228".to_string(), cvss: Some(10.0) },
            Severity::Critical,
            confidence,
            qod,
            "10.0.0.1",
            None,
        )
    }

    #[test]
    fn qod_constants_correct() {
        assert_eq!(qod::EXPLOIT, 100);
        assert_eq!(qod::REMOTE_APP, 97);
        assert_eq!(qod::REMOTE_ANALYSIS, 75);
        assert_eq!(qod::REMOTE_BANNER, 70);
        assert_eq!(qod::GENERAL, 50);
        assert_eq!(qod::default(), 70);
    }

    #[test]
    fn confidence_clamped_above_one() {
        assert_eq!(cve_finding(1.5, 70).confidence, 1.0);
    }

    #[test]
    fn confidence_clamped_below_zero() {
        assert_eq!(cve_finding(-0.5, 70).confidence, 0.0);
    }

    #[test]
    fn confidence_exact() {
        assert!((cve_finding(0.75, 70).confidence - 0.75).abs() < f32::EPSILON);
    }

    #[test]
    fn test_uid_propagated() {
        let uid = Uuid::new_v4();
        let f = Finding::new(uid, "s", FindingKind::Cve { cve_id: "CVE-X".to_string(), cvss: None }, Severity::Info, 0.5, 70, "host", None);
        assert_eq!(f.test_uid, uid);
    }

    #[test]
    fn each_finding_has_unique_id() {
        let a = cve_finding(0.5, 70);
        let b = cve_finding(0.5, 70);
        assert_ne!(a.id, b.id);
    }
}

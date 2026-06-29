use serde::Serialize;
use serde_json::Value;

use crate::error::{NoctisError, Result};
use crate::expr;
use crate::model::finding::{Evidence, Finding, FindingKind};
use crate::model::step::{FindingSpec, Step, StepOutcome};
use crate::model::test_def::{TestDef, TestKind};

use super::context::Context;

pub fn to_json<T: Serialize>(v: &T, step: &Step, def: &TestDef) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| NoctisError::StepError {
        test: def.uid.to_string(),
        step: step.id.clone(),
        message: format!("serialize step result: {e}"),
    })
}

pub fn handle_outcome(
    outcome: &Option<StepOutcome>,
    step: &Step,
    def: &TestDef,
    ctx: &mut Context,
    evidence_str: Option<String>,
) -> Result<bool> {
    let Some(out) = outcome else { return Ok(false) };

    if let Some(cond) = &out.condition {
        let interp = expr::interpolate_lenient(cond, &ctx.vars);
        if !expr::eval_condition(&interp, &ctx.vars).unwrap_or(false) {
            return Ok(false);
        }
    }

    if let Some(set_vars) = &out.set_vars {
        for (k, v) in set_vars {
            let raw = serde_json::to_string(v).unwrap_or_default();
            let interp = expr::interpolate_lenient(&raw, &ctx.vars);
            let val = serde_json::from_str(&interp).unwrap_or(Value::String(interp));
            ctx.set(k.clone(), val);
        }
    }

    if let Some(spec) = &out.finding {
        let finding = build_finding(spec, step, def, ctx, evidence_str)?;
        ctx.add_finding(finding);
    }

    Ok(out.stop)
}

fn build_finding(
    spec: &FindingSpec,
    step: &Step,
    def: &TestDef,
    ctx: &Context,
    evidence_raw: Option<String>,
) -> Result<Finding> {
    let confidence = (def.confidence_base + spec.confidence_delta).clamp(0.0, 1.0);
    let severity = spec.severity.unwrap_or(def.severity);

    let kind = match &def.kind {
        TestKind::Cve => FindingKind::Cve {
            cve_id: spec
                .cve
                .clone()
                .or_else(|| def.cve.clone())
                .unwrap_or_else(|| "UNKNOWN".to_string()),
            cvss: spec.cvss.or(def.cvss),
        },
        TestKind::Misconfig => FindingKind::Misconfig {
            category: def
                .category
                .clone()
                .unwrap_or_else(|| "general".to_string()),
            title: spec
                .title
                .as_ref()
                .map(|t| expr::interpolate_lenient(t, &ctx.vars))
                .unwrap_or_else(|| def.name.clone()),
            description: spec
                .description
                .as_ref()
                .map(|d| expr::interpolate_lenient(d, &ctx.vars)),
            remediation: spec
                .remediation
                .as_ref()
                .map(|r| expr::interpolate_lenient(r, &ctx.vars)),
        },
    };

    let evidence = Evidence {
        matched: evidence_raw,
        request: None,
        response_excerpt: spec
            .evidence
            .as_ref()
            .map(|e| expr::interpolate_lenient(e, &ctx.vars)),
    };

    let finding = Finding::new(
        def.uid,
        step.id.clone(),
        kind,
        severity,
        confidence,
        spec.qod,
        ctx.target_label(),
        Some(evidence),
    );

    let label = match &finding.kind {
        FindingKind::Cve { cve_id, .. } => cve_id.clone(),
        FindingKind::Misconfig { title, .. } => title.clone(),
    };
    tracing::info!(
        target = %ctx.target_label(),
        check = %label,
        qod = finding.qod,
        confidence = finding.confidence,
        severity = %finding.severity,
        "finding"
    );

    Ok(finding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::context::Context;
    use crate::model::finding::FindingKind;
    use crate::model::severity::Severity;
    use crate::model::step::{FindingSpec, StepOutcome};
    use crate::model::test_def::{TestDef, TestKind};
    use indexmap::IndexMap;
    use uuid::Uuid;

    fn make_def(kind: TestKind) -> TestDef {
        TestDef {
            uid: Uuid::new_v4(),
            name: "Test".to_string(),
            description: None,
            kind,
            severity: Severity::High,
            confidence_base: 0.8,
            tags: vec![],
            author: None,
            version: None,
            references: vec![],
            cve: Some("CVE-2021-44228".to_string()),
            cvss: Some(10.0),
            category: Some("injection".to_string()),
            services: vec![],
            includes: vec![],
            vars: IndexMap::new(),
            steps: vec![],
        }
    }

    fn make_step(id: &str) -> Step {
        Step {
            id: id.to_string(),
            action: "match".to_string(),
            condition: None,
            loop_cfg: None,
            store_as: None,
            on_success: None,
            on_failure: None,
            on_match: None,
            method: None,
            path: None,
            headers: None,
            body: None,
            follow_redirects: None,
            tls_insecure: false,
            port: None,
            send: None,
            auth_methods: vec![],
            source: None,
            pattern: None,
            negate: false,
            case_insensitive: false,
            code: None,
            oob_timeout_secs: 15,
            var_name: None,
            var_value: None,
            timeout_secs: 10,
        }
    }

    fn make_spec() -> FindingSpec {
        FindingSpec {
            cve: None,
            cvss: None,
            title: Some("Vuln found".to_string()),
            description: None,
            remediation: None,
            confidence_delta: 0.0,
            severity: None,
            evidence: None,
            qod: 75,
        }
    }

    fn ctx() -> Context {
        Context::new("10.0.0.1", Some(8080), "http", None)
    }

    // ── to_json ───────────────────────────────────────────────────────────

    #[test]
    fn to_json_serializes_value() {
        let def = make_def(TestKind::Cve);
        let step = make_step("s");
        let val = serde_json::json!({"status": 200});
        let result = to_json(&val, &step, &def).unwrap();
        assert_eq!(result["status"], 200);
    }

    // ── handle_outcome ────────────────────────────────────────────────────

    #[test]
    fn none_outcome_returns_false_no_stop() {
        let def = make_def(TestKind::Cve);
        let step = make_step("s");
        let mut c = ctx();
        assert!(!handle_outcome(&None, &step, &def, &mut c, None).unwrap());
        assert!(c.findings.is_empty());
    }

    #[test]
    fn outcome_stop_true_returns_true() {
        let def = make_def(TestKind::Cve);
        let step = make_step("s");
        let mut c = ctx();
        let out = StepOutcome {
            finding: None,
            set_vars: None,
            stop: true,
            condition: None,
        };
        assert!(handle_outcome(&Some(out), &step, &def, &mut c, None).unwrap());
    }

    #[test]
    fn outcome_emits_finding() {
        let def = make_def(TestKind::Cve);
        let step = make_step("s");
        let mut c = ctx();
        let out = StepOutcome {
            finding: Some(make_spec()),
            set_vars: None,
            stop: false,
            condition: None,
        };
        handle_outcome(&Some(out), &step, &def, &mut c, None).unwrap();
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn outcome_condition_false_skips() {
        let def = make_def(TestKind::Cve);
        let step = make_step("s");
        let mut c = ctx();
        let out = StepOutcome {
            finding: Some(make_spec()),
            set_vars: None,
            stop: true,
            condition: Some("false".to_string()),
        };
        let stop = handle_outcome(&Some(out), &step, &def, &mut c, None).unwrap();
        assert!(!stop);
        assert!(c.findings.is_empty());
    }

    #[test]
    fn outcome_condition_true_runs() {
        let def = make_def(TestKind::Cve);
        let step = make_step("s");
        let mut c = ctx();
        let out = StepOutcome {
            finding: Some(make_spec()),
            set_vars: None,
            stop: false,
            condition: Some("true".to_string()),
        };
        handle_outcome(&Some(out), &step, &def, &mut c, None).unwrap();
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn outcome_set_vars() {
        let def = make_def(TestKind::Cve);
        let step = make_step("s");
        let mut c = ctx();
        let mut set_vars = IndexMap::new();
        set_vars.insert(
            "foo".to_string(),
            serde_yaml::Value::String("bar".to_string()),
        );
        let out = StepOutcome {
            finding: None,
            set_vars: Some(set_vars),
            stop: false,
            condition: None,
        };
        handle_outcome(&Some(out), &step, &def, &mut c, None).unwrap();
        assert_eq!(c.vars.get("foo"), Some(&serde_json::json!("bar")));
    }

    // ── build_finding (via handle_outcome) ────────────────────────────────

    #[test]
    fn cve_finding_kind() {
        let def = make_def(TestKind::Cve);
        let step = make_step("s");
        let mut c = ctx();
        let out = StepOutcome {
            finding: Some(make_spec()),
            set_vars: None,
            stop: false,
            condition: None,
        };
        handle_outcome(&Some(out), &step, &def, &mut c, None).unwrap();
        assert!(matches!(c.findings[0].kind, FindingKind::Cve { .. }));
    }

    #[test]
    fn misconfig_finding_kind() {
        let def = make_def(TestKind::Misconfig);
        let step = make_step("s");
        let mut c = ctx();
        let out = StepOutcome {
            finding: Some(make_spec()),
            set_vars: None,
            stop: false,
            condition: None,
        };
        handle_outcome(&Some(out), &step, &def, &mut c, None).unwrap();
        assert!(matches!(c.findings[0].kind, FindingKind::Misconfig { .. }));
    }

    #[test]
    fn confidence_clamped_by_delta() {
        let mut def = make_def(TestKind::Cve);
        def.confidence_base = 0.9;
        let mut spec = make_spec();
        spec.confidence_delta = 0.5; // 0.9 + 0.5 = 1.4 → clamped to 1.0
        let step = make_step("s");
        let mut c = ctx();
        let out = StepOutcome {
            finding: Some(spec),
            set_vars: None,
            stop: false,
            condition: None,
        };
        handle_outcome(&Some(out), &step, &def, &mut c, None).unwrap();
        assert_eq!(c.findings[0].confidence, 1.0);
    }

    #[test]
    fn severity_override_from_spec() {
        let def = make_def(TestKind::Cve); // severity: High
        let mut spec = make_spec();
        spec.severity = Some(Severity::Critical);
        let step = make_step("s");
        let mut c = ctx();
        let out = StepOutcome {
            finding: Some(spec),
            set_vars: None,
            stop: false,
            condition: None,
        };
        handle_outcome(&Some(out), &step, &def, &mut c, None).unwrap();
        assert_eq!(c.findings[0].severity, Severity::Critical);
    }
}

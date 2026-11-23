use std::collections::HashSet;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;

use crate::error::{NoctisError, Result};
use crate::model::step::Step;
use crate::model::test_def::TestDef;

/// Load a test definition from `path`, recursively resolving `includes:`.
///
/// Include semantics:
///   - Included vars are merged first; the base test's vars override on conflict.
///   - Included steps are prepended before the base test's steps.
///   - Cycles are detected and rejected.
pub fn load(path: &Path) -> Result<TestDef> {
    let mut visited = HashSet::new();
    load_inner(path, &mut visited)
}

/// Parse one feed document.
///
/// serde-saphyr defaults to YAML 1.1-style inference for untyped values
/// (`vars:`, `var_value:`, `over:`, `set_vars:`): `yes`/`on` would become
/// booleans and `010` a number. These options pin YAML 1.2 Core semantics —
/// the behaviour feeds were written against with serde_yaml — so a var like
/// `answer: yes` or `pin: 0123` stays the string the author wrote.
/// Anti-alias-bomb budgets stay at their (enabled) defaults.
fn parse_feed(raw: &str) -> std::result::Result<TestDef, serde_saphyr::Error> {
    let options = serde_saphyr::options! {
        strict_booleans: true,
        leading_zero_numbers_as_strings: true,
        underscored_numbers_as_strings: true,
    };
    serde_saphyr::from_str_with_options(raw, options)
}

fn load_inner(path: &Path, visited: &mut HashSet<PathBuf>) -> Result<TestDef> {
    let canonical = path
        .canonicalize()
        .map_err(|_| NoctisError::IncludeNotFound(path.display().to_string()))?;

    if visited.contains(&canonical) {
        return Err(NoctisError::IncludeCycle(canonical.display().to_string()));
    }
    visited.insert(canonical.clone());

    let raw = std::fs::read_to_string(&canonical).map_err(NoctisError::Io)?;
    let mut def: TestDef = parse_feed(&raw).map_err(|e| NoctisError::Yaml {
        file: canonical.display().to_string(),
        source: Box::new(e),
    })?;

    if def.includes.is_empty() {
        visited.remove(&canonical);
        return Ok(def);
    }

    let base_dir = canonical.parent().unwrap_or(Path::new("."));

    let mut merged_vars: IndexMap<String, serde_json::Value> = IndexMap::new();
    let mut prepended_steps: Vec<Step> = Vec::new();

    for include_path in &def.includes {
        let inc_path = base_dir.join(include_path);
        let included = load_inner(&inc_path, visited)?;

        // Merge vars: included vars come first, base wins on key conflict
        for (k, v) in included.vars {
            merged_vars.entry(k).or_insert(v);
        }

        // Prepend steps from include (avoid id collisions by prefixing)
        for mut step in included.steps {
            step.id = format!("{}:{}", include_path, step.id);
            prepended_steps.push(step);
        }
    }

    // Base vars override included vars
    for (k, v) in def.vars {
        merged_vars.insert(k, v);
    }

    def.vars = merged_vars;
    prepended_steps.extend(def.steps);
    def.steps = prepended_steps;

    visited.remove(&canonical);
    Ok(def)
}

/// Glob-expand a list of patterns (may be file paths or glob patterns)
/// into resolved PathBufs.
pub fn resolve_test_paths(patterns: &[String]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for pattern in patterns {
        let p = Path::new(pattern);
        if p.is_file() {
            paths.push(p.to_path_buf());
        } else if p.is_dir() {
            collect_yaml(p, &mut paths)?;
        } else {
            // Treat as a glob
            let matches: Vec<_> = glob::glob(pattern)
                .map_err(|e| {
                    NoctisError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
                })?
                .filter_map(|r| r.ok())
                .collect();
            if matches.is_empty() {
                return Err(NoctisError::IncludeNotFound(pattern.clone()));
            }
            paths.extend(matches);
        }
    }
    Ok(paths)
}

fn collect_yaml(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).map_err(NoctisError::Io)? {
        let entry = entry.map_err(NoctisError::Io)?;
        let p = entry.path();
        if p.is_dir() {
            collect_yaml(&p, out)?;
        } else if matches!(p.extension().and_then(|e| e.to_str()), Some("yaml" | "yml")) {
            out.push(p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// Writes a minimal valid YAML file into a temporary directory.
    fn write_yaml(dir: &Path, filename: &str, content: &str) -> PathBuf {
        let path = dir.join(filename);
        std::fs::write(&path, content).unwrap();
        path
    }

    fn tmp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("noctis-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn minimal_yaml(uid: &str) -> String {
        format!("uid: {uid}\nname: Test\ntype: misconfig\nseverity: info\nsteps: []\n")
    }

    // ── load ──────────────────────────────────────────────────────────────

    #[test]
    fn load_valid_file() {
        let dir = tmp_dir();
        let uid = Uuid::new_v4();
        let path = write_yaml(&dir, "test.yaml", &minimal_yaml(&uid.to_string()));
        let def = load(&path).unwrap();
        assert_eq!(def.uid, uid);
        assert_eq!(def.name, "Test");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_nonexistent_file() {
        let err = load(Path::new("/does/not/exist.yaml")).unwrap_err();
        assert!(matches!(err, crate::error::NoctisError::IncludeNotFound(_)));
    }

    #[test]
    fn load_invalid_yaml() {
        let dir = tmp_dir();
        let path = write_yaml(&dir, "bad.yaml", "uid: [\nbroken yaml: {{{{");
        assert!(load(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_missing_uid_field() {
        let dir = tmp_dir();
        let path = write_yaml(
            &dir,
            "no_uid.yaml",
            "name: Test\ntype: misconfig\nseverity: info\nsteps: []\n",
        );
        assert!(load(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_with_include_prepends_steps() {
        let dir = tmp_dir();

        // Included file with one step
        let inc_uid = Uuid::new_v4();
        write_yaml(&dir, "common.yaml", &format!(
            "uid: {inc_uid}\nname: Common\ntype: misconfig\nseverity: info\nsteps:\n  - id: common-step\n    action: set_var\n"
        ));

        // Main file that includes common and adds its own step
        let main_uid = Uuid::new_v4();
        write_yaml(&dir, "main.yaml", &format!(
            "uid: {main_uid}\nname: Main\ntype: misconfig\nseverity: info\nincludes:\n  - common.yaml\nsteps:\n  - id: main-step\n    action: set_var\n"
        ));

        let def = load(&dir.join("main.yaml")).unwrap();
        assert_eq!(def.steps.len(), 2);
        // Included step is prepended
        assert!(def.steps[0].id.contains("common-step"));
        assert_eq!(def.steps[1].id, "main-step");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_include_cycle_detected() {
        let dir = tmp_dir();
        let uid_a = Uuid::new_v4();
        let uid_b = Uuid::new_v4();
        write_yaml(&dir, "a.yaml", &format!(
            "uid: {uid_a}\nname: A\ntype: misconfig\nseverity: info\nincludes:\n  - b.yaml\nsteps: []\n"
        ));
        write_yaml(&dir, "b.yaml", &format!(
            "uid: {uid_b}\nname: B\ntype: misconfig\nseverity: info\nincludes:\n  - a.yaml\nsteps: []\n"
        ));
        let err = load(&dir.join("a.yaml")).unwrap_err();
        assert!(matches!(err, crate::error::NoctisError::IncludeCycle(_)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_include_var_merge_base_wins() {
        let dir = tmp_dir();
        let inc_uid = Uuid::new_v4();
        write_yaml(&dir, "common.yaml", &format!(
            "uid: {inc_uid}\nname: Common\ntype: misconfig\nseverity: info\nvars:\n  shared: from_common\n  only_common: yes\nsteps: []\n"
        ));
        let main_uid = Uuid::new_v4();
        write_yaml(&dir, "main.yaml", &format!(
            "uid: {main_uid}\nname: Main\ntype: misconfig\nseverity: info\nincludes:\n  - common.yaml\nvars:\n  shared: from_main\nsteps: []\n"
        ));
        let def = load(&dir.join("main.yaml")).unwrap();
        assert_eq!(def.vars["shared"].as_str().unwrap(), "from_main");
        assert!(def.vars.contains_key("only_common"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ── resolve_test_paths ────────────────────────────────────────────────

    #[test]
    fn resolve_single_file() {
        let dir = tmp_dir();
        let uid = Uuid::new_v4();
        let path = write_yaml(&dir, "test.yaml", &minimal_yaml(&uid.to_string()));
        let paths = resolve_test_paths(&[path.to_str().unwrap().to_string()]).unwrap();
        assert_eq!(paths.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_directory_finds_yamls() {
        let dir = tmp_dir();
        let uid1 = Uuid::new_v4();
        let uid2 = Uuid::new_v4();
        write_yaml(&dir, "a.yaml", &minimal_yaml(&uid1.to_string()));
        write_yaml(&dir, "b.yml", &minimal_yaml(&uid2.to_string()));
        std::fs::write(dir.join("ignore.txt"), "not yaml").unwrap();
        let paths = resolve_test_paths(&[dir.to_str().unwrap().to_string()]).unwrap();
        assert_eq!(paths.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_nonexistent_pattern_errors() {
        let result = resolve_test_paths(&["/nonexistent/path/*.yaml".to_string()]);
        assert!(result.is_err());
    }

    // ── YAML parser contract (serde-saphyr, see parse_feed) ─────────────────

    /// Every feed and include shipped in the repo must load. Guards the parser
    /// swap and any future YAML-library change against silently dropping feeds.
    #[test]
    fn every_shipped_feed_loads() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut n = 0;
        for pat in ["tests/vulnerabilities/*/*.yaml", "tests/common/*.yaml"] {
            for p in glob::glob(root.join(pat).to_str().unwrap()).unwrap() {
                let p = p.unwrap();
                if let Err(e) = load(&p) {
                    panic!("{} failed to load: {e}", p.display());
                }
                n += 1;
            }
        }
        assert!(n > 100, "expected the shipped feeds, found only {n}");
    }

    const HEAD: &str =
        "uid: 00000000-0000-4000-8000-000000000000\nname: t\nseverity: info\nsteps: []\n";

    /// Untyped values keep YAML 1.2 Core semantics, as they did under serde_yaml.
    #[test]
    fn untyped_vars_use_yaml12_core_resolution() {
        let doc = format!(
            "{HEAD}vars:\n  y: yes\n  on_: on\n  no_: NO\n  oct: 010\n  pin: 0123\n  big: 1_000\n  \
             t: true\n  hex: 0x10\n  f: 1.5\n  n: ~\n  q: \"007\"\n  tpl: '{{{{port}}}}'\n"
        );
        let def = parse_feed(&doc).unwrap();
        let v = |k: &str| def.vars[k].clone();
        use serde_json::json;
        assert_eq!(v("y"), json!("yes"));
        assert_eq!(v("on_"), json!("on"));
        assert_eq!(v("no_"), json!("NO"));
        assert_eq!(v("oct"), json!("010"));
        assert_eq!(v("pin"), json!("0123"));
        assert_eq!(v("big"), json!("1_000"));
        assert_eq!(v("t"), json!(true));
        assert_eq!(v("hex"), json!(16));
        assert_eq!(v("f"), json!(1.5));
        assert_eq!(v("n"), json!(null));
        assert_eq!(v("q"), json!("007"));
        assert_eq!(v("tpl"), json!("{{port}}"));
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let doc = format!("{HEAD}name: again\n");
        let err = parse_feed(&doc).unwrap_err().to_string();
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn parse_error_reports_line() {
        let err = parse_feed(&format!("{HEAD}tags: [unclosed\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("line"), "{err}");
    }
}

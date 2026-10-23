//! String, regex and byte builtin functions for the noctis feed engine.
//!
//! These are registered into the Rhai engine so feed authors can manipulate request
//! and response data directly inside `script` steps and `condition:` expressions —
//! extracting captures, filtering lines, slicing, hex/byte conversions and the like.
//! Pure functions only — no I/O, no new dependencies (std + the existing `regex`
//! crate). See issue #331 / epic #330.
//!
//! Regex functions take an unanchored (partial) pattern; `icase` toggles
//! case-insensitivity. Where a function has an optional `icase` argument, both
//! arities are registered.

use regex::RegexBuilder;
use rhai::{Array, Dynamic, Engine};

fn compile(pattern: &str, icase: bool) -> Option<regex::Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(icase)
        .build()
        .ok()
}

/// `eregmatch(pattern, string)` → `[full, group1, group2, …]`, or `[]` on no match /
/// bad pattern. Element 0 is the whole match and 1.. are the capture groups.
fn eregmatch(pattern: &str, string: &str, icase: bool) -> Array {
    match compile(pattern, icase) {
        Some(re) => match re.captures(string) {
            Some(caps) => caps
                .iter()
                .map(|m| m.map(|x| x.as_str()).unwrap_or("").into())
                .collect(),
            None => Array::new(),
        },
        None => Array::new(),
    }
}

/// `egrep(pattern, string)` → the lines of `string` that match, joined by "\n".
fn egrep(pattern: &str, string: &str, icase: bool) -> String {
    match compile(pattern, icase) {
        Some(re) => string
            .lines()
            .filter(|l| re.is_match(l))
            .collect::<Vec<_>>()
            .join("\n"),
        None => String::new(),
    }
}

fn ereg(pattern: &str, string: &str, icase: bool) -> bool {
    compile(pattern, icase)
        .map(|re| re.is_match(string))
        .unwrap_or(false)
}

fn ereg_replace(pattern: &str, replace: &str, string: &str, icase: bool) -> String {
    match compile(pattern, icase) {
        Some(re) => re.replace_all(string, replace).into_owned(),
        None => string.to_string(),
    }
}

/// `substr(s, start, end)` — `end` inclusive; `substr(s, start)` slices to the end.
fn substr_to_end(s: &str, start: i64) -> String {
    let bytes = s.as_bytes();
    let start = start.max(0) as usize;
    if start >= bytes.len() {
        return String::new();
    }
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn substr_range(s: &str, start: i64, end: i64) -> String {
    let bytes = s.as_bytes();
    let start = start.max(0) as usize;
    if start >= bytes.len() || end < start as i64 {
        return String::new();
    }
    let end = ((end as usize) + 1).min(bytes.len()); // inclusive -> exclusive, clamped
    String::from_utf8_lossy(&bytes[start..end]).into_owned()
}

fn chomp(s: &str) -> String {
    s.trim_end_matches(['\r', '\n', ' ', '\t']).to_string()
}

fn strstr(s: &str, needle: &str) -> String {
    match s.find(needle) {
        Some(i) => s[i..].to_string(),
        None => String::new(),
    }
}

fn stridx(s: &str, needle: &str) -> i64 {
    s.find(needle).map(|i| i as i64).unwrap_or(-1)
}

fn hexstr(s: &str) -> String {
    s.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn ord(s: &str) -> i64 {
    s.as_bytes().first().map(|b| *b as i64).unwrap_or(0)
}

fn crap_n(n: i64) -> String {
    "X".repeat(n.max(0) as usize)
}

/// `crap(length, data)` → `data` repeated/truncated to exactly `length` bytes.
fn crap_data(n: i64, data: &str) -> String {
    let n = n.max(0) as usize;
    if data.is_empty() || n == 0 {
        return String::new();
    }
    data.bytes().cycle().take(n).map(|b| b as char).collect()
}

/// Register all phase-1 string/regex/byte builtins onto `engine`.
pub fn register(engine: &mut Engine) {
    // regex family — with and without the optional icase flag (default false)
    engine.register_fn("eregmatch", |p: &str, s: &str| eregmatch(p, s, false));
    engine.register_fn("eregmatch", |p: &str, s: &str, ic: bool| {
        eregmatch(p, s, ic)
    });
    engine.register_fn("egrep", |p: &str, s: &str| egrep(p, s, false));
    engine.register_fn("egrep", |p: &str, s: &str, ic: bool| egrep(p, s, ic));
    engine.register_fn("ereg", |p: &str, s: &str| ereg(p, s, false));
    engine.register_fn("ereg", |p: &str, s: &str, ic: bool| ereg(p, s, ic));
    engine.register_fn("ereg_replace", |p: &str, r: &str, s: &str| {
        ereg_replace(p, r, s, false)
    });
    engine.register_fn("ereg_replace", |p: &str, r: &str, s: &str, ic: bool| {
        ereg_replace(p, r, s, ic)
    });

    // substrings / indexing
    engine.register_fn("substr", |s: &str, start: i64| substr_to_end(s, start));
    engine.register_fn("substr", |s: &str, start: i64, end: i64| {
        substr_range(s, start, end)
    });
    engine.register_fn("strstr", strstr);
    engine.register_fn("stridx", stridx);

    // case / trimming / length
    engine.register_fn("strlen", |s: &str| s.len() as i64);
    engine.register_fn("tolower", |s: &str| s.to_lowercase());
    engine.register_fn("toupper", |s: &str| s.to_uppercase());
    engine.register_fn("chomp", chomp);
    engine.register_fn("str_replace", |s: &str, find: &str, rep: &str| {
        s.replace(find, rep)
    });

    // bytes / numbers
    engine.register_fn("hexstr", hexstr);
    engine.register_fn("hex", |n: i64| format!("0x{n:x}"));
    engine.register_fn("ord", ord);
    engine.register_fn("crap", crap_n);
    engine.register_fn("crap", crap_data);
    engine.register_fn("int", |s: &str| s.trim().parse::<i64>().unwrap_or(0));
    engine.register_fn("int", |f: f64| f as i64);

    // split(s, sep) -> array of strings
    engine.register_fn("split", |s: &str, sep: &str| -> Array {
        if sep.is_empty() {
            return Array::new();
        }
        s.split(sep).map(|p| Dynamic::from(p.to_string())).collect()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::{Dynamic, Engine};

    fn eng() -> Engine {
        let mut e = Engine::new();
        register(&mut e);
        e
    }

    fn eval<T: Clone + Send + Sync + 'static>(code: &str) -> T {
        eng().eval::<T>(code).expect("eval ok")
    }

    #[test]
    fn eregmatch_returns_groups() {
        let arr: Array = eval(r#"eregmatch("uid=(\\d+)", "x uid=0(root)")"#);
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].clone().into_string().unwrap(), "uid=0");
        assert_eq!(arr[1].clone().into_string().unwrap(), "0");
    }

    #[test]
    fn eregmatch_no_match_is_empty() {
        let arr: Array = eval(r#"eregmatch("ZZZ", "abc")"#);
        assert!(arr.is_empty());
    }

    #[test]
    fn ereg_icase() {
        assert!(!eval::<bool>(r#"ereg("ROOT", "root")"#));
        assert!(eval::<bool>(r#"ereg("ROOT", "root", true)"#));
    }

    #[test]
    fn egrep_filters_lines() {
        let out: String = eval(r#"egrep("gid", "uid=0\ngid=0\nfoo")"#);
        assert_eq!(out, "gid=0");
    }

    #[test]
    fn ereg_replace_works() {
        let out: String = eval(r#"ereg_replace("\\d+", "N", "a1b22c")"#);
        assert_eq!(out, "aNbNc");
    }

    #[test]
    fn substr_inclusive_end_and_to_end() {
        assert_eq!(eval::<String>(r#"substr("abcdef", 2)"#), "cdef");
        assert_eq!(eval::<String>(r#"substr("abcdef", 1, 3)"#), "bcd");
        assert_eq!(eval::<String>(r#"substr("abc", 5)"#), "");
    }

    #[test]
    fn string_helpers() {
        assert_eq!(eval::<i64>(r#"strlen("abc")"#), 3);
        assert_eq!(eval::<String>(r#"tolower("AbC")"#), "abc");
        assert_eq!(eval::<String>(r#"toupper("AbC")"#), "ABC");
        assert_eq!(eval::<String>("chomp(\"hi\\r\\n\")"), "hi");
        assert_eq!(eval::<String>(r#"str_replace("a.b.c", ".", "-")"#), "a-b-c");
        assert_eq!(eval::<String>(r#"strstr("key=value", "=")"#), "=value");
        assert_eq!(eval::<i64>(r#"stridx("key=value", "=")"#), 3);
        assert_eq!(eval::<i64>(r#"stridx("key", "=")"#), -1);
    }

    #[test]
    fn bytes_and_numbers() {
        assert_eq!(eval::<String>(r#"hexstr("AB")"#), "4142");
        assert_eq!(eval::<String>("hex(255)"), "0xff");
        assert_eq!(eval::<i64>(r#"ord("A")"#), 65);
        assert_eq!(eval::<String>("crap(3)"), "XXX");
        assert_eq!(eval::<String>(r#"crap(5, "ab")"#), "ababa");
        assert_eq!(eval::<i64>(r#"int("42")"#), 42);
    }

    #[test]
    fn split_returns_array() {
        let arr: Array = eval(r#"split("a:b:c", ":")"#);
        let got: Vec<String> = arr
            .into_iter()
            .map(|d: Dynamic| d.into_string().unwrap())
            .collect();
        assert_eq!(got, vec!["a", "b", "c"]);
    }
}

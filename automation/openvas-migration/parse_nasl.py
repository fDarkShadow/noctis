#!/usr/bin/env python3
"""Stage 0 — OpenVAS NASL corpus parser (Claude workflow for noctis migration).

Walks a local checkout of the Greenbone NVT feed (nvt-feed/ layout) and emits one
normalized JSON record per .nasl to stdout as JSONL. Pure extraction + a coarse,
deterministic tier classification — no network, no LLM. The subjective call
(is this *worth* porting, and *how*) is left to the Claude triage stage that
consumes this file; here we only pull the facts out of the source reliably.

Run isolated (the corpus is untrusted data):
    python3 -I automation/openvas-migration/parse_nasl.py <corpus_root> > candidates.jsonl

<corpus_root> is the directory that contains openvas-feeds/nvt-feed/ (or the
nvt-feed dir itself). vt-feed/ is deliberately ignored (older duplicate layout).
"""
from __future__ import annotations

import json
import os
import re
import sys

# --- script_tag(name:"X", value:"...") ------------------------------------
# values can be multi-line; capture up to the closing quote+paren, non-greedy.
_TAG_RE = re.compile(
    r'script_tag\s*\(\s*name\s*:\s*"([^"]+)"\s*,\s*value\s*:\s*"(.*?)"\s*\)',
    re.DOTALL,
)
_OID_RE = re.compile(r'script_oid\s*\(\s*"([^"]+)"')
_NAME_RE = re.compile(r'script_name\s*\(\s*"(.*?)"\s*\)', re.DOTALL)
_FAMILY_RE = re.compile(r'script_family\s*\(\s*"([^"]*)"')
_CATEGORY_RE = re.compile(r'script_category\s*\(\s*(ACT_[A-Z_]+)\s*\)')
_CVE_BLOCK_RE = re.compile(r'script_cve_id\s*\((.*?)\)', re.DOTALL)
_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_DEP_BLOCK_RE = re.compile(r'script_dependencies\s*\((.*?)\)', re.DOTALL)
_MKEY_BLOCK_RE = re.compile(r'script_mandatory_keys\s*\((.*?)\)', re.DOTALL)
_RKEY_BLOCK_RE = re.compile(r'script_require_keys\s*\((.*?)\)', re.DOTALL)
_REQ_PORTS_RE = re.compile(r'script_require_ports\s*\((.*?)\)', re.DOTALL)
_INCLUDE_RE = re.compile(r'include\s*\(\s*"([^"]+)"')
_QSTR_RE = re.compile(r'"([^"]*)"')

# Network primitives that mean "this script itself talks to the target".
_ACTIVE_PRIMITIVES = [
    "http_get", "http_post", "http_keepalive_send_recv", "http_send_recv",
    "http_vuln_check", "open_sock_tcp", "open_sock_udp", "send(", "recv(",
    "recv_line", "telnet_negotiate", "ftp_log_in", "smtp_recv_banner",
    "get_http_banner", "http_cgi_dirs", "ssh_login_or_reuse_connection",
]

# Includes / signals that mean "local or credentialed" -> out of scope for noctis.
_LOCAL_INCLUDES = {
    "smb_nt.inc", "smb_func.inc", "secpod_reg.inc", "secpod_smb_func.inc",
    "wmi_file.inc", "wmi_misc.inc", "wmi_os.inc", "wmi_rsop.inc", "wmi_svc.inc",
    "ssh_func.inc", "gather-package-list.inc", "ssh_cmd.inc",
    "policy_functions.inc", "cpe.inc",
}
_VERSION_INCLUDES = {"version_func.inc"}

_LOCAL_FAMILY_HINTS = (
    "local security checks", "windows", "privilege escalation",
    "compliance", "policy", "credentialed",
)
# mandatory/require keys that imply an authenticated / credentialed session
_CRED_KEY_HINTS = (
    "login/ssh/success", "wmi/", "smb/", "tools/present", "kb_smb",
    "ssh/login/", "login/password",
)
# Categories we never port (destructive / DoS) regardless of anything else.
_DESTRUCTIVE_CATS = {"ACT_DENIAL", "ACT_KILL_HOST", "ACT_FLOOD", "ACT_DESTRUCTIVE_ATTACK"}


def _qstrings(block: str | None) -> list[str]:
    if not block:
        return []
    return [s for s in _QSTR_RE.findall(block)]


def _collapse_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def parse_one(path: str, text: str) -> dict:
    tags = {name: val for name, val in _TAG_RE.findall(text)}

    oid_m = _OID_RE.search(text)
    name_m = _NAME_RE.search(text)
    fam_m = _FAMILY_RE.search(text)

    cves = []
    cve_block = _CVE_BLOCK_RE.search(text)
    if cve_block:
        cves = sorted({c.upper() for c in _CVE_RE.findall(cve_block.group(1))})

    categories = _CATEGORY_RE.findall(text)
    includes = _INCLUDE_RE.findall(text)
    deps = _qstrings(_DEP_BLOCK_RE.search(text).group(1)) if _DEP_BLOCK_RE.search(text) else []
    mkeys = _qstrings(_MKEY_BLOCK_RE.search(text).group(1)) if _MKEY_BLOCK_RE.search(text) else []
    rkeys = _qstrings(_RKEY_BLOCK_RE.search(text).group(1)) if _RKEY_BLOCK_RE.search(text) else []
    req_ports = _qstrings(_REQ_PORTS_RE.search(text).group(1)) if _REQ_PORTS_RE.search(text) else []

    primitives = [p.rstrip("(") for p in _ACTIVE_PRIMITIVES if p in text]
    # crude multi-step signal: count distinct send/recv/http request calls
    roundtrips = len(re.findall(r'\b(?:http_get|http_post|http_keepalive_send_recv|http_send_recv|http_vuln_check|send|recv|recv_line)\s*\(', text))

    inc_set = set(includes)
    uses_version_func = bool(inc_set & _VERSION_INCLUDES)
    has_active = bool(primitives) and not (set(primitives) <= {"get_http_banner"} and uses_version_func)
    cvss = tags.get("cvss_base")
    try:
        cvss_f = float(cvss) if cvss else None
    except ValueError:
        cvss_f = None

    rec = {
        "path": path,
        "oid": oid_m.group(1) if oid_m else None,
        "name": _collapse_ws(name_m.group(1)) if name_m else None,
        "family": fam_m.group(1) if fam_m else None,
        "categories": categories,
        "cves": cves,
        "cvss_base": cvss_f,
        "cvss_vector": tags.get("cvss_base_vector"),
        "qod_type": tags.get("qod_type"),
        "qod": tags.get("qod"),
        "solution_type": tags.get("solution_type"),
        "summary": _collapse_ws(tags.get("summary", "")) or None,
        "vuldetect": _collapse_ws(tags.get("vuldetect", "")) or None,
        "affected": _collapse_ws(tags.get("affected", "")) or None,
        "dependencies": deps,
        "mandatory_keys": mkeys,
        "require_keys": rkeys,
        "require_ports": req_ports,
        "includes": includes,
        "primitives": primitives,
        "roundtrips": roundtrips,
        "uses_version_func": uses_version_func,
        "has_active_probe": has_active,
    }
    rec["tier"], rec["tier_reason"] = classify(rec, inc_set)
    return rec


def classify(rec: dict, inc_set: set[str]) -> tuple[str, str]:
    """Coarse deterministic tier. Claude refines eligibility downstream.

    C = out of scope (local/credentialed/destructive/no-probe)
    B = version/banner check (portable only by folding the detect dependency's probe in)
    A = self-contained active network probe (maps directly to noctis)
    """
    cats = set(rec["categories"])
    fam = (rec["family"] or "").lower()
    mkeys = " ".join(rec["mandatory_keys"] + rec["require_keys"]).lower()

    if cats & _DESTRUCTIVE_CATS:
        return "C", f"destructive category {sorted(cats & _DESTRUCTIVE_CATS)}"
    if inc_set & _LOCAL_INCLUDES:
        return "C", f"local/credentialed include {sorted(inc_set & _LOCAL_INCLUDES)}"
    if any(h in fam for h in _LOCAL_FAMILY_HINTS):
        return "C", f"local family '{rec['family']}'"
    if any(h in mkeys for h in _CRED_KEY_HINTS):
        return "C", f"credentialed key '{mkeys[:60]}'"
    if rec["qod_type"] and rec["qod_type"].split("_")[0] in ("package", "registry", "executable"):
        return "C", f"local qod_type {rec['qod_type']}"

    if rec["has_active_probe"]:
        return "A", f"active probe: {rec['primitives']}"
    if rec["uses_version_func"]:
        return "B", "version check (needs detect-dependency probe folded in)"
    return "C", "no network probe and not a version check"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = sys.argv[1]
    if os.path.isdir(os.path.join(root, "openvas-feeds", "nvt-feed")):
        root = os.path.join(root, "openvas-feeds", "nvt-feed")
    elif os.path.basename(root.rstrip("/")) != "nvt-feed" and os.path.isdir(os.path.join(root, "nvt-feed")):
        root = os.path.join(root, "nvt-feed")

    n = 0
    errs = 0
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".nasl"):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                rec = parse_one(rel, text)
                sys.stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n += 1
            except Exception as exc:  # noqa: BLE001 - keep going on a bad file
                errs += 1
                print(f"ERR {rel}: {exc}", file=sys.stderr)
    print(f"parsed {n} nasl files ({errs} errors)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

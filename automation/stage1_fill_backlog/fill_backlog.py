#!/usr/bin/env python3
"""Stage 1 — CVE backlog filler. Runs entirely on the local machine against Ollama; spends
zero Claude/Anthropic tokens. Re-implements fill-backlog.md's sourcing methodology (grep the
local OpenVAS NASL corpus, curl EPSS/KEV, gh search for PoC/Nuclei/Metasploit) deterministically
in Python, and only calls the local model for the two things benchmarked as reliable: the 3
judgment-based scoring points, and transposing a detection strategy from an already-structured
source (never from prose alone — see the "structured-source gate" below).

Output: GitHub issues labeled status:pending-review (NOT status:available — Stage 2 must
promote them after a Claude review pass before a worker can claim them).

Safety: defaults to --dry-run (prints what would be created, makes no GitHub write calls
beyond read-only list/search). Pass --live to actually create issues.
"""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "automation"))

from common import gh, labels, ollama_client  # noqa: E402
from scoring import Candidate, deterministic_points, should_exclude, total_score  # noqa: E402

STATE_DIR = REPO_ROOT / "automation" / "state"
SKIP_CACHE_PATH = STATE_DIR / "prose_only_skipped.json"
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"

BACKLOG_TARGET = 50
MAX_ISSUES_PER_RUN = 12
MAX_RAW_CANDIDATES = 40          # cap on cheap NASL sourcing before enrichment
SKIP_TTL_DAYS = 14                # don't re-attempt a prose-only-skipped CVE for this long

JUDGMENT_MODEL = "qwen2.5-coder:7b"
DRAFT_MODEL = "qwen2.5-coder:7b"

# Recent years + priority vendors, per fill-backlog.md Source A.
NASL_YEARS = ["2023", "2024", "2025"]
VENDOR_KEYWORDS = [
    "apache", "php", "openssh", "nginx", "drupal", "joomla", "wordpress", "gitlab",
    "jenkins", "teamcity", "grafana", "nextcloud", "owncloud", "zoneminder", "roundcube",
    "vmware", "citrix", "ivanti", "paloalto", "fortinet", "cisco", "juniper", "qnap",
    "synology", "moodle", "chamilo",
]
EXCLUDE_PATH_SUBSTR = ["win_", "_win", "local", "package", "ssh_login", "smb_"]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


# ---------------------------------------------------------------------------
# Already-covered / backlog gate
# ---------------------------------------------------------------------------

def load_already_covered_cves() -> set[str]:
    covered: set[str] = set()
    for feed_path in (REPO_ROOT / "tests" / "vulnerabilities").glob("*/*.yaml"):
        text = feed_path.read_text(errors="ignore")
        covered.update(CVE_RE.findall(text))
    try:
        for issue in gh.issue_list(state="all", limit=500, json_fields="title"):
            covered.update(CVE_RE.findall(issue.get("title", "")))
    except gh.GhError as e:
        print(f"WARN: could not list existing issues for dedup: {e}", file=sys.stderr)
    return covered


def count_in_pipeline() -> int:
    try:
        issues = gh.issue_list(state="open", limit=500, json_fields="labels")
    except gh.GhError as e:
        print(f"WARN: could not count in-pipeline issues, assuming 0: {e}", file=sys.stderr)
        return 0
    count = 0
    for issue in issues:
        names = gh.label_names(issue)
        if names & labels.IN_PIPELINE_STATUSES and names & labels.VULN_TYPES:
            count += 1
    return count


# ---------------------------------------------------------------------------
# Skip cache (prose-only candidates — never drafted from unsourced text)
# ---------------------------------------------------------------------------

def load_skip_cache() -> dict:
    if not SKIP_CACHE_PATH.exists():
        return {}
    try:
        return json.loads(SKIP_CACHE_PATH.read_text())
    except json.JSONDecodeError:
        return {}


def save_skip_cache(cache: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    SKIP_CACHE_PATH.write_text(json.dumps(cache, indent=2, sort_keys=True))


def recently_skipped(cache: dict, cve_id: str) -> bool:
    entry = cache.get(cve_id)
    if not entry:
        return False
    try:
        last_seen = datetime.fromisoformat(entry["last_seen"])
    except (KeyError, ValueError):
        return False
    return datetime.now(timezone.utc) - last_seen < timedelta(days=SKIP_TTL_DAYS)


def mark_skipped(cache: dict, cve_id: str, reason: str) -> None:
    cache[cve_id] = {"reason": reason, "last_seen": datetime.now(timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# Source A — OpenVAS NASL corpus (local, free, no network)
# ---------------------------------------------------------------------------

def _nasl_tag(text: str, tag: str) -> str:
    m = re.search(rf'name:"{tag}",\s*value:"(.*?)"\);', text, re.DOTALL)
    return m.group(1).strip() if m else ""


def _nasl_code_body(text: str) -> str:
    """Everything after the description block's closing exit(0);} — i.e. the actual
    executable detection logic (http_get/http_post calls, response checks)."""
    m = re.search(r"exit\(0\);\s*\}\s*", text)
    return text[m.end():].strip()[:4000] if m else ""


def _parse_nasl_candidate(path: Path) -> Candidate | None:
    text = path.read_text(errors="ignore")
    if "ACT_ATTACK" not in text:
        return None

    cve_ids: set[str] = set()
    for call_args in re.findall(r"script_cve_id\(([^)]*)\)", text):
        cve_ids.update(CVE_RE.findall(call_args))
    if not cve_ids:
        return None  # not CVE-attributable — out of scope for this sourcing pass
    cve_ids = sorted(cve_ids)

    cvss_raw = _nasl_tag(text, "cvss_base")
    try:
        cvss = float(cvss_raw) if cvss_raw else None
    except ValueError:
        cvss = None

    summary = _nasl_tag(text, "summary")
    vuldetect = _nasl_tag(text, "vuldetect")
    insight = _nasl_tag(text, "insight")
    code_body = _nasl_code_body(text)

    lowered = (summary + " " + insight + " " + vuldetect).lower()
    requires_auth = "authenticated" in lowered and "unauthenticated" not in lowered and "pre-auth" not in lowered
    is_auth_bypass = "bypass" in lowered

    # Heuristic for a chained multi-request exploit (see scoring.Candidate.is_multi_step):
    # each literal http_keepalive_send_recv( call is one round trip. A loop trying several
    # candidate paths (e.g. foreach over 2 URLs) still shows as a single literal occurrence,
    # so this only fires on genuinely sequential, dependent requests — verified against two
    # real NASL plugins during Phase 1 validation (1 occurrence = simple, 2+ = chained).
    round_trips = code_body.count("http_keepalive_send_recv(")
    is_multi_step = round_trips >= 2

    structured_source_text = "\n".join(
        part for part in [
            f"[vuldetect] {vuldetect}" if vuldetect else "",
            f"[code body]\n{code_body}" if code_body else "",
        ] if part
    )

    return Candidate(
        cve_ids=cve_ids,
        cvss=cvss,
        epss=None,
        is_kev=False,
        requires_local_agent=False,  # already filtered by path substring before this is called
        requires_auth_session=requires_auth,
        is_documented_auth_bypass=is_auth_bypass,
        is_multi_step=is_multi_step,
        product=path.parent.name,
        nasl_path=str(path.relative_to(REPO_ROOT)),
        summary=summary or insight,
        structured_source_text=structured_source_text,
    )


def source_nasl_candidates(already_covered: set[str], skip_cache: dict) -> list[Candidate]:
    candidates: list[Candidate] = []
    seen_cves: set[str] = set()

    nasl_files: list[Path] = []
    for year in NASL_YEARS:
        year_dir = REPO_ROOT / "openvas" / "openvas" / "plugins" / year
        if not year_dir.exists():
            continue
        for f in year_dir.rglob("*.nasl"):
            path_lower = str(f).lower()
            if any(bad in path_lower for bad in EXCLUDE_PATH_SUBSTR):
                continue
            if not any(v in path_lower for v in VENDOR_KEYWORDS):
                continue
            nasl_files.append(f)

    for f in nasl_files:
        if len(candidates) >= MAX_RAW_CANDIDATES:
            break
        cand = _parse_nasl_candidate(f)
        if cand is None:
            continue
        if any(c in already_covered for c in cand.cve_ids):
            continue
        if any(recently_skipped(skip_cache, c) for c in cand.cve_ids):
            continue
        primary_cve = cand.cve_ids[0]
        if primary_cve in seen_cves:
            continue
        seen_cves.add(primary_cve)
        candidates.append(cand)

    return candidates


# ---------------------------------------------------------------------------
# Source B/G — EPSS + KEV (cheap batch lookups, applied before expensive enrichment)
# ---------------------------------------------------------------------------

def enrich_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}
    result: dict[str, float] = {}
    # FIRST.org accepts a comma-joined batch; keep batches modest to avoid URL-length issues.
    for i in range(0, len(cve_ids), 50):
        batch = cve_ids[i:i + 50]
        url = "https://api.first.org/data/v1/epss?cve=" + ",".join(batch)
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = json.loads(resp.read())
            for row in data.get("data", []):
                try:
                    result[row["cve"]] = float(row["epss"])
                except (KeyError, ValueError):
                    continue
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"WARN: EPSS batch lookup failed: {e}", file=sys.stderr)
    return result


def load_kev() -> set[str]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"WARN: KEV lookup failed, treating all as not-KEV: {e}", file=sys.stderr)
        return set()


# ---------------------------------------------------------------------------
# Sources C/D/F — PoC / Nuclei / Metasploit (per-candidate gh calls — only for survivors)
# ---------------------------------------------------------------------------

def enrich_poc_stars(cve_id: str) -> int:
    try:
        out = subprocess.run(
            ["gh", "search", "repos", cve_id, "--sort", "stars", "--limit", "5",
             "--json", "stargazersCount"],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return 0
        rows = json.loads(out.stdout or "[]")
        return max((r.get("stargazersCount", 0) for r in rows), default=0)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return 0


def enrich_nuclei(cve_id: str) -> bool:
    try:
        out = subprocess.run(
            ["gh", "api", f"search/code?q={cve_id}+repo:projectdiscovery/nuclei-templates"],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return False
        data = json.loads(out.stdout or "{}")
        return bool(data.get("items"))
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return False


def enrich_metasploit(cve_id: str) -> bool:
    try:
        out = subprocess.run(
            ["gh", "api", f"search/code?q={cve_id}+repo:rapid7/metasploit-framework"],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return False
        data = json.loads(out.stdout or "{}")
        return bool(data.get("items"))
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return False


# ---------------------------------------------------------------------------
# LLM steps — judgment scoring (3 points) and structured-source-only drafting
# ---------------------------------------------------------------------------

def llm_judgment_score(cand: Candidate) -> tuple[int, str]:
    static_prompt = (PROMPTS_DIR / "judgment_score.txt").read_text()
    candidate_dump = (
        f"CVE: {', '.join(cand.cve_ids)}\n"
        f"Product: {cand.product}\n"
        f"CVSS: {cand.cvss}\n"
        f"Summary: {cand.summary}\n"
        f"NASL source: {cand.nasl_path}\n"
    )
    try:
        raw = ollama_client.generate(JUDGMENT_MODEL, static_prompt + candidate_dump)
        raw = re.sub(r"^```[a-zA-Z]*\n|\n```$", "", raw.strip())
        # Defense-in-depth: the model sometimes echoes a leading "+" from the prompt's own
        # "+2 if..." style wording into the JSON numbers it emits (e.g. "+2"), which is not
        # valid JSON and used to crash json.loads outright (found during Phase 1 validation —
        # the prompt itself has since been reworded to avoid "+N", this just guards the rest).
        raw = re.sub(r':\s*\+(\d)', r': \1', raw)
        parsed = json.loads(raw)
        pts = (int(bool(parsed.get("unauthenticated_detection"))) * 2
               + int(bool(parsed.get("widely_deployed_product")))
               + int(bool(parsed.get("documented_apt_campaign"))))
        return pts, parsed.get("justification", "")
    except (ollama_client.OllamaError, json.JSONDecodeError, ValueError) as e:
        print(f"WARN: judgment scoring failed for {cand.cve_ids}, defaulting to 0: {e}", file=sys.stderr)
        return 0, ""


def _has_unfilled_placeholder(detection_strategy: str) -> bool:
    """Cheap deterministic guard: a genuine drafted endpoint never contains a literal '<'
    character, but a model that echoes the prompt's own template scaffolding instead of
    filling it in does (e.g. "POST <path, verbatim from the structured source>" — a real
    defect first caught by Stage 2 review in production; this check exists to catch it
    before an issue is even created, saving a full Stage 2 round trip)."""
    m = re.search(r"^Target endpoint\(s\):\s*(.*)$", detection_strategy, re.MULTILINE)
    return bool(m) and "<" in m.group(1)


def draft_detection_strategy(cand: Candidate) -> str:
    # Deliberately does NOT embed a reference feed here (unlike Stage 3's future feed-YAML
    # drafting, where a one-shot reference example was benchmarked as necessary). This prompt
    # only needs a short plain-text summary for an issue body, not YAML — an earlier version
    # that showed a reference feed "to match its structure" confused the model into drafting
    # a full feed (complete with an invented uid and a fake KB url that degenerated into a
    # repetition loop). See reference_feeds.py for where that technique belongs (Stage 3).
    static_prompt = (PROMPTS_DIR / "draft_detection_strategy.txt").read_text()
    body = (
        static_prompt
        + "=== STRUCTURED SOURCE (summarize this, do not invent anything beyond it) ===\n"
        + f"NASL file: {cand.nasl_path}\n"
        + cand.structured_source_text
        + "\n"
    )
    try:
        raw = ollama_client.generate(DRAFT_MODEL, body, num_predict=400)
        return re.sub(r"^```[a-zA-Z]*\n|\n```$", "", raw.strip())
    except ollama_client.OllamaError as e:
        print(f"WARN: drafting failed for {cand.cve_ids}: {e}", file=sys.stderr)
        return ""


# ---------------------------------------------------------------------------
# Issue body + creation
# ---------------------------------------------------------------------------

def build_issue_body(cand: Candidate, score: int, priority: str, detection_strategy: str,
                      justification: str) -> str:
    cve_line = ", ".join(cand.cve_ids) if cand.cve_ids else "None"
    kev_line = "yes" if cand.is_kev else "no"
    epss_line = f"{cand.epss:.3f}" if cand.epss is not None else "N/A"
    return f"""### CVE ID(s)
{cve_line}

### Product / component
{cand.product}

### CVSS v3 score
{cand.cvss if cand.cvss is not None else "N/A"}

### Target services
http, https

### Threat intelligence
- **EPSS**: {epss_line}
- **KEV CISA**: {kev_line}
- **Public PoC**: {"yes, " + str(cand.poc_stars) + " stars" if cand.poc_stars else "none found"}
- **Nuclei template**: {"yes" if cand.has_nuclei_template else "no"}
- **Metasploit module**: {"yes" if cand.has_metasploit_module else "no"}
- **Score**: {score}/15 ({priority})
- **Stage 1 judgment note**: {justification}

### Description
{cand.summary}

### Detection strategy
{detection_strategy}

### References
- https://nvd.nist.gov/vuln/detail/{cand.cve_ids[0] if cand.cve_ids else ""}
- OpenVAS plugin: {cand.nasl_path}

---
*Sourced automatically by automation/stage1_fill_backlog. Labeled status:pending-review —
awaiting Claude triage (Stage 2) before a worker can claim it.*
"""


def create_issue(cand: Candidate, score: int, priority: str, detection_strategy: str,
                  justification: str, live: bool) -> None:
    body = build_issue_body(cand, score, priority, detection_strategy, justification)
    primary = cand.cve_ids[0] if cand.cve_ids else cand.product
    title = f"{primary} — {cand.product} (score {score}/15{', KEV' if cand.is_kev else ''})"
    issue_labels = [labels.TYPE_CVE, labels.STATUS_PENDING_REVIEW, priority]

    if not live:
        print(f"\n[DRY-RUN] Would create issue: {title}")
        print(f"  labels: {issue_labels}")
        print(f"  body preview:\n{body[:600]}...\n")
        return

    result = gh.issue_create(title, body, issue_labels)
    print(f"Created issue #{result['number']}: {result['url']}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true",
                         help="Actually create GitHub issues. Default is dry-run (prints only).")
    parser.add_argument("--max-candidates", type=int, default=None,
                         help="Override MAX_RAW_CANDIDATES for a smaller manual test run.")
    parser.add_argument("--max-issues", type=int, default=None,
                         help="Override MAX_ISSUES_PER_RUN for a smaller manual test run.")
    args = parser.parse_args()

    global MAX_RAW_CANDIDATES, MAX_ISSUES_PER_RUN
    if args.max_candidates is not None:
        MAX_RAW_CANDIDATES = args.max_candidates
    if args.max_issues is not None:
        MAX_ISSUES_PER_RUN = args.max_issues

    in_pipeline = count_in_pipeline()
    print(f"In-pipeline backlog count: {in_pipeline} (target {BACKLOG_TARGET})")
    if in_pipeline >= BACKLOG_TARGET:
        print("Backlog target already met — exiting without sourcing.")
        return

    print("Loading already-covered CVEs...")
    already_covered = load_already_covered_cves()
    print(f"  {len(already_covered)} CVEs already covered or already tracked as issues.")

    skip_cache = load_skip_cache()

    print(f"Sourcing raw candidates from OpenVAS NASL corpus (years {NASL_YEARS})...")
    raw_candidates = source_nasl_candidates(already_covered, skip_cache)
    print(f"  {len(raw_candidates)} raw candidates found.")

    if not raw_candidates:
        print("No new candidates this run.")
        return

    all_cves = [c.cve_ids[0] for c in raw_candidates]
    print("Batch EPSS lookup...")
    epss_map = enrich_epss_batch(all_cves)
    print("KEV catalogue lookup...")
    kev_set = load_kev()

    for c in raw_candidates:
        primary = c.cve_ids[0]
        c.epss = epss_map.get(primary)
        c.is_kev = primary in kev_set

    survivors: list[Candidate] = []
    excluded_count = 0
    for c in raw_candidates:
        excluded, reason = should_exclude(c)
        if excluded:
            excluded_count += 1
            print(f"  EXCLUDED {c.cve_ids[0]}: {reason}")
            continue
        survivors.append(c)
    print(f"  {len(survivors)} survivors after exclusion rule ({excluded_count} excluded).")

    if not survivors:
        print("No candidates survived the exclusion rule this run.")
        return

    print(f"Enriching {len(survivors)} survivors with PoC/Nuclei/Metasploit (rate-limited)...")
    for c in survivors:
        primary = c.cve_ids[0]
        c.poc_stars = enrich_poc_stars(primary)
        time.sleep(1.0)
        c.has_nuclei_template = enrich_nuclei(primary)
        time.sleep(1.0)
        c.has_metasploit_module = enrich_metasploit(primary)
        time.sleep(1.0)

    scored: list[tuple[Candidate, int, str, str]] = []
    for c in survivors:
        det_pts = deterministic_points(c)
        judgment_pts, justification = llm_judgment_score(c)
        score = total_score(det_pts, judgment_pts)
        priority = labels.priority_for_score(score)
        scored.append((c, score, priority, justification))

    scored.sort(key=lambda t: t[1], reverse=True)

    created = 0
    prose_only = 0
    for c, score, priority, justification in scored:
        if created >= MAX_ISSUES_PER_RUN:
            print(f"Reached MAX_ISSUES_PER_RUN ({MAX_ISSUES_PER_RUN}), stopping.")
            break

        if len(c.structured_source_text) < 80:
            prose_only += 1
            mark_skipped(skip_cache, c.cve_ids[0], "no structured source captured (prose-only)")
            print(f"  SKIP {c.cve_ids[0]}: no structured source — logged, not issued this run.")
            continue

        if c.is_multi_step:
            prose_only += 1
            mark_skipped(skip_cache, c.cve_ids[0],
                         "multi-step/chained NASL source — automated drafting unreliable "
                         "(Phase 1 validation found the model collapses chained requests into "
                         "a naive single-status check, dropping the real confirmation condition)")
            print(f"  SKIP {c.cve_ids[0]}: multi-step source — needs manual detection strategy.")
            continue

        detection_strategy = draft_detection_strategy(c)
        if not detection_strategy.strip():
            prose_only += 1
            mark_skipped(skip_cache, c.cve_ids[0], "drafting failed / empty output")
            continue
        if _has_unfilled_placeholder(detection_strategy):
            prose_only += 1
            mark_skipped(skip_cache, c.cve_ids[0],
                         "drafting left the template placeholder unfilled (weak/thin source)")
            print(f"  SKIP {c.cve_ids[0]}: drafted output left an unfilled template placeholder.")
            continue

        create_issue(c, score, priority, detection_strategy, justification, live=args.live)
        created += 1

    save_skip_cache(skip_cache)

    print("\n=== Stage 1 — results ===")
    print(f"Raw candidates sourced   : {len(raw_candidates)}")
    print(f"Excluded (rule)          : {excluded_count}")
    print(f"Survivors scored         : {len(survivors)}")
    print(f"Skipped (prose-only)     : {prose_only}")
    print(f"Issues {'created' if args.live else 'that WOULD be created (dry-run)'} : {created}")


if __name__ == "__main__":
    main()

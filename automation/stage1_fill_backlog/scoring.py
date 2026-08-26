"""Deterministic part of fill-backlog's 15-point scoring table + exclusion rule.

9 of the 12 criteria (KEV, EPSS tiers, PoC-star tiers, Nuclei-exists, Metasploit-exists,
CVSS tiers) are pure arithmetic over facts already fetched via curl/gh in fill_backlog.py —
there is no reason to risk a model call or a hallucination on arithmetic, and it also acts
as a free pre-filter before any LLM or expensive gh-search enrichment call is spent.

Only the 3 genuinely judgment-based points (unauthenticated detection, widely-deployed
product, documented APT/campaign) are scored by the local model — see prompts/judgment_score.txt
and fill_backlog.py's llm_judgment_score(). That split is the benchmarked-safe boundary:
arithmetic stays deterministic, subjective calls go to the model where it was shown reliable.
"""
from dataclasses import dataclass, field


@dataclass
class Candidate:
    cve_ids: list[str]                  # [] for a 0-CVE misconfig check
    cvss: float | None
    epss: float | None                  # 0.0-1.0, None if lookup failed
    is_kev: bool
    poc_stars: int = 0                  # 0 if no PoC found
    has_nuclei_template: bool = False
    has_metasploit_module: bool = False
    requires_local_agent: bool = False  # smb_login / ssh_login / local NASL category
    requires_auth_session: bool = False # exploitation needs an authenticated session
    is_documented_auth_bypass: bool = False  # exception to the auth-session exclusion
    is_multi_step: bool = False         # >=2 request/response round trips in the NASL source —
                                         # see fill_backlog.py's structured-source gate: the local
                                         # model was found (Phase 1 manual validation) to silently
                                         # collapse a chained multi-request exploit into a naive
                                         # single-status-code check, dropping the real confirmation
                                         # condition. Not reliable yet; gated out of drafting.
    # enrichment / provenance fields, not scored directly here:
    product: str = ""
    nasl_path: str = ""
    summary: str = ""
    structured_source_text: str = ""    # vuldetect/nuclei/PoC excerpt; empty => prose-only
    extra: dict = field(default_factory=dict)


def deterministic_points(c: Candidate) -> dict[str, int]:
    """The 9 objective point contributions, keyed by criterion name."""
    pts: dict[str, int] = {}
    pts["kev"] = 4 if c.is_kev else 0

    if c.epss is not None and c.epss >= 0.90:
        pts["epss"] = 3
    elif c.epss is not None and c.epss >= 0.50:
        pts["epss"] = 1
    else:
        pts["epss"] = 0

    if c.poc_stars >= 100:
        pts["poc"] = 2
    elif c.poc_stars >= 10:
        pts["poc"] = 1
    else:
        pts["poc"] = 0

    pts["nuclei"] = 2 if c.has_nuclei_template else 0
    pts["metasploit"] = 1 if c.has_metasploit_module else 0

    if c.cvss is not None and c.cvss >= 9.0:
        pts["cvss"] = 2
    elif c.cvss is not None and c.cvss >= 7.0:
        pts["cvss"] = 1
    else:
        pts["cvss"] = 0

    return pts


def should_exclude(c: Candidate) -> tuple[bool, str]:
    """Mirrors fill-backlog.md's exclusion rule exactly.

    Note this only needs CVSS + KEV + EPSS (all cheap/batch lookups) — deliberately checked
    BEFORE the more expensive per-candidate PoC/Nuclei/Metasploit gh-search enrichment in
    fill_backlog.py, so excluded candidates never burn those rate-limited calls.
    """
    if (c.cvss is not None and c.cvss < 7.0
            and not c.is_kev
            and (c.epss is None or c.epss < 0.50)):
        return True, f"CVSS {c.cvss} < 7.0, not KEV, EPSS {c.epss} < 0.50"

    if c.requires_local_agent:
        return True, "detection requires a local agent (smb_login/ssh_login/local plugin)"

    if c.requires_auth_session and not c.is_documented_auth_bypass:
        return True, "exploitation requires an authenticated session and is not a documented auth-bypass"

    return False, ""


def total_score(deterministic: dict[str, int], judgment_points: int) -> int:
    return sum(deterministic.values()) + judgment_points

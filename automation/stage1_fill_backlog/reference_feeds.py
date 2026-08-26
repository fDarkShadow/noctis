"""Keyword -> reference feed path table, verbatim from CLAUDE.md's "Reference feeds to copy
from" section. All 10 paths verified to exist against the current tests/vulnerabilities/<vendor>/
layout on 2026-08-26 (the repo was refactored from tests/cve/ around that date — see memory
project-tests-layout-refactor).

Meant to be used when actually drafting a full noctis feed YAML — a one-shot reference example
in the prompt is what took the local model from 19/21 to 26/27 on the pitfall checklist during
benchmarking (it fixes the step-envelope, not the model's own knowledge of noctis's YAML shape).

NOT currently imported by Stage 1's fill_backlog.py: an earlier version used this to draft the
issue-body's plain-text "Detection strategy" section, but showing a full feed YAML "to match
its structure" while also asking for plain text confused the model into drafting a full feed
instead (complete with an invented uid and a hallucinated URL that degenerated into a repeat
loop). This technique belongs to feed-YAML generation specifically — reserved for Stage 3's
worker (Phase 4), which drafts the actual committed feed and needs exactly this pattern.
"""

REFERENCE_FEEDS: list[tuple[list[str], str]] = [
    (["path traversal", "directory traversal", "lfi", "%2e", "../", "arbitrary file read"],
     "tests/vulnerabilities/pulse-secure/CVE-2019-11510.yaml"),
    (["header injection", "shellshock", "env variable", "environment variable"],
     "tests/vulnerabilities/shellshock/CVE-2014-6271.yaml"),
    (["auth bypass", "authentication bypass"],
     "tests/vulnerabilities/bigip/CVE-2022-1388.yaml"),
    (["ssh banner", "openssh", "ssh version"],
     "tests/vulnerabilities/regresshion/CVE-2024-6387.yaml"),
    (["oob", "out-of-band", "blind", "log4j", "jndi", "callback"],
     "tests/vulnerabilities/log4shell/CVE-2021-44228.yaml"),
    (["ognl", "template injection", "ssti", "expression language"],
     "tests/vulnerabilities/confluence/CVE-2022-26134.yaml"),
    (["chain", "multi-step", "pre-auth rce", "two-stage"],
     "tests/vulnerabilities/ivanti/CVE-2023-46805.yaml"),
    (["exposed path", "exposed endpoint", "static list", "sensitive file"],
     "tests/vulnerabilities/general/exposed-paths.yaml"),
    (["weak auth", "default credentials", "default password"],
     "tests/vulnerabilities/general/ssh-weak-auth.yaml"),
    (["tls", "weak cipher", "ssl", "certificate"],
     "tests/vulnerabilities/general/tls-weak-config.yaml"),
]

# Most common pattern among network-active NASL checks (HTTP request + response-body match).
DEFAULT_REFERENCE_FEED = "tests/vulnerabilities/pulse-secure/CVE-2019-11510.yaml"


def pick_reference_feed(text: str) -> str:
    """Case-insensitive keyword match against the candidate's summary/insight/vuldetect text."""
    lowered = text.lower()
    for keywords, path in REFERENCE_FEEDS:
        if any(kw in lowered for kw in keywords):
            return path
    return DEFAULT_REFERENCE_FEED

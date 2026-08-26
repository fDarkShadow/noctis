"""Thin JSON wrapper around the `gh` CLI.

Only what Stage 1 needs today (list + create issues). Stage 2/4 will extend this module
when they're built (Phase 2/3) rather than pre-stubbing PR operations no one can test yet.
"""
import json
import subprocess


class GhError(RuntimeError):
    pass


def _run(args: list[str]) -> str:
    result = subprocess.run(["gh", *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise GhError(f"gh {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def issue_list(state: str = "open", limit: int = 500,
               json_fields: str = "number,title,state,labels") -> list[dict]:
    """No --label filtering here on purpose: gh's --label ANDs multiple values, but the
    backlog-gate and dedup logic both need OR-style membership checks across label sets.
    Simpler and more robust to fetch and filter in Python (see labels.IN_PIPELINE_STATUSES)."""
    args = ["issue", "list", "--state", state, "--limit", str(limit), "--json", json_fields]
    return json.loads(_run(args))


def issue_create(title: str, body: str, labels: list[str]) -> dict:
    args = ["issue", "create", "--title", title, "--body", body]
    for label in labels:
        args += ["--label", label]
    url = _run(args).strip()
    number = int(url.rstrip("/").rsplit("/", 1)[-1])
    return {"number": number, "url": url}


def label_names(issue: dict) -> set[str]:
    """`gh issue list --json labels` returns [{"id":..,"name":..}, ...] per issue."""
    return {label["name"] for label in issue.get("labels", [])}

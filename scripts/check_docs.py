#!/usr/bin/env python3
"""Documentation drift guard.

Deterministic check that the human docs (README.md, CLAUDE.md) stay in sync with
the engine's real surface. It cannot *write* prose — it fails loudly when the docs
fall behind the code, so a reviewer (or the pre-push hook / CI) catches the drift
instead of shipping stale docs. Run from the repo root:

    python3 scripts/check_docs.py

Checks:
  1. Every `action:` value in schemas/feed.schema.json is mentioned in BOTH
     README.md and CLAUDE.md.
  2. No known-removed strings reappear (dead paths / renamed tooling).

Exit code 0 = in sync, 1 = drift (with a report on stderr).
"""
from __future__ import annotations

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "schemas", "feed.schema.json")
# Docs that must document every engine action (the reference docs).
DOCS = ["README.md", "CLAUDE.md"]


def forbidden_targets() -> list[str]:
    """Every markdown doc the forbidden-string check applies to: the reference
    docs plus the GitHub Pages site under docs/."""
    targets = list(DOCS)
    docs_dir = os.path.join(ROOT, "docs")
    if os.path.isdir(docs_dir):
        for dirpath, _dirs, files in os.walk(docs_dir):
            for fn in sorted(files):
                if fn.endswith(".md"):
                    targets.append(os.path.relpath(os.path.join(dirpath, fn), ROOT))
    return targets

# Strings that must NOT appear in the docs — removed layout / renamed tooling.
# Add an entry here the moment you rename or delete something user-facing.
FORBIDDEN = [
    ("tests/cve/", "old feed layout — feeds now live in tests/vulnerabilities/<product>/"),
    ("tests/misconfig/", "old feed layout — misconfig checks now live in tests/vulnerabilities/general/"),
    ("docker buildx bake", "`task build` uses `podman build`, not buildx bake"),
    ("libssl-dev", "the build dep is libssh2-1-dev + pkg-config"),
]


def load_actions() -> list[str]:
    with open(SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)
    # Find the enum attached to a property named "action" anywhere in the schema.
    found: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            if "action" in node and isinstance(node["action"], dict):
                enum = node["action"].get("enum")
                if isinstance(enum, list):
                    found.extend(enum)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema)
    return sorted(set(found))


def main() -> int:
    actions = load_actions()
    if not actions:
        print("check_docs: could not find the action enum in the schema", file=sys.stderr)
        return 1

    texts = {}
    for d in DOCS:
        path = os.path.join(ROOT, d)
        with open(path, encoding="utf-8") as fh:
            texts[d] = fh.read()

    problems: list[str] = []

    # 1. Action coverage.
    for d, text in texts.items():
        for action in actions:
            # word-boundary match so `tcp_connect` doesn't satisfy `connect`
            if not re.search(rf"(?<![\w]){re.escape(action)}(?![\w])", text):
                problems.append(f"{d}: engine action `{action}` is not documented")

    # 2. Forbidden strings — across the reference docs AND the docs/ Pages site.
    for d in forbidden_targets():
        with open(os.path.join(ROOT, d), encoding="utf-8") as fh:
            text = fh.read()
        for needle, why in FORBIDDEN:
            if needle in text:
                problems.append(f"{d}: contains removed/renamed `{needle}` — {why}")

    if problems:
        print("check_docs: documentation is out of sync with the engine:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            f"\nKnown actions ({len(actions)}): {', '.join(actions)}\n"
            "Update README.md / CLAUDE.md (and FORBIDDEN in this script when you "
            "rename or remove something), then re-run.",
            file=sys.stderr,
        )
        return 1

    print(f"check_docs: OK — {len(actions)} actions documented in {', '.join(DOCS)}; no stale references.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

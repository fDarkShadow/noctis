#!/usr/bin/env python3
"""Feed catalogue statistics + doc counters.

Counts what tests/vulnerabilities/ really covers and keeps the numbers quoted in
README.md and the GitHub Pages site (docs/) in sync with it. Every counter in the
docs is wrapped in a marker pair:

    <!-- feed-stats:<key> -->123<!-- /feed-stats -->

Run from anywhere (via `task feeds-stats` from infra/):

    python3 scripts/feed_stats.py            # print the stats
    python3 scripts/feed_stats.py --write    # rewrite every marker in the docs
    python3 scripts/feed_stats.py --check    # exit 1 if a marker is out of date
    python3 scripts/feed_stats.py --badge DIR  # write shields.io endpoint JSON files

`--badge DIR` writes DIR/feeds.json and DIR/cves.json in the shields.io
endpoint format. The Badges workflow runs it on every push to main and pushes
the files to the `badges` branch, which the README badges read.

Keys:
  feeds        number of feed files = vulnerability tests (one per vulnerability)
  cves         distinct CVE IDs referenced by the feeds' `cves:` lists
  cve_feeds    feeds with at least one CVE
  nocve_feeds  feeds with `cves: []` (misconfiguration / exposure checks)
  products     product directories under tests/vulnerabilities/
  mocks        mock image directories under infra/docker/
  actions      step actions in schemas/feed.schema.json
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FEEDS_DIR = os.path.join(ROOT, "tests", "vulnerabilities")
DOCKER_DIR = os.path.join(ROOT, "infra", "docker")
SCHEMA = os.path.join(ROOT, "schemas", "feed.schema.json")
DOC_FILES = ["README.md", "docs/index.html"] + sorted(
    os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "docs", "*.md"))
)
MARKER = re.compile(r"(<!-- feed-stats:(\w+) -->)(.*?)(<!-- /feed-stats -->)")


def schema_actions() -> int:
    with open(SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)
    found: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            act = node.get("action")
            if isinstance(act, dict) and isinstance(act.get("enum"), list):
                found.update(act["enum"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema)
    return len(found)


def compute() -> dict[str, int]:
    feeds = sorted(glob.glob(os.path.join(FEEDS_DIR, "*", "*.yaml")))
    cves: set[str] = set()
    cve_feeds = 0
    for path in feeds:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        ids = doc.get("cves") or []
        if ids:
            cve_feeds += 1
        cves.update(ids)
    products = {os.path.basename(os.path.dirname(p)) for p in feeds}
    mocks = [
        d for d in os.listdir(DOCKER_DIR)
        if not d.startswith("_") and os.path.isdir(os.path.join(DOCKER_DIR, d))
    ]
    return {
        "feeds": len(feeds),
        "cves": len(cves),
        "cve_feeds": cve_feeds,
        "nocve_feeds": len(feeds) - cve_feeds,
        "products": len(products),
        "mocks": len(mocks),
        "actions": schema_actions(),
    }


def sync(stats: dict[str, int], write: bool) -> list[str]:
    stale: list[str] = []
    for rel in DOC_FILES:
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            text = fh.read()

        def repl(m: re.Match) -> str:
            key = m.group(2)
            if key not in stats:
                stale.append(f"{rel}: unknown key '{key}'")
                return m.group(0)
            want = str(stats[key])
            if m.group(3) != want:
                stale.append(f"{rel}: {key} = {m.group(3)!r}, expected {want}")
            return f"{m.group(1)}{want}{m.group(4)}"

        new = MARKER.sub(repl, text)
        if write and new != text:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(new)
    return stale


BADGES = {
    # file name: (stats key, label)
    "feeds": ("feeds", "vulnerability tests"),
    "cves": ("cves", "CVEs covered"),
}


def write_badges(stats: dict[str, int], out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    for name, (key, label) in BADGES.items():
        badge = {
            "schemaVersion": 1,
            "label": label,
            "message": str(stats[key]),
            "color": "blueviolet",
        }
        with open(os.path.join(out_dir, f"{name}.json"), "w", encoding="utf-8") as fh:
            json.dump(badge, fh, indent=2)
            fh.write("\n")


def main() -> int:
    write = "--write" in sys.argv
    check = "--check" in sys.argv
    stats = compute()
    for k, v in stats.items():
        print(f"{k:12} {v}")
    if "--badge" in sys.argv:
        idx = sys.argv.index("--badge")
        if idx + 1 >= len(sys.argv):
            print("feed-stats: --badge needs an output directory", file=sys.stderr)
            return 2
        write_badges(stats, sys.argv[idx + 1])
        return 0
    if not (write or check):
        return 0
    stale = sync(stats, write)
    unknown = [s for s in stale if "unknown key" in s]
    if write:
        print(f"feed-stats: updated {len(stale) - len(unknown)} counter(s) in the docs.")
        for s in unknown:
            print(s, file=sys.stderr)
        return 1 if unknown else 0
    if stale:
        print("feed-stats: doc counters are out of date — run `task feeds-stats -- --write`:", file=sys.stderr)
        for s in stale:
            print(f"  {s}", file=sys.stderr)
        return 1
    print("feed-stats: doc counters in sync.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

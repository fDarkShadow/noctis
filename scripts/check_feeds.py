#!/usr/bin/env python3
"""Feed tree integrity: sha256 lockfile + uid uniqueness.

Run via `task feeds-check` (from infra/). Pass --write to regenerate the lockfile
after an intentional feed edit — do that as part of the same commit, never separately.
"""
import glob
import hashlib
import json
import os
import re
import sys

REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
FEEDS_DIR = os.path.join(REPO_ROOT, "tests", "vulnerabilities")
LOCKFILE_PATH = os.path.join(FEEDS_DIR, ".feed-shas.json")


def feed_paths() -> list[str]:
    return sorted(glob.glob(os.path.join(FEEDS_DIR, "**", "*.yaml"), recursive=True))


def sha256_of(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def current_hashes() -> dict[str, str]:
    return {
        os.path.relpath(p, FEEDS_DIR): sha256_of(p)
        for p in feed_paths()
    }


def load_lockfile() -> dict[str, str]:
    if not os.path.isfile(LOCKFILE_PATH):
        return {}
    with open(LOCKFILE_PATH) as f:
        return json.load(f)


def check_uid_uniqueness(paths: list[str]) -> list[str]:
    errors = []
    seen: dict[str, str] = {}
    for path in paths:
        with open(path) as f:
            content = f.read()
        m = re.search(r"^uid:\s*(\S+)", content, re.MULTILINE)
        if not m:
            errors.append(f"{os.path.relpath(path, REPO_ROOT)}: no uid field found")
            continue
        uid = m.group(1)
        rel = os.path.relpath(path, REPO_ROOT)
        if uid in seen:
            errors.append(f"duplicate uid {uid}: {seen[uid]} and {rel}")
        else:
            seen[uid] = rel
    return errors


def main() -> int:
    write = "--write" in sys.argv

    hashes = current_hashes()
    if write:
        with open(LOCKFILE_PATH, "w") as f:
            json.dump(hashes, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"Wrote {LOCKFILE_PATH} ({len(hashes)} feeds).")

    lock = load_lockfile()
    errors = []

    for rel, sha in hashes.items():
        if rel not in lock:
            errors.append(f"{rel}: new feed not in lockfile — run `task feeds-check -- --write`")
        elif lock[rel] != sha:
            errors.append(f"{rel}: content changed without updating the lockfile")
    for rel in lock:
        if rel not in hashes:
            errors.append(f"{rel}: in lockfile but file no longer exists")

    errors.extend(check_uid_uniqueness(feed_paths()))

    if errors:
        print(f"feeds-check: {len(errors)} problem(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"feeds-check: {len(hashes)} feeds, lockfile in sync, no duplicate uids.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

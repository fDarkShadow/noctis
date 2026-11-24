#!/usr/bin/env python3
"""Feed tree integrity: sha256 lockfile + uid uniqueness + resolvable includes +
no `{{...}}` template in a step field the engine reads literally + `general/`
feeds use one of the agreed categories (see CLAUDE.md, "TestDef (YAML)").

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


def check_includes(paths: list[str]) -> list[str]:
    """Every `includes:` entry must point to an existing file.

    The engine resolves includes relative to the including feed's directory and
    *skips the whole feed* (with only a log warning) when one is missing — so a
    broken path silently disables the check. Catch it here instead.
    """
    errors = []
    for path in paths:
        with open(path) as f:
            lines = f.read().splitlines()
        entries: list[str] = []
        in_block = False
        for line in lines:
            inline = re.match(r"^includes:\s*\[(.*)\]\s*(#.*)?$", line)
            if inline:
                entries += [e.strip().strip("'\"") for e in inline.group(1).split(",") if e.strip()]
                continue
            if re.match(r"^includes:\s*(#.*)?$", line):
                in_block = True
                continue
            if in_block:
                item = re.match(r"^\s+-\s+['\"]?([^'\"#]+?)['\"]?\s*(#.*)?$", line)
                if item:
                    entries.append(item.group(1))
                elif line.strip() and not line.lstrip().startswith("#"):
                    in_block = False
        rel = os.path.relpath(path, REPO_ROOT)
        for inc in entries:
            target = os.path.normpath(os.path.join(os.path.dirname(path), inc))
            if not os.path.isfile(target):
                errors.append(
                    f"{rel}: include `{inc}` not found (resolves to "
                    f"{os.path.relpath(target, REPO_ROOT)}) — includes are relative to the feed file"
                )
    return errors


# Step fields the engine reads as literal text — it never runs them through the
# `{{var}}` template engine. A template there is sent / matched verbatim and the step
# silently misbehaves (e.g. `method: "{{http_method}}"` used to go out as the HTTP
# method itself). Keep this list in sync with src/engine/actions/*.rs.
LITERAL_STEP_FIELDS = ("id", "action", "store_as", "source", "pattern", "var_name", "handle", "line_ending")
_LITERAL_RE = re.compile(
    r"^\s+(?:-\s+)?(" + "|".join(LITERAL_STEP_FIELDS) + r"):\s*(.*\{\{.*)$"
)


def check_literal_fields(paths: list[str]) -> list[str]:
    errors = []
    for path in paths:
        rel = os.path.relpath(path, REPO_ROOT)
        with open(path) as f:
            for n, line in enumerate(f, 1):
                m = _LITERAL_RE.match(line)
                if m and not line.lstrip().startswith("#"):
                    errors.append(
                        f"{rel}:{n}: `{m.group(1)}:` is not templated by the engine, "
                        f"so `{m.group(2).strip()}` would be used verbatim"
                    )
    return errors


def common_paths() -> list[str]:
    return sorted(glob.glob(os.path.join(REPO_ROOT, "tests", "common", "*.yaml")))


# `filters.exclude_category` is an exact-string match, so a synonym escapes it.
GENERAL_CATEGORIES = {"exposure", "hardening", "default-credentials"}


def check_general_categories(paths: list[str]) -> list[str]:
    errors = []
    general = os.path.join(FEEDS_DIR, "general") + os.sep
    for path in paths:
        if not path.startswith(general):
            continue
        with open(path) as f:
            m = re.search(r"^category:\s*[\"']?([^\"'\s#]+)", f.read(), re.MULTILINE)
        rel = os.path.relpath(path, FEEDS_DIR)
        if not m:
            errors.append(f"{rel}: general/ feed has no category")
        elif m.group(1) not in GENERAL_CATEGORIES:
            errors.append(
                f"{rel}: category {m.group(1)!r} — general/ feeds use one of "
                f"{sorted(GENERAL_CATEGORIES)}"
            )
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
    errors.extend(check_includes(feed_paths()))
    errors.extend(check_literal_fields(feed_paths() + common_paths()))
    errors.extend(check_general_categories(feed_paths()))

    if errors:
        print(f"feeds-check: {len(errors)} problem(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"feeds-check: {len(hashes)} feeds, lockfile in sync, no duplicate uids, all includes resolve, no literal-field templates, general/ categories valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/bin/bash
# PreToolUse(Bash) guard — when the command being run is a `git push`, replay
# the fast CI gates locally and block the push if any fails, so a red CI is
# caught before it reaches the remote. Only `git push` commands are inspected;
# everything else is allowed through untouched.
#
# Gates mirrored from .github/workflows/ci.yml (the fast ones only — cargo test
# and CodeQL are left to CI):
#   - cargo fmt --check
#   - cargo clippy --locked -- -D warnings
#   - python3 scripts/check_feeds.py            (feed sha lockfile + uid uniqueness)
#   - python3 scripts/gen_mocks_manifest.py --check
set -uo pipefail

input=$(cat)

# Extract the command string without requiring jq.
cmd=$(printf '%s' "$input" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get("tool_input",{}).get("command",""))
except Exception:
    print("")' 2>/dev/null)

# Not a git push? Allow silently.
case "$cmd" in
  *"git push"*) ;;
  *) exit 0 ;;
esac

# Escape hatch: honour an explicit opt-out in the command itself.
case "$cmd" in
  *NO_PREPUSH*) exit 0 ;;
esac

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0

# If the Rust toolchain isn't present (e.g. a docs-only machine), don't block.
command -v cargo >/dev/null 2>&1 || exit 0

fails=""
run() { # label, cmd...
  local label="$1"; shift
  if ! "$@" >/tmp/prepush.$$ 2>&1; then
    fails+=$(printf '\n--- %s ---\n%s\n' "$label" "$(tail -30 /tmp/prepush.$$)")
  fi
}

run "cargo fmt --check" cargo fmt --check
run "cargo clippy --locked -D warnings" cargo clippy --locked -- -D warnings
[ -f scripts/check_feeds.py ] && run "check_feeds.py" python3 scripts/check_feeds.py
[ -f scripts/gen_mocks_manifest.py ] && run "gen_mocks_manifest --check" python3 scripts/gen_mocks_manifest.py --check
rm -f /tmp/prepush.$$

if [ -n "$fails" ]; then
  reason="Pre-push CI gates failed — fix before pushing (or append NO_PREPUSH to the command to override):${fails}"
  # Deny the Bash tool call with a reason the agent sees.
  printf '%s' "$reason" | python3 -c 'import json,sys
msg=sys.stdin.read()
print(json.dumps({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":msg}}))'
  exit 0
fi

exit 0

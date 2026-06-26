#!/usr/bin/env bash
# run-agents.sh — Run agent-loop iterations sequentially with rate-limit awareness.
#
# Usage:
#   ./scripts/run-agents.sh              # run until no issues remain
#   ./scripts/run-agents.sh --max 3      # stop after 3 iterations
#   ./scripts/run-agents.sh --delay 120  # 120s pause between iterations (default: 60)
#
# Token budget strategy:
#   Each claude invocation consumes tokens. If the CLI returns a rate-limit error
#   (exit code 2 or "rate limit" in output), the script backs off exponentially
#   up to MAX_BACKOFF_SECS. Between successful iterations, DELAY_SECS is respected.
#
# Requirements: claude CLI, gh CLI, git

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
DELAY_SECS=60          # pause between successful iterations
MAX_BACKOFF_SECS=3600  # max wait on rate-limit (1h)
MAX_ITERATIONS=0       # 0 = unlimited
LOG_FILE="run-agents.log"

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --max)    MAX_ITERATIONS="$2"; shift 2 ;;
    --delay)  DELAY_SECS="$2";     shift 2 ;;
    --log)    LOG_FILE="$2";       shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

available_issues() {
  gh issue list \
    --label "status:available" \
    --state open \
    --json number \
    --jq 'length' 2>/dev/null || echo 0
}

run_agent() {
  # Run one agent-loop iteration in non-interactive mode.
  # Exit codes:
  #   0 = completed (issue picked and PR opened, or no issue found)
  #   2 = rate limited
  #   1 = other error
  claude --print "/agent-loop" 2>&1
}

# ── Main loop ─────────────────────────────────────────────────────────────────
log "=== run-agents started (max=${MAX_ITERATIONS:-unlimited}, delay=${DELAY_SECS}s) ==="

iteration=0
backoff=60

while true; do
  # Check iteration cap
  if [[ $MAX_ITERATIONS -gt 0 && $iteration -ge $MAX_ITERATIONS ]]; then
    log "Reached max iterations ($MAX_ITERATIONS). Stopping."
    break
  fi

  # Check available issues before spending tokens
  count=$(available_issues)
  if [[ $count -eq 0 ]]; then
    log "No available issues. Stopping."
    break
  fi
  log "Available issues: $count — starting iteration $((iteration + 1))"

  # Run agent
  output=$(run_agent 2>&1)
  exit_code=$?

  echo "$output" >> "$LOG_FILE"

  # Detect rate limit
  if [[ $exit_code -eq 2 ]] || echo "$output" | grep -qi "rate.limit\|too many requests\|quota exceeded\|usage limit"; then
    log "Rate limit detected. Backing off ${backoff}s…"
    sleep "$backoff"
    backoff=$(( backoff * 2 > MAX_BACKOFF_SECS ? MAX_BACKOFF_SECS : backoff * 2 ))
    continue  # retry same iteration, do not increment
  fi

  # Detect explicit "no issues" output from agent
  if echo "$output" | grep -q "No available issues"; then
    log "Agent found no available issues. Stopping."
    break
  fi

  # Success — reset backoff, increment counter
  backoff=60
  iteration=$(( iteration + 1 ))
  log "Iteration $iteration complete."

  # Pause between runs
  count_after=$(available_issues)
  if [[ $count_after -eq 0 ]]; then
    log "No remaining issues. Stopping."
    break
  fi
  log "Waiting ${DELAY_SECS}s before next iteration…"
  sleep "$DELAY_SECS"
done

log "=== run-agents done — $iteration iteration(s) completed ==="

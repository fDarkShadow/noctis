#!/usr/bin/env bash
# Stage 2 — Claude review of the pending-review backlog queue. Headless, fixed cadence,
# minimal token usage by design (one `claude -p` call batches every pending-review issue).
# A failed run (rate limit, network) just exits non-zero; the next scheduled timer tick
# retries the whole batch — no budget tracking, per the "cadence fixe + retry" decision
# in the plan (radiant-meandering-bumblebee.md).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."   # repo root

LOG_DIR="automation/state/logs"
mkdir -p "$LOG_DIR"
STAMP="$(date +%Y%m%dT%H%M%S)"

PROMPT_FILE="automation/stage2_backlog_review/review_pending_backlog.md"
SETTINGS_FILE="automation/stage2_backlog_review/claude-settings.json"

cat "$PROMPT_FILE" | claude -p \
  --settings "$SETTINGS_FILE" \
  --permission-mode dontAsk \
  --max-budget-usd "${STAGE2_MAX_BUDGET_USD:-2.00}" \
  --output-format text \
  2>&1 | tee -a "$LOG_DIR/stage2-$STAMP.log"

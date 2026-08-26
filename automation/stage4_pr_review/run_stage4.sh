#!/usr/bin/env bash
# Stage 4 — Claude review (and fix) of worker-generated PRs before human merge. Headless,
# fixed cadence. A failed run just exits non-zero; the next scheduled timer tick retries the
# whole batch — no budget tracking, per the "cadence fixe + retry" decision in the plan.
#
# Unlike Stage 2, this stage pushes real commits — it runs `git`/`cargo`/`task` for real, so it
# must execute from a clean repo state. It operates on the main working tree (via `gh pr
# checkout`), not an isolated worktree, so do not run this concurrently with other work in this
# checkout.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."   # repo root

LOG_DIR="automation/state/logs"
mkdir -p "$LOG_DIR"
STAMP="$(date +%Y%m%dT%H%M%S)"

PROMPT_FILE="automation/stage4_pr_review/review_worker_prs.md"
SETTINGS_FILE="automation/stage4_pr_review/claude-settings.json"

cat "$PROMPT_FILE" | claude -p \
  --settings "$SETTINGS_FILE" \
  --permission-mode dontAsk \
  --max-budget-usd "${STAGE4_MAX_BUDGET_USD:-5.00}" \
  --output-format text \
  2>&1 | tee -a "$LOG_DIR/stage4-$STAMP.log"

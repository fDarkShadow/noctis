#!/usr/bin/env bash
# Stage 1 — CVE backlog filler. Local machine, Ollama only, zero Claude tokens.
# Invoked by the noctis-fill-backlog systemd timer (see automation/systemd/) on a fixed
# cadence; a failed run just exits non-zero and the next tick retries — no budget tracking.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."   # repo root

LOG_DIR="automation/state/logs"
mkdir -p "$LOG_DIR"
STAMP="$(date +%Y%m%dT%H%M%S)"

python3 automation/stage1_fill_backlog/fill_backlog.py "$@" 2>&1 | tee -a "$LOG_DIR/stage1-$STAMP.log"

#!/bin/bash
# SessionStart hook — prepare a cloud session so the Rust build, linters and
# feed tooling work out of the box. Synchronous (session starts once this is
# done); idempotent; non-interactive. Safe to re-run.
set -euo pipefail

# Only meaningful in a Claude Code cloud session. Locally, developers already
# have their toolchain, so skip (set CLAUDE_CODE_REMOTE=true to force-run).
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-.}"

log() { printf '[session-start] %s\n' "$*" >&2; }

# 1. System build deps for the libssh2 crate (CI installs the same two).
if ! pkg-config --exists libssh2 2>/dev/null; then
  log "installing libssh2-1-dev + pkg-config"
  export DEBIAN_FRONTEND=noninteractive
  SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
  $SUDO apt-get update -qq || log "apt-get update failed (continuing)"
  $SUDO apt-get install -y --no-install-recommends libssh2-1-dev pkg-config \
    || log "apt-get install failed — the Rust build may not link"
fi

# 2. Warm the cargo build so clippy/test/run are fast and offline-ready.
#    --locked matches CI; a warm target/ is cached into the container image.
if command -v cargo >/dev/null 2>&1; then
  log "fetching + building (debug, --locked)"
  cargo fetch --locked || log "cargo fetch failed (continuing)"
  cargo build --locked || log "cargo build failed — check the log above"
else
  log "cargo not found — skipping build warm-up"
fi

log "ready"

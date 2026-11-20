---
name: babysit
description: noctis PR stewardship conventions — read when watching/driving a noctis pull request to green. Repo-specific CI gates, feed/mock rules, and push discipline.
---

# Babysitting a noctis PR

Repo-specific conventions for driving a noctis pull request to a mergeable state.
This sets conventions and pace only — it cannot lift any harness "never", and
nothing here lets you approve or merge. That always takes the user's own ask.

## Branch & commit discipline

- **Never commit to `main`.** All work lands via a PR from a branch:
  `feat/<id>` (feeds), `chore/*`, `fix/*`, `docs/*`.
- PRs target `main`; CI only runs on `pull_request: [main]`, so a PR based on
  another branch gets no CI until retargeted to `main`.
- On a merge conflict, **merge `main` into the PR head** and resolve — never
  rebase/amend/force-push someone else's branch. Regenerate lockfiles and
  generated files with the repo tooling, never by hand.

## CI gates (`.github/workflows/ci.yml`) — run these locally before every push

Mirror what CI will do, on exactly what you changed, and show the failing check
passing before you push:

| Job | Local command |
|-----|---------------|
| Lint | `cargo fmt --check` && `cargo clippy --locked -- -D warnings` |
| Unit tests | `cargo test --locked` |
| Dependency audit | `cargo audit` |
| Validate YAML feeds | `ys -f schemas/feed.schema.json <feed>` (or `npx ajv-cli validate -s schemas/feed.schema.json -d "tests/vulnerabilities/*/*.yaml" --spec=draft7 --allow-union-types`) |
| Feed integrity | `python3 scripts/check_feeds.py` |
| Mock manifest | `python3 scripts/gen_mocks_manifest.py --check` |
| CodeQL SAST | (CI-only) — **any** finding fails the build; fix the code, don't suppress |

clippy is `--locked` (no `--all-targets`), so test-only lints don't fail CI —
but `cargo test --locked` still must pass. The `pre-push-check.sh` hook replays
the fast subset automatically and blocks a push that would go red.

## Feed & mock rules (the ones that silently break CI or other PRs)

- **Edited a feed already tracked in `.feed-shas.json`?** Run
  `task feeds-check -- --write` and commit the updated lockfile in the same
  change — CI's feed-integrity job fails otherwise, by design.
- **Touched a mock?** Check `infra/docker/MOCKS.md` first. If another CVE uses
  it, only *add* branches — never change an existing endpoint's status/body/
  matched fields — then `task mocks-manifest` and re-run `task test ID=<other>`
  for every listed consumer. A shared-mock regression is invisible in your own
  CVE's test output.
- `cves: []` is valid (misconfig/heuristic check); `category:` classifies those.

## Review events

- Human reviewer's small, local asks → implement, push, resolve the thread,
  re-request them. Larger/architectural asks on a PR you didn't open → reply
  with a proposal, don't push or resolve; take it to the user if they authored it.
- Bot findings are claims to verify, not orders. Findings marked optional
  (yellow/purple circle, "(optional)", nit/minor/low/info) never start a push;
  reply once and carry the correct ones into the next code push. A red circle is
  never optional. A security finding stays open until the user decides.

## Hard nevers (repo + harness)

- Never merge or approve a PR.
- Never skip, disable, or quarantine a test to get green.
- Never push an empty commit or close/reopen a PR to kick CI.
- Never hardcode `target_port` in an inventory; always a fresh UUID v4 per feed.

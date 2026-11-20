# Feed sourcing — Claude workflow

Industrialized, Claude-native pipeline that turns a large external corpus of upstream
detection scripts into noctis detection feeds, through the project's normal lifecycle
(**issue → project board → PR**). It reuses the existing `automation/` conventions
(`common/labels.py`, the 15-point scoring table in `stage1_fill_backlog/scoring.py`, and the
`make-test` agent loop) but drives the drafting with Claude, so multi-step chains and
engine-capability judgments can be handled faithfully.

> This directory holds the *machine*. The corpus itself and all run state live outside git
> (`.gitignore`: `automation/state/`, and the corpus checkout).

## Design constraints

- **Every test is fully isolated — there is no shared knowledge base.** Each feed must be
  self-contained: it does its own probing and matching within its own steps. A detection
  whose logic upstream relied on cross-script state has to fold that probe into the one feed.
- **noctis models remote, unauthenticated, non-destructive detection only** — that is what
  makes Tier A the real target (see the funnel below) and Tier C ineligible by construction.
- Only facts are carried across (endpoints, payloads, response patterns); nothing is invented.

## The funnel

`parse_sources.py` classifies every source script into a coarse tier:

| Tier | Meaning | Maps to noctis? |
|------|---------|-----------------|
| **C** | local / credentialed / destructive / no network probe | ✗ out of scope |
| **B** | version/banner check whose probe lives in a separate dependency | ◑ portable only by folding the probe in (no shared state ⇒ self-contained) |
| **A** | self-contained active probe (`http_get`/`send`+`recv`/… → match) | ✓ direct |

## Stages

```
parse_sources.py     Stage 0  corpus → candidates.jsonl   (deterministic, no LLM)
triage.py            Stage 1  dedup + prefilter + CVSS/EPSS/KEV score → shortlist.jsonl
   └─ Claude         Stage 1b per shortlisted item: confirm eligibility, draft the detection
                              strategy, write the issue (fill-backlog body format), add to board
   └─ Claude         Stage 2  engine-capability gap: when a detection needs a transport/protocol
                              the engine lacks, open a type:feature issue + a Rust PR rather than
                              faking a confirmation the feed can't actually make (see epic #330)
make-test (existing) Stage 4  per eligible issue: feed + mock + inventory + playbook → verify → PR
```

State is a resumable, idempotent manifest (`automation/state/feed-sourcing/manifest.json`): each
item carries `new → triaged → eligible|skipped(reason) → issue#N → pr#M → merged`. Re-runs skip
anything already covered by an existing feed or already in the manifest.

## Verification posture

The e2e harness (`task test`) needs **podman + ansible** and is a *local-only* gate (CI does
not run it). Where those are unavailable, reproduce the role's TP/TN check by hand with `docker`
(or the mock's server run directly) + the real binary:

```
cargo build --release
docker run -d -p 8080:80 <mock>:vuln     # + :patched on another port
./target/release/noctis serve &          # POST /scans, assert finding on vuln, none on patched
```

Every PR must still pass CI: `cargo fmt`, `clippy -D warnings`, `cargo test`, `cargo audit`,
schema validation of each feed, `scripts/check_feeds.py`, `scripts/gen_mocks_manifest.py --check`,
CodeQL. Run `task feeds-check -- --write` after any feed edit and commit the lockfile.

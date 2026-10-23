# OpenVAS → noctis migration — Claude workflow

Industrialized, Claude-native pipeline that turns the open-source OpenVAS/Greenbone NVT
corpus into noctis detection feeds, through the project's normal lifecycle
(**issue → project board → PR**). It reuses the existing `automation/` conventions
(`common/labels.py`, the 15-point scoring table in `stage1_fill_backlog/scoring.py`, and the
`make-test` agent loop) but replaces the local-LLM (Ollama) drafting of Stage 1 with Claude,
which — unlike the benchmarked-out local model — can faithfully port **multi-step** chains and
make the eligibility / builtin-gap judgments this corpus demands.

> This directory holds the *machine*. The corpus itself and all run state live outside git
> (`/home/user/openvas-corpus/`, `automation/state/` — both `.gitignore`d).

## Source of the corpus

There is **no browsable git repo of the ~250k NASL VTs**. The Greenbone Community Feed is
rsync-only (`rsync://feed.community.greenbone.net/community/.../vt-data/nasl/`), pulled with
`greenbone-feed-sync`, and rate-limited/bannable. This pipeline instead consumes a git mirror
of that feed (e.g. `jbeasl7/openvas-feed-sync-local`, the `openvas-feeds/nvt-feed/` tree —
the `vt-feed/` tree is an older duplicate and is ignored). Freshness depends on the mirror.
NASL is GPL-2.0-only: each generated feed/issue must credit the source plugin path.

## The funnel (why "all NASL" is a few thousand, not 250k)

`parse_nasl.py` classifies every `.nasl` into a coarse tier (counts from the 2026-10 feed):

| Tier | Meaning | Maps to noctis? | ~count |
|------|---------|-----------------|--------|
| **C** | local / credentialed / destructive / no network probe (package, registry, SMB/WMI, SSH-login, `version_func` with no self-probe, `ACT_DENIAL`…) | ✗ out of scope | ~133k |
| **B** | version/banner check whose probe lives in a `*_detect`/consolidation **dependency** | ◑ portable only by folding the dependency's banner-grab in | ~11k |
| **A** | self-contained active probe (`http_get`/`http_post`/`send`+`recv`/`http_vuln_check` → match) | ✓ direct | ~4.4k (2.2k with a CVE, after dedup vs existing feeds) |

noctis models **remote, unauthenticated, non-destructive** detection only — that is what makes
Tier A the real target and Tier C ineligible by construction (not a backlog we're behind on).

## Stages

```
parse_nasl.py        Stage 0  corpus → candidates.jsonl   (deterministic, no LLM)
triage.py            Stage 1  dedup + prefilter + CVSS/EPSS/KEV score → shortlist.jsonl
   └─ Claude         Stage 1b per shortlisted VT: confirm eligibility, draft detection
                              strategy from the NASL body, write the issue (fill-backlog
                              body format), add to the project board
   └─ Claude         Stage 2  builtin-gap map: NASL primitives → noctis actions
                              {http_request,tcp_connect,tls_check,ssh_check,match,script,
                               wait_oob,set_var}. A primitive with no mapping (FTP/SMTP/
                               telnet/SNMP login helpers, raw packet forge, protocol X) →
                               ONE type:feature issue per *capability* (not per VT) + a Rust
                               PR; dependent VTs go status:delayed until it merges.
make-test (existing) Stage 4  per eligible issue: feed + mock + inventory + playbook → verify
                              → PR. See "Verification" below.
```

State is a resumable, idempotent manifest (`automation/state/openvas/manifest.json`): each OID
carries `new → triaged → eligible|skipped(reason) → issue#N → pr#M → merged`. Re-runs skip
anything already covered by an existing feed or already in the manifest.

## Verification posture

The e2e harness (`task test`) needs **podman + ansible** and is a *local-only* gate (CI does
not run it). Where those are unavailable (e.g. a cloud session), reproduce the role's TP/TN
check by hand with `docker` + the real binary:

```
cargo build --release
docker build -f infra/docker/<mock>/Dockerfile.vuln    -t noctis/<mock>:vuln    infra/docker/<mock>
docker build -f infra/docker/<mock>/Dockerfile.patched -t noctis/<mock>:patched infra/docker/<mock>
docker run -d -p 8080:80 noctis/<mock>:vuln   # + :patched on another port
./target/release/noctis serve &               # POST /scans, assert finding on vuln, none on patched
```

This proves the same TP/TN + QoD + confidence the inventory asserts, without podman/ansible.
Every PR must still pass CI: `cargo fmt`, `clippy -D warnings`, `cargo test`, `cargo audit`,
`ys` schema validation of each feed, `scripts/check_feeds.py`, `scripts/gen_mocks_manifest.py
--check`, CodeQL. Run `task feeds-check -- --write` (or `python3 scripts/check_feeds.py
--write`) after any feed edit and commit the lockfile.

## Hard rules (inherited)

- Never port a Tier-C check by faking a remote confirmation it can't actually make.
- Never invent a detection detail not present in the NASL source (no fake URL/header/pattern).
- One `type:feature` issue per missing *capability*, deduped against open ones (e.g. #316).
- Credit the GPL source plugin path in every feed and issue.
- Cap issue creation per batch to keep each entry high-quality; the manifest makes it resumable.

# Contributing to noctis

Thanks for your interest in contributing! noctis is a Rust vulnerability scanner
driven by self-contained YAML feeds. This guide explains how to set up your
environment, the conventions we follow, and how to get a change merged.

By participating in this project you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

---

## Ways to contribute

- **New detection feeds** — the most common contribution: one YAML file per
  vulnerability or misconfiguration, plus a reproducible mock.
- **Engine capabilities** — new step actions, protocol primitives, or expression
  builtins that let feeds express more (see `src/engine/` and `src/expr/`).
- **Mocks & test infrastructure** — vulnerable/patched containers under `infra/`.
- **Documentation** — fixes and improvements to the docs and `CLAUDE.md`.

For anything non-trivial, please **open an issue first** (see the templates under
[`.github/ISSUE_TEMPLATE`](.github/ISSUE_TEMPLATE)) so the approach can be
discussed before you invest time.

> Found a security vulnerability in noctis itself? **Do not open a public
> issue** — follow [`SECURITY.md`](SECURITY.md) instead.

---

## Design principles

Please keep these in mind; PRs that break them will be asked to change:

- **Feeds are self-contained.** There is no shared knowledge base or cross-test
  state. Every feed must detect its target on its own, from a single scan.
- **Detections are generic facts.** Describe the observable behaviour (banner,
  response, protocol reply). Do not copy text, identifiers, or branding from
  third-party vulnerability databases or scanners into feeds, issues, commits,
  or PRs.
- **Every feed is proven with a mock.** A contribution that claims a detection
  must ship a vulnerable *and* a patched mock and demonstrate a true-positive on
  the former and a true-negative on the latter.
- **Minimal, focused changes.** One logical change per PR.

---

## Development setup

You need a recent stable Rust toolchain (the CI pins the current stable; keep
`clippy` and `rustfmt` clean against it).

```sh
git clone https://github.com/fDarkShadow/noctis
cd noctis

cargo build                  # debug build
cargo test                   # unit tests
cargo fmt --all              # format
cargo clippy --all-targets -- -D warnings   # lint (CI runs: cargo clippy --locked -- -D warnings)
cargo audit                  # dependency advisories (install: cargo install cargo-audit)
```

End-to-end feed tests use [Task](https://taskfile.dev), Ansible, and rootless
Podman (from `infra/`):

```sh
task build                   # build local mock images
task test ID=CVE-2021-41773  # run TP + TN for one vulnerability
task test-all                # run every vulnerability
task feeds-check             # sha lockfile + uid-uniqueness check
task mocks-manifest          # regenerate infra/docker/MOCKS.md
task feeds-stats             # count feeds / CVEs (-- --write refreshes README + Pages)
task bake-gen                # regenerate infra/bake/mocks.hcl after adding a mock
```

`CLAUDE.md` documents every convention, pattern, and pitfall in depth — **read it
before writing a feed or a mock.** The existing files in
`tests/vulnerabilities/` and `infra/docker/` are your primary reference; copy and
adapt them rather than inventing new patterns.

---

## Adding a detection feed

1. **Feed** — `tests/vulnerabilities/<product>/<id>.yaml` (one directory per
   product, shared by all its CVEs — reuse it if it exists) with:
   - a stable, unique **UUID v4** `uid` (never reuse or change one);
   - `cves:` set to the matching 0, 1, or N CVE IDs (`[]` is valid and normal for
     a misconfiguration/exposure check — use `category:` to classify it);
   - `services:` the targeted service names;
   - a low `confidence_base`, raised by `confidence_delta` on match, and a `qod:`
     (quality-of-detection) score.
   After editing any feed, run `task feeds-check -- --write` and **commit the
   updated `tests/vulnerabilities/.feed-shas.json` lockfile in the same commit**
   (CI fails otherwise).
2. **Schema** — validate against the JSON schema:
   ```sh
   npx ajv-cli validate -s schemas/feed.schema.json \
     -d "tests/vulnerabilities/*/*.yaml" --spec=draft7 --allow-union-types
   ```
3. **Mock** — `infra/docker/<product>-mock/` with a `vuln` and a `patched`
   variant. Reuse an existing mock only by *adding* branches, never by changing
   an endpoint another feed depends on (check `infra/docker/MOCKS.md`). Run
   `task mocks-manifest` afterwards.
4. **Inventory & playbook** — `infra/inventories/<product>/<id>/hosts.yml` and
   `infra/playbooks/10-<product>-<id>.yml` (the `10-` prefix is required). Set
   `expected_result`, `expected_qod`, and `expected_min_confidence` on vuln hosts
   so the harness asserts the right detection branch fired.
5. **Prove it** — `task test ID=<id>` must pass: a finding on the vuln host(s),
   zero findings on the patched host(s).

---

## Adding an engine capability

- Put low-level primitives in `src/checks/`, wire the action in
  `src/engine/step.rs` and `src/engine/actions/`, and add any new step fields to
  `src/model/step.rs`.
- Expression builtins (Rhai) live in `src/expr/` and are registered in
  `src/expr/rhai.rs`.
- Update `schemas/feed.schema.json` when you add an action or a step field.
- Add unit tests. Prefer a pure-Rust library over a hand-rolled binary protocol
  or a new system dependency; if a dependency is unavoidable, explain the
  trade-off in the issue and get agreement before implementing.

---

## Commit and PR conventions

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org):
  `feat(...)`, `fix(...)`, `chore(...)`, `docs(...)`, `test(...)`, `refactor(...)`.
  Write clear, imperative messages explaining *why*, not just *what*.
- **Branches**: use a short descriptive name, e.g. `feat/<slug>` or
  `chore/<slug>`.
- **Pull requests**:
  - Keep them focused; one logical change per PR.
  - Fill in the [PR template](.github/pull_request_template.md). For feeds or
    engine changes you can use the specialized templates by appending
    `?template=feed.md` or `?template=engine.md` to the PR creation URL.
  - Link the issue they resolve with `Closes #<n>`.
  - Make sure every CI check passes: **Lint** (fmt + clippy), **Unit tests**,
    **Dependency audit**, **Validate YAML feeds**, and CodeQL.
  - Include the evidence that the detection works (TP/TN results) in the PR body.

Maintainers review and merge with a merge commit. Please be responsive to review
feedback and keep the branch up to date with `main`.

---

## License

noctis is released under the [MIT License](LICENSE). By contributing, you agree
that your contributions will be licensed under the same terms.

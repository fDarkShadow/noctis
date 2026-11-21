---
title: Contributing
nav_order: 6
---
{% raw %}
# Contributing

Contributions are welcome — new detection feeds, engine capabilities, mocks, and docs.

Start with the repository's **[CONTRIBUTING.md](https://github.com/fDarkShadow/noctis/blob/main/CONTRIBUTING.md)**,
which covers the dev setup, design principles, and the step-by-step workflow for adding a feed
or an engine capability. The deep authoring reference lives in
**[CLAUDE.md](https://github.com/fDarkShadow/noctis/blob/main/CLAUDE.md)**.

Questions, ideas and things you built go to
[GitHub Discussions](https://github.com/fDarkShadow/noctis/discussions) (Q&A, Ideas, Show and tell);
issues are for bugs, detection-quality reports and new feed requests.

## Design principles

- **Feeds are self-contained** — no shared knowledge base or cross-test state.
- **Detections are generic, observable facts** — no third-party database text or branding copied in.
- **Every feed is proven with a mock** — a true-positive on a vulnerable mock and a true-negative
  on a patched one.
- **Minimal, focused changes** — one logical change per pull request.

## Before opening a PR

- `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` are clean
- `cargo test` passes
- Feeds validate and the `.feed-shas.json` lockfile is regenerated and committed
- Use the [PR template](https://github.com/fDarkShadow/noctis/tree/main/.github) and link the issue

## Community & security

- [Code of Conduct](https://github.com/fDarkShadow/noctis/blob/main/CODE_OF_CONDUCT.md)
- [Security policy](https://github.com/fDarkShadow/noctis/blob/main/SECURITY.md) — report
  vulnerabilities privately; do not open a public issue.
{% endraw %}

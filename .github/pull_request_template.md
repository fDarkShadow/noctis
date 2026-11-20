<!--
Thanks for contributing to noctis!

For a new/updated detection feed or an engine change, consider the specialized
templates — append ?template=feed.md or ?template=engine.md to the PR URL.

Keep the PR focused on one logical change. Fill in the sections below.
-->

## What

<!-- A short description of the change and the motivation behind it. -->

## Type of change

- [ ] New detection feed
- [ ] Engine capability (action / primitive / builtin)
- [ ] Mock / test infrastructure
- [ ] Bug fix
- [ ] Documentation
- [ ] Other (describe)

## How it was verified

<!-- Commands you ran and their results. For a detection, show the
true-positive (vuln) and true-negative (patched) outcomes. -->

## Checklist

- [ ] One logical change; the PR is focused
- [ ] `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` are clean
- [ ] `cargo test` passes
- [ ] YAML feeds validate and `.feed-shas.json` is regenerated & committed (if feeds changed)
- [ ] No third-party vulnerability-database text/branding copied into code, feeds, or this PR
- [ ] Linked the relevant issue below

## Related issues

<!-- e.g. Closes #123 -->

<!--
Bug fix. See CONTRIBUTING.md. Open this template with ?template=fix.md
-->

## Bug

<!-- What was broken, and the impact. -->

Closes #

## Root cause

<!-- Why it happened. -->

## Fix

<!-- What this change does, and why it's the right, minimal fix. -->

## Verification

<!-- Reproduce the failure first, then show it resolved — paste the before/after. -->

## Checklist

- [ ] Reproduced the failure, then confirmed this change resolves it
- [ ] Added/updated a test that fails without this fix (or explained why not)
- [ ] `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` are clean
- [ ] `cargo test` passes
- [ ] If a feed was touched: `task feeds-check -- --write` run and `.feed-shas.json` committed
- [ ] Considered regression risk and kept the change scoped

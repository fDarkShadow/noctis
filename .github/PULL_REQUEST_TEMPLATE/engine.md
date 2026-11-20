<!--
Engine capability: a new step action, network primitive, or expression builtin.
See CONTRIBUTING.md and CLAUDE.md.
-->

## What capability does this add?

<!-- The new action / primitive / builtin and the feeds it unlocks. -->

## Design & trade-offs

<!-- Why this approach? If a new dependency is introduced, justify it (prefer a
maintained pure-Rust crate over hand-rolling a binary protocol). Link the issue
where the approach was agreed. -->

## Surface changes

- [ ] New/changed step action wired in `src/engine/step.rs` + `src/engine/actions/`
- [ ] New step fields added to `src/model/step.rs`
- [ ] New expression builtin registered in `src/expr/rhai.rs`
- [ ] `schemas/feed.schema.json` updated (new action and/or fields)

## Verification

<!-- Unit tests added, and (if applicable) a feed exercising the capability with
a TP/TN mock. Paste the relevant results. -->

- [ ] Unit tests added/updated
- [ ] `cargo test` passes
- [ ] `cargo fmt --all` + `cargo clippy --locked -- -D warnings` clean
- [ ] Backward compatible with existing feeds (or the break is documented)

## Related issues

<!-- e.g. Closes #123 -->

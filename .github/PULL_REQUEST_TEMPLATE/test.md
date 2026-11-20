<!--
Tests only — no production behaviour change. See CONTRIBUTING.md.
Open this template with ?template=test.md
-->

## What this adds

<!-- The unit tests, feed true-positive/true-negative coverage, or mock
improvements added. -->

## Why

<!-- The gap being closed — a bug, an edge case, or an untested code path. -->

## Verification

<!-- Paste the results. For a feed, show vuln → finding and patched → no finding. -->

## Checklist

- [ ] No production code behaviour change (tests / mocks / CI only)
- [ ] `cargo test` passes
- [ ] For feed TP/TN: vuln host → finding, patched host → zero findings (results pasted above)
- [ ] If a feed/mock was touched: `task feeds-check -- --write` / `task mocks-manifest` run as needed

## Related issues

<!-- e.g. Closes #123 -->

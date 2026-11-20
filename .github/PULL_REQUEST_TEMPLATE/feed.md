<!--
New or updated detection feed. See CONTRIBUTING.md and CLAUDE.md.
-->

## Vulnerability / misconfiguration

<!-- What this feed detects, and why it matters. -->

- **Feed:** `tests/vulnerabilities/<product>/<id>.yaml`
- **CVE(s):** <!-- CVE-YYYY-NNNNN, several, or "none (misconfiguration/exposure)" -->
- **Services:** <!-- e.g. http, https, ssh, mongodb -->
- **Category / severity / QoD:**

## Detection strategy

<!-- Which step actions it uses and what it matches on. -->

## Mock

- **Mock dir:** `infra/docker/<product>-mock/`
- `vuln` behaviour:
- `patched` behaviour:

## Verification (required)

<!-- Show the true-positive and true-negative results. -->

| Host | Expected | Result |
|------|----------|--------|
| vuln | finding | <!-- qod / confidence --> |
| patched | no finding | |

## Checklist

- [ ] `uid` is a fresh, unique UUID v4
- [ ] `cves:` cardinality is correct (`[]` for a 0-CVE check; `category:` set)
- [ ] `task feeds-check -- --write` run and `.feed-shas.json` committed in this PR
- [ ] Feed validates against `schemas/feed.schema.json`
- [ ] Mock ships `vuln` **and** `patched`; existing mocks extended (never overwritten); `task mocks-manifest` run
- [ ] Inventory (4 hosts min for http/https; `expected_qod` + `expected_min_confidence` on vuln hosts) and `10-`prefixed playbook added
- [ ] `task test ID=<id>` passes (TP on vuln, TN on patched)
- [ ] Detection described as a generic observable fact — no third-party DB/scanner text or branding copied in
- [ ] The feed is self-contained (no shared state / knowledge base)

## Related issues

<!-- e.g. Closes #123 -->

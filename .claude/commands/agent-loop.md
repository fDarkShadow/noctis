# noctis — agent loop

You are an autonomous implementation agent for the noctis scanner.
Your role: pick a GitHub issue, implement the feed + test infrastructure, open a PR.

## Iteration cycle

### 1. Find the next available issue

```bash
gh issue list \
  --label "status:available" \
  --state open \
  --json number,title,labels,body \
  --jq 'sort_by(.labels | map(select(.name == "priority:high")) | length) | reverse | .[0]'
```

If no issue is available: print "No available issues." and stop.

### 2. Claim the issue (distributed lock)

```bash
ISSUE=<number>
gh issue edit $ISSUE \
  --add-label "status:in-progress" \
  --remove-label "status:available" \
  --assignee "@me"
```

### 3. Parse the issue body

Extract from the body:
- CVE ID or check name
- Product, affected versions, severity, target services
- Description, detection strategy, references, Docker mock notes

### 4. Create an isolated worktree

```bash
CVE=<cve-id>   # e.g. CVE-2024-1234
BRANCH="feat/$CVE"
git worktree add "../noctis-$CVE" -b "$BRANCH"
cd "../noctis-$CVE"
```

### 5. Implement

Follow CLAUDE.md strictly. For each CVE/misconfig:

**a) YAML feed** — `tests/cve/<CVE>.yaml` or `tests/misconfig/<name>.yaml`
  - Generate a fresh valid UUID v4 (variant byte `[89ab]`)
  - Always set `services:`
  - Use `tcp_connect` for any URL-encoded path payload
  - Use `resp.banner` (never `resp.data`)
  - Never define `port:` or `scheme:` in `vars:`

**b) Docker mock** — `infra/docker/<name>/`
  - `Dockerfile.vuln` + `Dockerfile.patched`
  - Use `python:3.11-slim` base for proprietary appliances
  - Serve HTTP:80 + HTTPS:443 (self-signed cert via openssl)
  - Use `_make_https_server()` + `threading.Thread` pattern for Python mocks
  - Use `SSLSessionCache none` + `Mutex file:` for Apache (not shmcb)
  - Debian Buster EOL: patch sources.list to archive.debian.org first

**c) Inventory** — `infra/inventories/<CVE>/hosts.yml`
  - 4 hosts: `_vuln`, `_vuln_https`, `_patched`, `_patched_https`
  - Add `container_port: 443` on HTTPS hosts
  - Never add `target_port`

**d) Playbook** — `infra/playbooks/<CVE>.yml` (copy an existing one)

**e) site.yml** — add `import_playbook: playbooks/<CVE>.yml`

**f) Taskfile.yml** — add the CVE to `vars.INVENTORIES`

**g) build_local_images.yml** — add build tasks for the new images

### 6. Build images

```bash
cd infra
task build
```

If it fails: diagnose, fix, retry. Do not proceed until images build successfully.

### 7. Run tests

```bash
task test CVE=<CVE>
```

Expected: 4 passing tests (vuln HTTP, vuln HTTPS, patched HTTP, patched HTTPS).

On failure:
- Analyse the Ansible output
- Fix the feed or the mock
- Rebuild if needed
- Retry up to 3 times
- After 3 failures: open the PR anyway with label `needs-help`, document the error in the PR body

### 8. Validate the schema

```bash
cd ..  # repo root
npx ajv-cli validate -s schemas/feed.schema.json \
  -d "tests/cve/<CVE>.yaml" --spec=draft7 --allow-union-types
```

Fix any validation error before continuing.

### 9. Commit and push

```bash
git add tests/ infra/
git commit -m "feat(<CVE>): add detection feed and test infrastructure

- Feed YAML with <detection_method>
- Python/Docker mock (vuln + patched), HTTP + HTTPS
- Ansible inventory + playbook, 4 test cases

Closes #<ISSUE>"
git push origin "$BRANCH"
```

### 10. Open the PR

```bash
gh pr create \
  --title "feat(<CVE>): <product> — <short description>" \
  --body "$(cat <<'EOF'
## CVE / Check

**Issue:** #<ISSUE>
**CVE:** <CVE_ID>
**Product:** <product>
**CVSS:** <cvss>

## Implementation

- Feed: `tests/cve/<CVE>.yaml`
- Mock: `infra/docker/<name>/` (HTTP:80 + HTTPS:443)
- Tests: 4 cases (vuln/patched × HTTP/HTTPS)

## Test results

\`\`\`
<paste task test output here>
\`\`\`

## Checklist

- [ ] YAML feed validated by ajv-cli
- [ ] Valid UUID v4
- [ ] 4 passing tests (TP×2 + TN×2)
- [ ] Schema respected (additionalProperties)
EOF
)"
```

### 11. Update the issue

```bash
gh issue edit $ISSUE \
  --add-label "status:review" \
  --remove-label "status:in-progress"
gh issue comment $ISSUE --body "PR opened: <pr_url>"
```

### 12. Clean up the worktree

```bash
cd /home/flo/workspace/iscan
git worktree remove "../noctis-$CVE" --force
```

## Hard rules

- Never merge a PR
- Never hardcode `target_port` in an inventory
- Never commit directly to `main`
- After 3 test failures with no resolution: open a PR with label `needs-help`
- Always generate a fresh UUID v4 — never reuse an existing one

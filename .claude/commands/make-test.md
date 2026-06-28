# noctis — agent loop

You are an autonomous implementation agent for the noctis scanner.
Your role: pick a GitHub issue, implement the feed + test infrastructure, open a PR.

## Iteration cycle

### 0. Read CLAUDE.md

Before touching any file, read the project instructions in full:

```bash
cat CLAUDE.md
```

CLAUDE.md contains every convention, result field, known pitfall, Python mock template,
and reference feed you need. Do not skip this step — it will save you from rediscovering
patterns the hard way mid-implementation.

### 1. Resume check (context loss recovery)

Before picking a new issue, check if a previous iteration was interrupted (token pressure,
context summarization, crash). An interrupted run leaves an issue assigned to @me with
`status:in-progress` and possibly a worktree on disk.

```bash
# Is there already an in-progress issue assigned to me?
gh issue list \
  --label "status:in-progress" \
  --assignee "@me" \
  --state open \
  --json number,title,body \
  --jq '.[0]'
```

**If an in-progress issue is found**, first check if it is already fully done:

```bash
ISSUE=<number from above>
CVE=<cve id parsed from issue title/body>
BRANCH="feat/$CVE"

# Does the issue already carry status:review?
gh issue view $ISSUE --json labels --jq '[.labels[].name] | contains(["status:review"])'

# Is a PR already open on this branch?
gh pr list --head "$BRANCH" --json number,url --jq '.[0]'
```

**If `status:review` is present OR a PR is already open** — the iteration was completed but
cleanup was skipped. Finish the cleanup now and move on:

```bash
# Ensure labels are correct
gh issue edit $ISSUE \
  --add-label "status:review" \
  --remove-label "status:in-progress"

# Remove stale worktree if still on disk
git worktree list | grep "noctis-$CVE" \
  && git worktree remove "../noctis-$CVE" --force || true
```

Then continue to Step 2 — do not re-implement this issue.

**Otherwise** (issue is genuinely in-progress), reconstruct state and resume:

```bash
# Is the worktree still on disk?
git worktree list | grep "noctis-$CVE"
```

Determine the resume point by checking what already exists:

| What exists | Resume at |
|-------------|-----------|
| Worktree exists, feed + mock present | Step 8 (run tests) |
| Worktree exists, feed present, no mock | Step 6c (Docker mock) |
| Worktree exists but mostly empty | Step 6a (feed) |
| No worktree | Step 5 (create worktree) |

If the worktree is gone, recreate it:
```bash
git worktree add "../noctis-$CVE" "$BRANCH"
```

Once resumed, continue from the identified step and complete the iteration normally.

**If no in-progress issue is found**, continue to Step 2.

### 2. Find the next available issue

```bash
gh issue list \
  --label "status:available" \
  --state open \
  --json number,title,labels,body \
  --jq 'sort_by(.labels | map(select(.name == "priority:high")) | length) | reverse | .[0]'
```

If no issue is available: print "No available issues." and stop.

### 3. Claim the issue (distributed lock)

```bash
ISSUE=<number>
gh issue edit $ISSUE \
  --add-label "status:in-progress" \
  --remove-label "status:available" \
  --assignee "@me"
```

### 4. Parse the issue body

Extract from the body:
- CVE ID or check name
- Product, affected versions, severity, target services
- Description, detection strategy, references, Docker mock notes

### 5. Create an isolated worktree

```bash
CVE=<cve-id>   # e.g. CVE-2024-1234
BRANCH="feat/$CVE"
git worktree add "../noctis-$CVE" -b "$BRANCH"
cd "../noctis-$CVE"
```

### 6. Implement

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
  - On every vuln host, set `expected_qod` and `expected_min_confidence` to match
    the **highest** detection branch the mock actually exercises:

    | Detection branch | `expected_qod` | `expected_min_confidence` |
    |-----------------|----------------|--------------------------|
    | Banner / version fingerprint | 50–70 | `confidence_base` + banner delta |
    | Response analysis (body/header pattern) | 75 | `confidence_base` + resp delta |
    | Confirmed RCE / exploit output | 97 | `confidence_base` + rce delta |
    | OOB callback received | 97 | `confidence_base` + oob delta |

    Example for a feed with `confidence_base: 0.20` where the RCE branch adds `0.75`:
    ```yaml
    bigip_vuln:
      expected_qod: 97
      expected_min_confidence: 0.90
    ```

    If the feed has multiple branches (safe probe QoD 75 **and** RCE QoD 97), the mock
    must implement the RCE endpoint so the QoD 97 branch fires. Set `expected_qod: 97`.
    A QoD 75 finding on a host where you set `expected_qod: 97` means the RCE path failed.

**d) Playbook** — `infra/playbooks/10-<CVE>.yml` (copy an existing one — the `10-` prefix is mandatory;
  `task test-all` auto-discovers playbooks by sorted filename)

**e) Bake target** — add a matrix target in the appropriate `infra/bake/<family>.hcl`
  (or create a new file for a new product family). See CLAUDE.md for the template.
  `task build` picks up all `*.hcl` files automatically — no other registration needed.

### 7. Build images

```bash
cd infra
task build
```

If it fails: diagnose, fix, retry. Do not proceed until images build successfully.

### 8. Run tests and verify branch coverage

```bash
task test CVE=<CVE>
```

Expected: **4 passing tests** — but a green count is not enough. After the run, check:

**a) TP hosts — right branch fired**

  In the Ansible "Findings detail" output, verify for each vuln host:
  - `qod` equals the `expected_qod` you set in the inventory
    (e.g., 97 for RCE, 75 for response analysis, not 50 for a mere banner match)
  - `confidence` ≥ `expected_min_confidence`
  - `evidence` contains the text proving the intended code path executed
    (e.g., "RCE confirmed via bash endpoint" — not just "status 200")

  If `qod` is lower than expected: a shallower branch fired. Either the mock doesn't
  implement the deeper path, or a `condition:` guard is wrong. Fix and rebuild.

**b) All feed branches are exercised**

  Count the `on_match` blocks in your feed. Each one is a detection branch.
  If a branch is never reached in any test:
  - The mock doesn't implement that endpoint/behaviour → fix the mock
  - The `condition:` guarding that step is wrong → fix the feed

  A feed with two branches (safe probe + RCE) where only the safe probe ever fires is
  an undertested feed. The RCE mock endpoint must produce the expected output.

**c) TN hosts — no false positives**

  Trace through each step in your feed against the patched mock's responses.
  Common FP sources:
  - A step with no `condition:` fires unconditionally, and the pattern accidentally
    matches a generic error page on the patched host
  - The patched mock returns the same status code as the vuln mock on a different path

  If a TN fails: add a tighter `condition:` guard or narrow the regex pattern.

**d) OOB feeds**

  If the feed uses `wait_oob`, the relevant vuln hosts must have `noctis_use_oob: true`
  in the inventory. Verify the "Findings detail" shows `qod: 97` — this proves the OOB
  callback was actually received, not just that the HTTP request was sent.

On any failure:
- Analyse the Ansible output (confidence, QoD, evidence)
- Fix the feed or the mock, rebuild if needed
- Retry up to 3 times
- After 3 failures: open the PR with label `needs-help`, document the error in the PR body

**If the failure is caused by a bug in the Rust engine** (not in the feed or the mock):
→ see [Handling engine bugs](#handling-engine-bugs) below.

### 9. Validate the schema

```bash
cd ..  # repo root
npx ajv-cli validate -s schemas/feed.schema.json \
  -d "tests/cve/<CVE>.yaml" --spec=draft7 --allow-union-types
```

Fix any validation error before continuing.

### 10. Commit and push

```bash
git add tests/ infra/
git commit -m "feat(<CVE>): add detection feed and test infrastructure

- Feed YAML with <detection_method>
- Python/Docker mock (vuln + patched), HTTP + HTTPS
- Ansible inventory + playbook, 4 test cases

Closes #<ISSUE>"
git push origin "$BRANCH"
```

### 11. Open the PR

```bash
gh pr create \
  --title "feat(<CVE>): <product> — <short description>" \
  --reviewer fDarkShadow \
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
- Detection branch: `expected_qod=<N>` / `expected_min_confidence=<X.XX>`

## Test results

\`\`\`
<paste task test output here — include the "Findings detail" lines showing cve_id, severity, confidence%, qod, evidence>
\`\`\`

## Checklist

- [ ] YAML feed validated by ajv-cli
- [ ] Valid UUID v4
- [ ] 4 passing tests (TP×2 + TN×2)
- [ ] Schema respected (additionalProperties)
- [ ] `expected_qod` set in inventory — right detection branch fired (QoD ≥ expected)
- [ ] `expected_min_confidence` set in inventory — confidence proves steps ran, not just base
- [ ] Finding `cve_id` matches CVE
- [ ] Patched mock produces zero findings (no false positive)
EOF
)"
```

### 12. Update the issue

```bash
gh issue edit $ISSUE \
  --add-label "status:review" \
  --remove-label "status:in-progress"
gh issue comment $ISSUE --body "PR opened: <pr_url>"
```

### 13. Clean up the worktree

```bash
cd /home/flo/workspace/iscan
git worktree remove "../noctis-$CVE" --force
```

### 14. Stop

Print a one-line summary and exit:
```
✔ agent-loop done — <CVE> — PR #<N> opened — <N> issues remaining
```

**Do not pick another issue. Do not continue.** The orchestrator (run-agents.sh or
/loop run-agents) is responsible for launching the next iteration.

---

## Handling engine bugs

During implementation you may discover a bug in the noctis Rust source (wrong field name,
missing action support, broken parser, unexpected behaviour in `tcp_connect` / `http_request`,
etc.). The response depends on the scope of the bug.

### Criterion: is the fix self-contained?

A fix is **self-contained** if ALL of the following are true:
- It touches ≤ 3 lines in a single file under `src/`
- It does not change any public interface (structs, enums, function signatures)
- `cargo test` still passes after the change
- The reason the fix is correct is immediately obvious from the code

Examples of self-contained fixes:
- Wrong field name in a struct (`resp.data` → `resp.banner`)
- Missing `serde` attribute on a new field
- Off-by-one in a condition
- Missing `services:` field allowed to be empty when it shouldn't be

Examples that are **not** self-contained:
- Behaviour change in `tcp_connect`, `http_request`, or `runner.rs`
- Concurrency or timeout issues
- TLS handshake or crypto provider problems
- Anything that could affect feeds already passing their tests

---

### Case A — Self-contained fix

Fix it on the current branch. Then:

```bash
cargo build 2>&1
cargo test 2>&1
```

Both must pass before continuing. Include the fix in the commit:

```
feat(<CVE>): add feed + fix <what> in src/<file>.rs

- Feed YAML with <detection_method>
- Python/Docker mock (vuln + patched), HTTP + HTTPS
- Ansible inventory + playbook, 4 test cases
- Fix: <one-line description of the engine fix>

Closes #<ISSUE>
```

Add to the PR checklist:
```
- [x] Engine fix included — <description> (src/<file>.rs)
- [ ] cargo test passes
```

---

### Case B — Non-trivial engine bug

Do not attempt to fix it on this branch. Instead:

**1. Open a bug issue:**
```bash
gh issue create \
  --title "bug: <short description of the engine problem>" \
  --label "type:bug,priority:high" \
  --body "$(cat <<'BODY'
## Discovered while implementing #<ISSUE>

### Symptom
<What happened — exact error or wrong behaviour>

### Reproduction
<Minimal YAML step or cargo test that triggers it>

### Expected behaviour
<What should happen>

### Affected code
`src/<file>.rs` line <N> — <brief diagnosis>

### Workaround used in #<ISSUE>
<If you found a workaround, describe it here>
BODY
)"
```

**2. Work around it in the feed if possible:**
Adjust the YAML steps to avoid triggering the broken code path (different action,
different payload structure, etc.). Document the workaround in the feed with a comment.

**3. If no workaround is possible:**
Open the PR with label `needs-help`. In the PR body:
- Reference the bug issue
- Explain exactly what blocks implementation
- Leave the test results showing the failure

**4. Either way:** unblock the issue and move on:
```bash
gh issue edit $ISSUE \
  --add-label "status:review" \
  --remove-label "status:in-progress"
gh issue comment $ISSUE --body "PR opened: <pr_url> — blocked by engine bug <bug_issue_url>"
```

---

## Hard rules

- Never merge a PR
- Never hardcode `target_port` in an inventory
- Never commit directly to `main`
- After 3 test failures with no resolution: open a PR with label `needs-help`
- Always generate a fresh UUID v4 — never reuse an existing one

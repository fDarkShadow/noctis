# Stage 4 — Worker PR review

You are running unattended via `claude -p` on a fixed schedule (systemd timer, no one watching).
No conversation history, no one to ask. This is the second half of the same "review, then fix"
role you play in Stage 2 — a worker PR that fails `task test` is not automatically worse than a
Stage-1 candidate with a placeholder defect; fix what's fixable, block what's genuinely blocked
on a missing engine capability, and only surface `needs-help` for a human when neither applies.

**Ground truth**: CI never runs `task test`/`task test-all` (no Ansible/Podman in GitHub Actions —
see CLAUDE.md). A green CI check on a worker PR proves nothing about whether the feed actually
detects the vulnerability. You must run `task build && task test ID=<ID>` yourself, locally, for
every PR — that is the only authoritative signal.

## Task

1. List every open worker PR:
   ```
   gh pr list --label status:review --label worker:local-llm --state open --json number,title,headRefName,body
   ```
   If there are none, print "No worker PRs pending review." and stop.

2. For each PR:

   **a. Checkout and identify.**
   ```
   gh pr checkout <N>
   ```
   Find the linked vulnerability issue: `gh pr view <N> --json closingIssuesReferences -q '.closingIssuesReferences[].number'`.
   Derive `<ID>` (the CVE/slug used in `task test ID=<ID>`) from the branch name (`feat/<ID>`) or
   the feed file added under `tests/vulnerabilities/<vendor>/<ID>.yaml`.

   **b. Run the authoritative test.**
   ```
   cd infra && task build && task test ID=<ID> ; cd ..
   ```
   Capture the full output — you need the "Findings detail" lines (qod, confidence, evidence),
   not just the pass/fail exit code.

   **c. Review the diff regardless of pass/fail.** `gh pr diff <N>`. Check against CLAUDE.md's
   known pitfalls even if tests pass (a test can pass for the wrong reason): `resp.banner` not
   `resp.data`, `port: "{{port}}"` set on every step, valid UUID v4 (regenerate if not — never
   trust a worker-generated uid), `set_var` uses `var_name`/`var_value` not a `vars:` map,
   `evidence:` is a string not a list, no `port:`/`scheme:` redefined in `vars:`. If a mock was
   reused (check `infra/docker/MOCKS.md` after running `task mocks-manifest`), confirm no other
   consumer's endpoint was overwritten — re-run `task test ID=<other-id>` for every other listed
   consumer if the diff touched a shared mock file.

   **d. Decide, in this order:**

      - **Passes cleanly and the diff looks correct** → this PR is done. Go to step (e) APPROVE.

      - **Fails, or passes for the wrong reason, but you can fix it** (wrong field name, wrong
        endpoint, missing mock branch, wrong QoD/confidence expectation, missing
        `task feeds-check -- --write` / `task mocks-manifest` regen, etc.) → fix it yourself:
        edit the feed/mock/inventory files directly, re-run `task build && task test ID=<ID>`
        until it passes, then commit and push to the PR's OWN branch:
        ```
        git add tests/ infra/
        git commit -m "fix(<ID>): <what you fixed>

        Reviewed by Stage 4 — <one line on what was wrong and what changed>"
        git push origin <headRefName>
        ```
        Go to step (e) APPROVE.

      - **Blocked on a missing noctis engine capability** (the detection mechanism genuinely
        cannot be expressed with `http_request`/`tcp_connect`/`match`/`ssh_check`/`tls_check`/the
        HTTP-only OOB primitive — same class of gap as `automation/stage2_backlog_review` and
        `.claude/commands/make-test.md`'s "Handling a missing engine feature" section) → do NOT
        keep trying to force a fix. Follow the identical convention:
        1. `gh issue list --label type:feature --state open --json number,title` — reuse an
           existing one if it matches, otherwise create one (`type:feature,priority:medium`,
           same body shape as Stage 2's: what's missing, why existing primitives don't cover it,
           reference the source, cite the relevant `src/` file if you can identify it).
        2. Comment on the PR and on the linked vulnerability issue, cross-referencing the
           feature issue.
        3. `gh issue edit <linked-issue> --add-label status:delayed --remove-label status:in-progress`
        4. `gh pr close <N> --comment "Blocked on missing engine feature: <feature_issue_url> — closing, nothing to merge until that capability exists."`
        5. Go to step (f) — do not label this PR ready-for-human, it's closed.

      - **Fails and you genuinely cannot fix it within this session** (the mock's vulnerable
        behavior needs a substantial rewrite you can't safely complete unattended, or repeated
        fix attempts still fail) → do NOT silently discard it and do NOT reopen the source issue
        to `status:available` for a blind retry (an unattended worker retrying the same failure
        mode is not more likely to succeed than you). Instead surface it for a human:
        ```
        gh pr edit <N> --add-label needs-help --remove-label status:review
        gh issue edit <linked-issue> --add-label needs-help
        gh pr comment <N> --body "<precise diagnosis: what's wrong, what you tried, what's still needed>"
        ```
        Leave the PR OPEN (a human needs to see it in their PR list). Go to step (f).

   **e. APPROVE.**
   ```
   gh pr edit <N> --add-label status:ready-for-human --remove-label status:review
   gh pr comment <N> --body "<one-paragraph summary: what was verified, what (if anything) was fixed, task test result>"
   ```
   **Never run `gh pr merge`** — this hands off to the human, it does not finish the job.

3. Print ONE compact summary line per PR:
   ```
   #<N> <ID> -> READY(<clean | fixed: what>) | BLOCKED(#<feature-issue>) | NEEDS-HELP(<short reason>)
   ```
   End with a total line: `Stage 4 — X ready (Y fixed), Z blocked, W needs-help, V total.`

## Hard rules

- Never `gh pr merge`, under any circumstance.
- Never push to `main`, never force-push. Always push to the PR's own existing branch.
- Never skip actually running `task build && task test ID=<ID>` — a PR that "looks right" on
  diff alone is not verified. CI passing is not verified either (CI doesn't run these tests).
- Only fix using facts grounded in the cited source / the existing codebase conventions — do not
  invent detection logic to make a test pass; if the only way to make it pass is to weaken what's
  actually being verified, that's a `needs-help` case, not a fix.
- If a `gh`/`git`/`task` call fails unexpectedly (not a test failure, an actual tooling error),
  print the error and stop processing that PR — move to the next one, do not retry in a loop.

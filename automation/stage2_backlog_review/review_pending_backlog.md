# Stage 2 — Pending-backlog review

You are running unattended via `claude -p` on a fixed schedule (systemd timer, no one watching).
You have no conversation history and no one to ask — decide everything from the data below and
the current repo state. This step exists to keep token spend low relative to fully re-researching
every candidate, but "cheap" does not mean "reject anything imperfect" — Stage 1's local model is
known to leave fixable defects (an unfilled template placeholder, a missing field) in otherwise
good candidates. A KEV-listed critical CVE is not disposable just because a draft was sloppy.
Your job is triage AND repair, not just pass/fail — the same "review, then fix" role you play on
worker PRs in Stage 4 applies here too.

## Task

1. List every open issue labeled `status:pending-review`:
   ```
   gh issue list --label status:pending-review --state open --json number,title,body,labels
   ```
   If there are none, print "No pending-review issues." and stop — do nothing else.

2. For each issue, check all four of the following:

   **a. Dedup.** Does its "CVE ID(s)" section overlap with a CVE already present in
   `tests/vulnerabilities/*/*.yaml` (grep `^cves:` across that glob), or with a CVE already
   claimed by a different OPEN issue (`gh issue list --state open --json number,title`, any
   status label, not just this batch)? If yes → REJECT (duplicate, not fixable — the other issue
   is canonical). Note: Stage 1's NASL sourcing can produce two different issues that both
   mention the same CVE (one plugin bundles several CVEs, another covers one individually with a
   different CVSS) — this is a known, expected overlap pattern, not a Stage-1 bug; just reject
   the redundant one (keep the issue with the higher score).

   **b. Exclusion-rule sanity check.** Re-derive from the issue's own "Threat intelligence"
   section: if CVSS < 7.0 AND KEV = no AND EPSS < 0.50, this issue should never have been
   created → REJECT (not fixable — the CVE genuinely doesn't meet the bar).

   **c. Detection strategy is sourced and complete.** The "### Detection strategy" section's
   "Source cited" line must name a real structured source (an OpenVAS NASL file, a Nuclei
   template path, or a PoC repository). This branches three ways:

      - **No source cited at all**, or the strategy reads as unsourced/invented prose → REJECT
        (unfixable — this pipeline has a known failure mode where an unsourced strategy is a
        hallucinated exploit mechanism that looks plausible but is wrong; never approve or try
        to complete one you can't ground in a real source).

      - **A source IS cited, but the drafted section has a fixable defect** — an unfilled
        template placeholder (literal text like `<path, verbatim from the structured source>`),
        a missing endpoint, an incomplete response pattern, or similar mechanical gaps → FIX IT
        YOURSELF: read the cited source file directly (it's a real path under `openvas/` or a
        Nuclei template — read the whole thing, not a grep snippet), extract the real values,
        and rewrite the "Detection strategy" section faithfully. See "How to fix" below.

      - **A source IS cited and the mechanism is fully specified, but it does not map onto
        noctis's existing engine capabilities** (`http_request`, `tcp_connect`, `match`,
        `ssh_check`, `tls_check`, and noctis's OOB primitive which is HTTP-callback-only via
        `{{oob_url}}`/`wait_oob` — NOT raw TCP/ICMP packet capture, NOT any protocol noctis's
        `checks/` modules don't implement) → this is the **"blocked on a missing feature"**
        branch. See below — do not silently invent a workaround, and do not reject a real,
        well-sourced CVE just because noctis can't test it yet.

   **d. Basic sanity.** A CVE ID is present and correctly formatted (or the section explicitly
   says "None" for a misconfiguration/heuristic check), a product/component is named, and the
   target is network-reachable over http/https (not something requiring local/SMB/authenticated
   access — the exclusion rule should already have filtered this, this is just a final check).

### How to fix a fixable detection-strategy defect

1. Read the full cited source file (`Read` the NASL/Nuclei path named in "Source cited").
2. Identify the real endpoint(s), request details, and confirmation condition(s) — if the source
   checks a compound condition (status code AND a body pattern, or multiple sequential requests),
   capture ALL of it, not just the first part.
3. Check whether the confirmation mechanism is expressible with noctis's existing primitives.
   If yes, rewrite the "Detection strategy" section with the real values (see CVE-2022-22963 /
   issue #313 for a worked example: NASL confirmed via raw TCP-SYN/ICMP capture, which was
   adapted — not invented — into an HTTP-OOB-callback payload using the same injection
   technique, with the adaptation clearly flagged in the text).
4. Push the corrected body:
   ```
   gh issue edit <N> --body "$(cat <<'EOF'
   <full corrected body, same structure as the original — do not drop other sections>
   EOF
   )"
   ```
   (Construct this inline via a Bash heredoc — do not write a temp file, you don't have Write
   tool access in this stage and don't need it.)
5. Comment briefly on what was wrong and what you changed (one short paragraph, not an essay).
6. This issue now counts as APPROVED — proceed to labeling as in step 3 below.

### Blocked-on-missing-feature branch

1. **Check for an existing feature request first**: `gh issue list --label type:feature --state open --json number,title,body` — search for one already describing the same missing capability (e.g. "raw TCP/ICMP OOB callback", "non-HTTP protocol support for X"). Match on the underlying capability, not exact wording.
2. **If none exists**, create one:
   ```
   gh issue create --title "feature: <short description of the missing engine capability>" \
     --label "type:feature,priority:medium" \
     --body "Needed to implement <CVE-ID> (noctis issue #<N>). <Describe exactly what noctis's engine is missing — e.g. an action/check that can capture a raw TCP SYN or ICMP echo, or a new protocol handler — and why the existing http_request/tcp_connect/oob primitives don't cover it. Reference the structured source that specifies the mechanism.>"
   ```
3. **Cross-reference both issues**: comment on the vulnerability issue linking the feature issue number (and vice versa) so either one leads to the other.
4. **Label the vulnerability issue** `status:delayed` (remove `status:pending-review`, do NOT
   add `status:available` — a worker must never claim a blocked feed). Leave `type:cve`/priority
   labels as-is.
5. This issue is neither "approved" nor "rejected" in the summary — report it as `BLOCKED(#<feature-issue-number>)`.
6. Re-activating a `status:delayed` issue once the feature ships is a manual/human step, not
   automated by this stage.

3. Act on each issue (skip this for BLOCKED issues — already labeled `status:delayed` above):
   - **Passes all checks (as-is, or after you fixed it)** → `gh issue edit <N> --add-label status:available --remove-label status:pending-review`
   - **Fails an unfixable check (a, b, or unsourced c)** → `gh issue edit <N> --add-label wontfix` then `gh issue close <N> --comment "<one-sentence reason, name which check failed>"`

4. Print ONE compact summary line per issue processed (this is a log file, not meant to be read
   interactively in real time):
   ```
   #<N> <CVE-or-slug> -> APPROVED | APPROVED(fixed: <what>) | REJECTED(<short reason>) | BLOCKED(#<feature-issue>)
   ```
   End with a total line: `Stage 2 — X approved (Y fixed), Z blocked, W rejected, V total.`

## Hard rules

- This stage only ever touches issues — never open, comment on, or close a PR here (that's
  Stage 4's job).
- Never run `git push`, `git commit`, or anything that modifies the working tree — fixes happen
  in the issue body via `gh issue edit`, never as a file edit or commit.
- When fixing a detection strategy, only use facts present in the cited source (plus the
  documented noctis primitives available to adapt the confirmation channel). Never invent a
  detail the source doesn't specify — if something is genuinely absent from the source after
  reading it in full, write "not specified in source", same as Stage 1 was supposed to.
- If a `gh` call or network request fails, print the error and stop immediately — do not retry
  in a loop. The next scheduled timer tick will retry the whole batch from scratch.

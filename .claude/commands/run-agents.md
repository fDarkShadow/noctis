# noctis — run-agents (loop mode)

You are an orchestrator running inside `/loop` mode.
Each wake-up: run one agent-loop iteration, then schedule the next wake-up.
Pause longer if you detect signs of token pressure or rate limiting.

---

## On every wake-up

### 1. Check available issues

```bash
gh issue list \
  --label "status:available" \
  --state open \
  --json number,title,labels \
  --jq 'sort_by(.labels | map(select(.name == "priority:high")) | length) | reverse'
```

If the list is empty: print "No available issues — stopping loop." and do NOT call
ScheduleWakeup. The loop ends here.

### 2. Run one agent-loop iteration

Invoke the full agent-loop protocol (from `.claude/commands/agent-loop.md`) for the
highest-priority available issue:
- Claim the issue
- Create a worktree
- Implement feed + mock + infra
- Build, test, validate schema
- Commit, push, open PR
- Update the issue labels
- Clean up the worktree

### 3. Assess pacing before scheduling the next wake-up

After completing (or failing) the iteration, choose the next delay:

| Situation | Delay |
|-----------|-------|
| Iteration completed normally, issues still available | 90s |
| Iteration hit 3 test failures (needs-help PR) | 120s |
| Iteration took unusually long (> 10 min of wall time) | 270s |
| Claude returned any error mentioning "rate limit", "quota", or "usage" | 1800s (30 min) |
| Uncertain — default | 90s |

The 270s threshold keeps the prompt cache warm (< 5 min TTL).
The 1800s delay is used only on confirmed rate-limit signals — wait for token reset.

### 4. Schedule next wake-up

```
ScheduleWakeup(
  delaySeconds = <chosen delay>,
  reason = "agent-loop iteration <N> done — <N> issues remaining",
  prompt = "run-agents"
)
```

Pass `"run-agents"` as the prompt so each wake-up re-enters this command.

---

## Token pressure signals

You cannot directly read your token usage %, but these are reliable proxies:

- Claude Code reports "context window approaching limit" → use 270s delay
- A previous iteration was truncated or produced an incomplete response → use 270s delay
- The response to a `gh` or `git` command came back with an error about the API
  mentioning rate limits or quotas → use 1800s delay

When in doubt about token pressure, prefer the longer delay. A 4-minute pause costs
little; a failed iteration costs a full worktree + CI run.

---

## Hard rules

- Run exactly **one agent-loop iteration per wake-up** — no parallelism
- Never merge a PR
- Never commit directly to `main`
- If the issue queue is empty, stop the loop (do not schedule another wake-up)
- If 3 consecutive iterations result in `needs-help` PRs, stop and print a summary
  — something systemic may be broken in the engine

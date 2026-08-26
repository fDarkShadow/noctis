"""Single source of truth for GitHub label strings used across all pipeline stages.

Every stage must import from here rather than hardcoding a label string — this is the
concrete fix for the type:cve/type:vulnerability drift found between CLAUDE.md and
fill-backlog.md during the pipeline design (see plan doc, "Constats techniques").
"""

# --- Status labels (existing, pre-pipeline) ---
STATUS_AVAILABLE = "status:available"
STATUS_IN_PROGRESS = "status:in-progress"
STATUS_REVIEW = "status:review"

# --- Status labels (new, added for this pipeline) ---
STATUS_PENDING_REVIEW = "status:pending-review"
STATUS_READY_FOR_HUMAN = "status:ready-for-human"
# A feed whose detection strategy needs a noctis engine capability that doesn't exist yet
# (e.g. raw TCP/ICMP callback confirmation — noctis's OOB is HTTP-callback-only). Blocked on
# a linked type:feature issue, not claimable by a worker. See STAGE 2's "Blocked on a missing
# engine feature" branch in review_pending_backlog.md — first used on CVE-2022-22963 (#313).
STATUS_DELAYED = "status:delayed"

# --- Priority ---
PRIORITY_HIGH = "priority:high"
PRIORITY_MEDIUM = "priority:medium"
PRIORITY_LOW = "priority:low"

# --- Type ---
TYPE_CVE = "type:cve"
TYPE_MISCONFIG = "type:misconfig"
TYPE_BUG = "type:bug"
TYPE_FEATURE = "type:feature"  # missing noctis engine capability, not a bug

# --- Worker / misc ---
WORKER_LOCAL_LLM = "worker:local-llm"
NEEDS_HELP = "needs-help"
WONTFIX = "wontfix"

# An issue counts toward the ~50-item backlog gate if it's in any of these statuses
# (deliberately includes pending-review so Stage 1 doesn't keep flooding the queue
# while Stage 2 review is lagging behind). status:delayed is deliberately EXCLUDED — a
# blocked feed isn't usable backlog capacity, so it doesn't count toward the target and
# doesn't suppress Stage 1 from sourcing more candidates.
IN_PIPELINE_STATUSES = {STATUS_AVAILABLE, STATUS_PENDING_REVIEW, STATUS_IN_PROGRESS}
VULN_TYPES = {TYPE_CVE, TYPE_MISCONFIG}


def priority_for_score(total_score: int) -> str:
    if total_score >= 10:
        return PRIORITY_HIGH
    if total_score >= 6:
        return PRIORITY_MEDIUM
    return PRIORITY_LOW

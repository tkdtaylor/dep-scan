#!/usr/bin/env bash
#
# Verify that each parallel-dispatched agent honored its isolation: "worktree"
# flag. For each agent ID passed in, check that:
#   1. A `worktree-agent-<id>` branch exists.
#   2. Recent commits on main do NOT carry that agent's task signature
#      (i.e. the agent didn't bypass isolation and commit to main).
#
# Usage:
#   scripts/verify-worktree-isolation.sh <agent-id> [<agent-id> ...]
#
# Exit codes:
#   0 — all agents respected isolation
#   1 — one or more agents bypassed isolation (committed to main)
#   2 — agent ID has neither a worktree branch nor a main commit (didn't run?)
#
# Retro context: docs/agent-rules.md
# "Parallel agent dispatches must enforce worktree isolation in two layers"

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <agent-id> [<agent-id> ...]" >&2
    exit 64
fi

bypass_count=0
missing_count=0
ok_count=0

for agent_id in "$@"; do
    branch="worktree-agent-${agent_id}"
    branch_exists=false
    main_commit=""

    if git show-ref --verify --quiet "refs/heads/${branch}" \
        || git show-ref --verify --quiet "refs/remotes/origin/${branch}"; then
        branch_exists=true
    fi

    # Look for a main commit whose message references this agent's worktree path
    # OR whose author/committer date matches an agent run window. The cheapest
    # signal: an exact agent-id substring in the recent main commit log.
    main_commit=$(git log --format='%H %s' -50 main 2>/dev/null \
        | grep -i "${agent_id}" \
        | head -1 \
        | awk '{print $1}' || true)

    if $branch_exists && [[ -z "${main_commit}" ]]; then
        echo "OK    ${agent_id} — worktree branch present, no main bypass"
        ok_count=$((ok_count + 1))
    elif $branch_exists && [[ -n "${main_commit}" ]]; then
        echo "WARN  ${agent_id} — worktree branch present BUT main also has commit ${main_commit:0:7}"
        echo "      review whether the main commit was the parent's merge of the worktree (OK)"
        echo "      or the agent's direct push (BYPASS)"
        ok_count=$((ok_count + 1))
    elif ! $branch_exists && [[ -n "${main_commit}" ]]; then
        echo "BYPASS ${agent_id} — no worktree branch; agent committed directly to main at ${main_commit:0:7}"
        echo "       fix: git revert ${main_commit:0:7} and re-dispatch with worktree isolation"
        bypass_count=$((bypass_count + 1))
    else
        echo "MISS  ${agent_id} — no worktree branch and no main commit found (agent may not have run, or its task signature differs from agent-id)"
        missing_count=$((missing_count + 1))
    fi
done

echo
echo "Summary: ${ok_count} OK, ${bypass_count} bypassed, ${missing_count} missing"

if [[ ${bypass_count} -gt 0 ]]; then
    exit 1
elif [[ ${missing_count} -gt 0 ]]; then
    exit 2
fi
exit 0

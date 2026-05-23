#!/usr/bin/env bash
#
# start-task.sh — set up branch-or-worktree isolation for a new task.
#
# Usage:
#   scripts/start-task.sh <NNN> <slug>
#
# What it does:
#   - Counts live Claude Code sessions on this project (via .claude/sessions/*.lock,
#     filtered to entries newer than the staleness window).
#   - If exactly one session is active (just us), creates branch `task/NNN-<slug>`
#     from the current default branch and switches to it.
#   - If two or more sessions are active (concurrent), creates a worktree at
#     `.claude/worktrees/NNN-<slug>/` on the same branch instead. The caller
#     should `cd` into that path before doing further work.
#
# Output:
#   Prints a single line on stdout describing what to do next, in one of two shapes:
#       BRANCH task/NNN-<slug>
#       WORKTREE .claude/worktrees/NNN-<slug>
#
# Exits 0 on success, non-zero on any setup failure. Errors go to stderr.
#
# Side effects:
#   - Creates the branch and (optionally) the worktree.
#   - Re-sweeps stale session locks before deciding (mtime > 4h → removed).

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <NNN> <slug>" >&2
    exit 64
fi

NNN="$1"
SLUG="$2"
TASK_REF="task/${NNN}-${SLUG}"
WORKTREE_DIR=".claude/worktrees/${NNN}-${SLUG}"
STALE_SECONDS=$(( 4 * 60 * 60 ))

cd "$(git rev-parse --show-toplevel)"

# Sweep stale locks (mtime older than staleness window). POSIX-portable.
sessions_dir=".claude/sessions"
mkdir -p "${sessions_dir}"

now=$(date +%s)
active=0
for lock in "${sessions_dir}"/*.lock; do
    [[ -f "${lock}" ]] || continue
    if mtime=$(stat -c %Y "${lock}" 2>/dev/null); then
        :
    elif mtime=$(stat -f %m "${lock}" 2>/dev/null); then
        :
    else
        continue
    fi
    age=$(( now - mtime ))
    if (( age > STALE_SECONDS )); then
        rm -f "${lock}"
        continue
    fi
    active=$(( active + 1 ))
done

# Determine the default branch (prefer `main`, fall back to `master` or HEAD).
default_branch=""
for candidate in main master trunk; do
    if git show-ref --verify --quiet "refs/heads/${candidate}"; then
        default_branch="${candidate}"
        break
    fi
done
if [[ -z "${default_branch}" ]]; then
    # Last resort — current HEAD if it's not a task branch.
    head_branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")
    if [[ -n "${head_branch}" && "${head_branch}" != task/* ]]; then
        default_branch="${head_branch}"
    fi
fi
if [[ -z "${default_branch}" ]]; then
    echo "start-task: cannot determine default branch (no main/master/trunk found)" >&2
    exit 2
fi

# If the task branch already exists, we re-use it; otherwise create from default.
existing_branch=""
if git show-ref --verify --quiet "refs/heads/${TASK_REF}"; then
    existing_branch="${TASK_REF}"
fi

if (( active >= 2 )); then
    # Concurrent session(s) detected → worktree mode.
    if [[ -d "${WORKTREE_DIR}" ]]; then
        echo "start-task: worktree ${WORKTREE_DIR} already exists — reusing it" >&2
    else
        mkdir -p "$(dirname "${WORKTREE_DIR}")"
        if [[ -n "${existing_branch}" ]]; then
            git worktree add "${WORKTREE_DIR}" "${TASK_REF}"
        else
            git worktree add -b "${TASK_REF}" "${WORKTREE_DIR}" "${default_branch}"
        fi
    fi
    echo "WORKTREE ${WORKTREE_DIR}"
    exit 0
fi

# Solo session → branch mode.
current_branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")
if [[ "${current_branch}" == "${TASK_REF}" ]]; then
    # Already on the task branch — nothing to do.
    echo "BRANCH ${TASK_REF}"
    exit 0
fi

# If we're on a different task branch, the caller should resolve that first.
if [[ "${current_branch}" == task/* ]]; then
    echo "start-task: currently on ${current_branch}, not switching automatically." >&2
    echo "start-task: commit or stash, switch to ${default_branch}, then re-run." >&2
    exit 3
fi

# If there are uncommitted changes, refuse silently — caller decides what to do.
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "start-task: working tree has uncommitted changes; refusing to switch branch." >&2
    echo "start-task: commit/stash first, then re-run." >&2
    exit 4
fi

if [[ -n "${existing_branch}" ]]; then
    git checkout "${TASK_REF}"
else
    git checkout -b "${TASK_REF}" "${default_branch}"
fi
echo "BRANCH ${TASK_REF}"

#!/usr/bin/env bash
#
# finish-task.sh — close a task: merge its branch into the default branch,
# delete the branch, remove its worktree, and VERIFY all three happened.
#
# Usage:
#   scripts/finish-task.sh <NNN> <slug> [--local] [--ff]
#
# Pairs with start-task.sh: that opens branch/worktree isolation for a task,
# this closes it. Unlike auto-cleanup-merge.py (best-effort, and only if a
# `git merge task/...` happens to run), this performs the merge itself and
# exits non-zero if the branch or worktree is still present afterward — so a
# forgotten merge or a piled-up worktree becomes a hard failure, not silent
# drift. Run it from anywhere in the repo (including inside the task worktree);
# it always operates on the main working tree.
#
# Options:
#   --local / --no-push  merge locally but do not push (avoids re-triggering CI
#                        on every task during a multi-task run)
#   --ff                 fast-forward merge instead of the default --no-ff
#                        (--no-ff keeps a merge commit marking the task boundary,
#                        matching the common "no direct commits to main" pattern)
#
# Exit codes:
#   0  merged + cleaned + verified
#   2  setup error (bad args, not a git repo, default branch undiscoverable)
#   3  precondition failed (task branch missing, dirty main tree, dirty worktree)
#   4  merge failed (conflict or other) — nothing deleted; resolve and retry
#   5  cleanup verification failed (merge done but branch/worktree still present)

set -euo pipefail

usage() { echo "Usage: $0 <NNN> <slug> [--local] [--ff]" >&2; }

NNN=""; SLUG=""; PUSH=1; FF="--no-ff"
for arg in "$@"; do
    case "$arg" in
        --local|--no-push) PUSH=0 ;;
        --ff)    FF="--ff-only" ;;
        --no-ff) FF="--no-ff" ;;
        -*) echo "finish-task: unknown option $arg" >&2; usage; exit 2 ;;
        *)
            if [[ -z "$NNN" ]]; then NNN="$arg"
            elif [[ -z "$SLUG" ]]; then SLUG="$arg"
            else echo "finish-task: unexpected argument $arg" >&2; usage; exit 2; fi
            ;;
    esac
done
[[ -n "$NNN" && -n "$SLUG" ]] || { usage; exit 2; }

TASK_REF="task/${NNN}-${SLUG}"
WORKTREE_REL=".claude/worktrees/${NNN}-${SLUG}"

git rev-parse --git-dir >/dev/null 2>&1 || { echo "finish-task: not a git repo" >&2; exit 2; }

# Always operate from the MAIN working tree: you cannot check out / merge into
# the default branch from inside a linked worktree, nor remove your own worktree.
common_dir=$(cd "$(git rev-parse --git-common-dir)" && pwd)
main_root=$(dirname "$common_dir")
g() { git -C "$main_root" "$@"; }

WORKTREE_ABS="${main_root}/${WORKTREE_REL}"

# Determine the merge target. TASK_BASE_BRANCH (if set and existing) overrides the
# default branch — the /autopilot integration-branch flow sets it so each task
# merges into the integration branch, not main. Unset → merge into the default branch.
default_branch=""
if [[ -n "${TASK_BASE_BRANCH:-}" ]]; then
    if g show-ref --verify --quiet "refs/heads/${TASK_BASE_BRANCH}"; then
        default_branch="${TASK_BASE_BRANCH}"
    else
        echo "finish-task: TASK_BASE_BRANCH=${TASK_BASE_BRANCH} set but that branch does not exist" >&2
        exit 2
    fi
fi
for cand in main master trunk; do
    [[ -n "$default_branch" ]] && break
    if g show-ref --verify --quiet "refs/heads/${cand}"; then default_branch="$cand"; break; fi
done
[[ -n "$default_branch" ]] || { echo "finish-task: cannot determine default branch (no main/master/trunk)" >&2; exit 2; }

# --- Preconditions -----------------------------------------------------------

if ! g show-ref --verify --quiet "refs/heads/${TASK_REF}"; then
    echo "finish-task: branch ${TASK_REF} does not exist — nothing to finish" >&2
    exit 3
fi

# A worktree with uncommitted work would lose it on removal — refuse.
if [[ -d "$WORKTREE_ABS" ]]; then
    if ! git -C "$WORKTREE_ABS" diff --quiet || ! git -C "$WORKTREE_ABS" diff --cached --quiet; then
        echo "finish-task: worktree ${WORKTREE_REL} has uncommitted changes — commit or discard them first" >&2
        exit 3
    fi
fi

# The main tree must be clean before we switch branches / merge.
if ! g diff --quiet || ! g diff --cached --quiet; then
    echo "finish-task: ${default_branch} working tree is dirty — commit/stash first" >&2
    exit 3
fi

current=$(g symbolic-ref --short HEAD 2>/dev/null || echo "")
if [[ "$current" != "$default_branch" ]]; then
    g checkout "$default_branch"
fi

# --- Merge -------------------------------------------------------------------

if ! g merge "$FF" -m "merge: task ${NNN} — ${SLUG}" "$TASK_REF"; then
    echo "finish-task: merge of ${TASK_REF} into ${default_branch} failed — aborting, no cleanup performed" >&2
    g merge --abort 2>/dev/null || true
    exit 4
fi

# --- Cleanup (worktree before branch: `branch -d` refuses while held) ---------

if [[ -d "$WORKTREE_ABS" ]]; then
    g worktree remove "$WORKTREE_ABS" 2>/dev/null \
        || g worktree remove --force "$WORKTREE_ABS" 2>/dev/null || true
fi
g worktree prune 2>/dev/null || true
g branch -d "$TASK_REF" 2>/dev/null || true

if [[ "$PUSH" -eq 1 ]]; then
    g remote get-url origin >/dev/null 2>&1 && g push 2>/dev/null || true
fi

# --- Verify post-conditions (the whole point of this script) -----------------

errs=()
if g show-ref --verify --quiet "refs/heads/${TASK_REF}"; then
    errs+=("branch ${TASK_REF} still present (merge may not have fully merged it)")
fi
if [[ -d "$WORKTREE_ABS" ]]; then
    errs+=("worktree dir ${WORKTREE_REL} still present")
fi
if g worktree list --porcelain 2>/dev/null | grep -q "${WORKTREE_REL}"; then
    errs+=("worktree ${WORKTREE_REL} still registered (run: git worktree prune)")
fi

if (( ${#errs[@]} > 0 )); then
    echo "finish-task: cleanup verification FAILED for ${TASK_REF}:" >&2
    for e in "${errs[@]}"; do echo "  - $e" >&2; done
    exit 5
fi

echo "FINISHED ${TASK_REF} → merged into ${default_branch}, branch + worktree removed$([[ "$PUSH" -eq 0 ]] && echo ' (local, not pushed)')"

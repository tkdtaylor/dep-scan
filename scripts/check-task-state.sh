#!/usr/bin/env bash
#
# check-task-state.sh — enforces the invariant that each task file
# (NNN-*.md under docs/tasks/) is tracked in EXACTLY ONE of
# {backlog, active, completed}.
#
# Duplicate copies across state directories happen when a task-executor's
# `git mv` / `git add` flow drifts, leaving stale paths still tracked
# alongside the new one. The fix is mechanical (`git rm <stale path>`)
# but only if you notice — without this check the duplicate ships.
#
# Exits 0 if every task is in exactly one state directory, 1 otherwise.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

violations=$(
    git ls-files 'docs/tasks/backlog/*.md' \
                 'docs/tasks/active/*.md' \
                 'docs/tasks/completed/*.md' \
        | awk -F/ '{ print $4, $3 }' \
        | sort \
        | awk '
            {
                name = $1
                state = $2
                count[name]++
                if (places[name] == "") {
                    places[name] = state
                } else {
                    places[name] = places[name] ", " state
                }
            }
            END {
                for (n in count) {
                    if (count[n] > 1) {
                        printf "  %s → %s\n", n, places[n]
                    }
                }
            }
        '
)

if [ -n "$violations" ]; then
    echo "FAIL: the following task files appear in more than one state directory:" >&2
    echo >&2
    printf '%s\n' "$violations" >&2
    echo >&2
    echo "Each task must live in exactly one of {backlog, active, completed}." >&2
    echo "When moving a task forward, use 'git mv' and verify with:" >&2
    echo "    git ls-files docs/tasks/ | grep <NNN>" >&2
    echo "before committing." >&2
    exit 1
fi

echo "OK: every task is tracked in exactly one state directory."

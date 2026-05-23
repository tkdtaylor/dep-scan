#!/usr/bin/env python3
"""PreToolUse hook for Bash — blocks `git commit` when HEAD is on main.

Working directly on the default branch is the failure mode that lets two
concurrent sessions silently overwrite each other and makes "abandon this
half-done task" require destructive ops. The fix is a branch-per-task
discipline: every task-executor invocation starts with a `task/NNN-<slug>`
branch (or worktree under concurrency).

This hook is the floor for that discipline. It refuses to let `git commit`
land on the default branch unless one of two escape hatches applies:

1. **No task branches exist yet** — the project is in its scaffold phase
   (the create-project skill itself commits initial setup on main). Once
   the first `task/*` branch is created, the rule fully engages.

2. **The commit message contains `[allow-main]`** — explicit operator
   override for cases like a deliberate doc-only commit, a hotfix, or
   the scaffold-time `chore: add project agents…` commit. Always
   self-documenting in `git log`.

Exit codes:
- 0 → allow
- 2 → block (Claude sees stderr and corrects)

Tokenization uses shlex.split so the marker can't be smuggled in via a
quoted argument elsewhere on the command line.
"""

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "minimal")

DEFAULT_BRANCHES = {"main", "master", "trunk"}


def current_branch(cwd: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "symbolic-ref", "--short", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


def any_task_branches(cwd: Path) -> bool:
    try:
        out = subprocess.run(
            ["git", "for-each-ref", "--format=%(refname:short)", "refs/heads/task/"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return bool(out.stdout.strip())


def is_git_commit(tokens: list[str]) -> bool:
    """Detect a `git commit` invocation in the token stream.

    Walks tokens left to right. `git` followed (possibly after `git`-level
    flags like `-c key=val`) by `commit` counts. A shell separator resets
    the state so chained commands don't false-match.
    """
    SEPARATORS = {"&&", "||", ";", "|", "&"}
    GIT_FLAGS_WITH_VALUE = {"-c", "-C", "--git-dir", "--work-tree", "--namespace"}

    in_git = False
    expect_value = False
    for tok in tokens:
        if tok in SEPARATORS:
            in_git = False
            expect_value = False
            continue
        if not in_git:
            if tok == "git":
                in_git = True
            continue
        # in_git == True
        if expect_value:
            expect_value = False
            continue
        if tok in GIT_FLAGS_WITH_VALUE:
            expect_value = True
            continue
        if tok.startswith("-"):
            # Any other git-level flag (-c, --no-pager, etc.) — keep scanning.
            if "=" in tok and tok.split("=", 1)[0] in GIT_FLAGS_WITH_VALUE:
                # Already paired (e.g. `--git-dir=...`)
                continue
            continue
        # First non-flag token after `git` is the subcommand.
        return tok == "commit"
    return False


def commit_message_allows_main(command: str) -> bool:
    """Look for an `[allow-main]` marker anywhere in the raw command.

    We scan the literal command text (not just the parsed tokens) so the
    marker can appear inside a `-m "..."` quoted message or a heredoc.
    """
    return bool(re.search(r"\[allow-main\]", command))


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    try:
        tokens = shlex.split(command)
    except ValueError:
        # Unparseable shell — let it through; bash will surface its own error.
        sys.exit(0)

    if not is_git_commit(tokens):
        sys.exit(0)

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    branch = current_branch(project)
    if branch is None or branch not in DEFAULT_BRANCHES:
        sys.exit(0)

    # On main/master/trunk — apply the escape hatches.
    if not any_task_branches(project):
        # Pre-first-task phase (scaffold). Let it through.
        sys.exit(0)

    if commit_message_allows_main(command):
        # Explicit operator override.
        sys.exit(0)

    print(
        f"BLOCKED: refusing to commit on `{branch}`.\n"
        f"\n"
        f"This project uses branch-per-task discipline — every task lives on\n"
        f"its own `task/NNN-<slug>` branch (or worktree under concurrent\n"
        f"sessions). Working on `{branch}` directly lets parallel sessions\n"
        f"silently overwrite each other.\n"
        f"\n"
        f"Fix one of these ways:\n"
        f"  1. Switch to a task branch:\n"
        f"       git checkout -b task/NNN-<slug>\n"
        f"     (or run `scripts/start-task.sh NNN <slug>` to auto-pick\n"
        f"     branch vs. worktree based on session concurrency)\n"
        f"\n"
        f"  2. Override deliberately by including `[allow-main]` in the\n"
        f"     commit message (e.g. doc-only fixes, hotfix patterns).\n",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    main()

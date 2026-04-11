#!/usr/bin/env python3
"""PreToolUse hook for Bash — blocks `git checkout -- <path>` over a dirty tree.

Background: `git checkout HEAD -- src/` (or any `git checkout … -- <path>`)
silently overwrites uncommitted working-tree changes with the prior commit's
content. The reflog does not capture uncommitted blobs, so the work is
unrecoverable. This hook intercepts that command pattern and refuses to run
it when the working tree has uncommitted changes that would be lost.

Allowed:
  - `git checkout -- <path>` over a CLEAN tree (it's a no-op anyway)
  - `git checkout <branch>` (no `--`, this is a branch switch — git itself
    will refuse if it would lose work, so we don't second-guess it)
  - `git checkout <ref> -- <path>` over a CLEAN tree
  - Any other git command (`git stash`, `git worktree add`, `git diff`, …)

Blocked:
  - `git checkout -- <path>` when `git diff` or `git diff --cached` is non-empty
  - `git checkout <ref> -- <path>` under the same condition
  - `git checkout HEAD -- .` and `git checkout -- .` (same hazard at full-tree scale)

Exit codes:
  0 — allow the command to proceed
  2 — block the command (stderr is shown to Claude)

Adapted from .claude/scripts/protect-secrets.py.

Origin: this hook was added after an agent ran `git checkout HEAD -- src/`
to take a "clean-tree baseline" for a clippy comparison and silently wiped
~1 hour of uncommitted in-progress work. The checkout is silent, has no
confirmation, and the reflog cannot recover uncommitted blobs. The
right tools for "compare to a prior commit" are `git diff <ref> -- <path>`,
`git show <ref>:<path>`, or `git worktree add ../baseline <ref>` — none of
which touch the working tree.
"""

import json
import os
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "minimal")


# Pattern: `git checkout … -- …` — the `--` is what makes it a path checkout
# rather than a branch/ref checkout. We match the literal `--` token after
# the `checkout` subcommand.
#
# Examples this matches:
#   git checkout -- src/
#   git checkout HEAD -- .
#   git checkout abc1234 -- src/main.rs
#   git checkout main -- docs/
#   cd foo && git checkout HEAD -- src/    (compound)
#
# Examples this does NOT match (no `--` token, or `git checkout` is text
# inside a quoted argument to another command — e.g. `git commit -m "...
# git checkout -- src/ ..."` — because `shlex.split` keeps the quoted
# argument as a single token):
#   git checkout main
#   git checkout -b new-branch
#   git checkout HEAD~1
#   git commit -m "mentions git checkout -- src/ in the message body"
def is_path_checkout(tokens: list[str]) -> bool:
    """Return True if `tokens` contains `git checkout … -- …` as a real
    command sequence. Token-position scan: ignores any occurrence inside
    a quoted string argument, since `shlex.split` collapses those into a
    single token."""
    for i in range(len(tokens) - 1):
        if tokens[i] == "git" and tokens[i + 1] == "checkout":
            if "--" in tokens[i + 2 :]:
                return True
    return False


def working_tree_dirty() -> bool:
    """Return True if `git diff` or `git diff --cached` reports any changes."""
    try:
        # `git diff --quiet` exits 1 if there are unstaged changes, 0 if clean.
        unstaged = subprocess.run(
            ["git", "diff", "--quiet"],
            capture_output=True,
            check=False,
        )
        staged = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            capture_output=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        # No git, or git not on PATH — let the command through and let
        # the user see the real error.
        return False
    return unstaged.returncode != 0 or staged.returncode != 0


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    if tool_name != "Bash":
        sys.exit(0)

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    # Tokenize the WHOLE command via shlex.split so quoted strings, heredoc
    # bodies, and `$(...)` substitutions stay collapsed inside a single
    # token and can't trigger the scan. shell separators like `&&` and `||`
    # become their own tokens, which lets `is_path_checkout` walk past
    # leading commands like `cd foo` to find a real `git checkout` invocation
    # in a compound command.
    try:
        tokens = shlex.split(command)
    except ValueError:
        # Unparseable shell (e.g. unterminated quote) — let it through and
        # let the user see the real error from bash itself.
        sys.exit(0)

    if is_path_checkout(tokens) and working_tree_dirty():
        for_show = command if len(command) <= 200 else command[:197] + "..."
        print(
            "BLOCKED: `git checkout -- <path>` would silently overwrite "
            "uncommitted changes.\n"
            "\n"
            f"  Command: {for_show}\n"
            "\n"
            "The reflog does NOT capture uncommitted blobs, so any work "
            "this command discards is unrecoverable.\n"
            "\n"
            "If you want to COMPARE to a prior commit (not overwrite):\n"
            "  - git diff <ref> -- <path>            (read-only diff)\n"
            "  - git show <ref>:<path>               (read prior content)\n"
            "  - git worktree add ../baseline <ref>  (isolated comparison)\n"
            "\n"
            "If you genuinely want to DISCARD your uncommitted changes:\n"
            "  1. git stash             (saves your uncommitted work)\n"
            "  2. (re-run the original command)\n"
            "  3. git stash drop        (if you really want to throw it away)\n"
            "\n"
            "Stashing first is always safer than a raw checkout — it gives "
            "you a recoverable checkpoint.",
            file=sys.stderr,
        )
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()

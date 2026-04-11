#!/usr/bin/env python3
"""PreToolUse hook for Bash — blocks hook-bypass flags on git commands.

Pre-commit hooks exist for a reason. If they fail, fix the underlying issue
instead of bypassing the safety net.

Inspired by block-no-verify from everything-claude-code.

Exit code 2 hard-blocks the tool call.
Exit code 0 allows it to proceed.

Tokenization note: uses shlex.split to tokenize the whole command before
scanning. This means the flag strings must appear as actual argv tokens —
they are ignored when embedded inside a quoted string argument. Example:
`git commit -m "note about hook-bypass"` passes through even though the
flag name appears inside the commit message, because shlex collapses the
quoted string into a single token. Same pattern as protect-checkout.py.
"""

import json
import os
import shlex
import sys

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "minimal")

BLOCKED_FLAGS = {
    "--no-verify",
    "--no-gpg-sign",
}


def tokens_contain_git_with_blocked_flag(tokens: list[str]) -> str | None:
    """Return the first blocked flag found as a real argv token in a git
    invocation, or None if the command is safe.

    Walks the token stream looking for `git` followed later by one of the
    blocked flags. Shell separators (`&&`, `||`, `;`, `|`) reset the git
    context so that a subsequent non-git command's arguments cannot be
    misattributed to a leading git command."""
    SEPARATORS = {"&&", "||", ";", "|", "&"}
    in_git = False
    for tok in tokens:
        if tok in SEPARATORS:
            in_git = False
            continue
        if tok == "git":
            in_git = True
            continue
        if in_git and tok in BLOCKED_FLAGS:
            return tok
    return None


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    # Tokenize via shlex.split so quoted strings (commit message bodies,
    # heredocs, `$(...)` substitutions) stay collapsed inside a single
    # token and cannot false-positive the flag scan. Shell separators like
    # `&&` and `||` become their own tokens and reset the git context.
    try:
        tokens = shlex.split(command)
    except ValueError:
        # Unparseable shell (e.g. unterminated quote) — let it through and
        # let the user see the real error from bash itself.
        sys.exit(0)

    flag = tokens_contain_git_with_blocked_flag(tokens)
    if flag is not None:
        print(
            f"BLOCKED: hook-bypass flag detected ({flag}).\n"
            f"Pre-commit hooks are a safety net — fix the underlying issue\n"
            f"instead of bypassing them. If this is genuinely needed,\n"
            f"run the command manually outside Claude Code.",
            file=sys.stderr,
        )
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()

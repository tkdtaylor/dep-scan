#!/usr/bin/env python3
"""PreToolUse hook for Bash — blocks --no-verify and similar hook-bypass flags.

Pre-commit hooks exist for a reason. If they fail, fix the underlying issue
instead of bypassing the safety net.

Inspired by block-no-verify from everything-claude-code.

Exit code 2 hard-blocks the tool call.
Exit code 0 allows it to proceed.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "minimal")

BLOCKED_FLAGS = [
    r"--no-verify",
    r"--no-gpg-sign",
]


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    # Only inspect git commands.
    if not re.search(r"\bgit\b", command):
        sys.exit(0)

    for pattern in BLOCKED_FLAGS:
        if re.search(pattern, command):
            print(
                f"BLOCKED: hook-bypass flag detected ({pattern.strip()}).\n"
                f"Pre-commit hooks are a safety net — fix the underlying issue\n"
                f"instead of bypassing them. If this is genuinely needed,\n"
                f"run the command manually outside Claude Code.",
                file=sys.stderr,
            )
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()

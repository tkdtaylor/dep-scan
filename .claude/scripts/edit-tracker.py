#!/usr/bin/env python3
"""PostToolUse hook for Edit|Write — tracks edited file paths for batch processing.

Appends file paths to a session-scoped state file that batch-format-typecheck.py
reads at Stop time. This enables running format+typecheck once per turn instead
of after every individual edit — a significant performance optimization.

Inspired by edit-accumulator from everything-claude-code.
"""

import json
import os
import sys

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "strict")

STATE_DIR = Path.home() / ".claude" / ".hook-state"


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    file_path = hook_input.get("tool_input", {}).get("file_path", "")
    if not file_path:
        sys.exit(0)

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project_name = Path(cwd).name

    state_dir = STATE_DIR / project_name
    state_dir.mkdir(parents=True, exist_ok=True)

    edits_file = state_dir / "edited-files"
    with open(edits_file, "a") as f:
        f.write(file_path + "\n")


if __name__ == "__main__":
    main()

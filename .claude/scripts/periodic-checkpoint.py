#!/usr/bin/env python3
"""Stop hook — periodic checkpoint reminder.

Counts how many times the agent has completed a response turn. After every
N turns (default 15), blocks the stop if there are uncommitted changes and
instructs the agent to checkpoint progress.

This prevents long sessions from silently losing work if something crashes
or the user closes the session before compaction triggers the pre-compact hook.

Inspired by awrshift/claude-memory-kit.
"""

import json
import os
import subprocess
import sys

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "standard")

STATE_DIR = Path.home() / ".claude" / ".hook-state"
DEFAULT_INTERVAL = 15


def main():
    try:
        json.loads(sys.stdin.read())
    except Exception:
        pass

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    if not project.is_dir():
        sys.exit(0)

    project_name = project.name
    state_dir = STATE_DIR / project_name
    state_dir.mkdir(parents=True, exist_ok=True)

    # Anti-loop: if we already asked for a checkpoint this turn, let the
    # agent stop so it doesn't get stuck in a block→stop→block cycle.
    loop_guard = state_dir / "checkpoint-active"
    if loop_guard.exists():
        loop_guard.unlink(missing_ok=True)
        sys.exit(0)

    # Increment the turn counter.
    count_file = state_dir / "stop-count"
    interval = int(os.environ.get("CLAUDE_CHECKPOINT_INTERVAL", str(DEFAULT_INTERVAL)))

    count = 0
    if count_file.exists():
        try:
            count = int(count_file.read_text().strip())
        except (ValueError, OSError):
            count = 0

    count += 1
    count_file.write_text(str(count))

    if count < interval:
        sys.exit(0)

    # Interval reached — check if there's actually unsaved work.
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=str(project),
        )
        has_changes = bool(result.stdout.strip())
    except Exception:
        has_changes = False

    if not has_changes:
        # Nothing to save — reset counter silently.
        count_file.write_text("0")
        sys.exit(0)

    # Reset counter and set the loop guard so the next stop passes through.
    count_file.write_text("0")
    loop_guard.write_text(str(time.time()))

    print(
        json.dumps(
            {
                "decision": "block",
                "reason": (
                    f"Periodic checkpoint ({count} turns since last save). "
                    "You have uncommitted changes — please save your progress:\n"
                    "1. Commit current changes with a descriptive message\n"
                    "2. Update the active task file with progress notes if needed\n"
                    "3. Run: touch .claude/.last-checkpoint\n"
                    "Then continue with your work."
                ),
            }
        )
    )


if __name__ == "__main__":
    main()

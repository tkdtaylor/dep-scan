#!/usr/bin/env python3
"""PreCompact hook — block compaction until the agent checkpoints progress.

When Claude's context window is about to be compacted, this hook checks
whether there is unsaved work (uncommitted changes). If so, it blocks
compaction and instructs the agent to commit first.

This complements post-compact.py (which re-injects context after compaction)
as a belt-and-suspenders approach: pre-compact saves working memory,
post-compact re-injects known state.

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

# How recently (seconds) a checkpoint must have occurred to skip blocking.
RECENT_THRESHOLD = 120


def main():
    try:
        json.loads(sys.stdin.read())
    except Exception:
        pass

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    if not project.is_dir():
        print(json.dumps({"decision": "allow"}))
        return

    # If the agent recently checkpointed, allow compaction immediately.
    checkpoint_marker = project / ".claude" / ".last-checkpoint"
    if checkpoint_marker.exists():
        age = time.time() - checkpoint_marker.stat().st_mtime
        if age < RECENT_THRESHOLD:
            print(json.dumps({"decision": "allow"}))
            return

    # Check for uncommitted changes as a proxy for unsaved work.
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
        # Can't determine git state — allow compaction rather than block.
        print(json.dumps({"decision": "allow"}))
        return

    if not has_changes:
        # Working tree is clean — safe to compact.
        print(json.dumps({"decision": "allow"}))
        return

    # Block compaction — instruct the agent to checkpoint first.
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": (
                    "Context compaction requested but you have uncommitted changes. "
                    "Before compaction, please:\n"
                    "1. Commit all current changes with a descriptive message\n"
                    "2. Update the active task file with your current progress\n"
                    "3. Run: touch .claude/.last-checkpoint\n"
                    "Then compaction will proceed automatically on the next attempt."
                ),
            }
        )
    )


if __name__ == "__main__":
    main()

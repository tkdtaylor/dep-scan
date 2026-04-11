#!/usr/bin/env python3
"""Stop hook — suggests compaction at logical task boundaries.

Tracks response turns and nudges the agent to /compact when the count
exceeds a threshold. Better to compact between tasks than mid-implementation
where context loss is most painful.

Advisory only — prints to stderr so the agent sees it but isn't blocked.

Inspired by strategic-compact from everything-claude-code.
"""

import json
import os
import sys

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "standard")

STATE_DIR = Path.home() / ".claude" / ".hook-state"
DEFAULT_THRESHOLD = 25  # ~25 turns ≈ 50-100+ tool calls


def main():
    try:
        json.loads(sys.stdin.read())
    except Exception:
        pass

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)
    project_name = project.name

    state_dir = STATE_DIR / project_name
    state_dir.mkdir(parents=True, exist_ok=True)

    count_file = state_dir / "compact-turn-count"
    threshold = int(
        os.environ.get("CLAUDE_COMPACT_THRESHOLD", str(DEFAULT_THRESHOLD))
    )

    count = 0
    if count_file.exists():
        try:
            count = int(count_file.read_text().strip())
        except (ValueError, OSError):
            count = 0

    count += 1
    count_file.write_text(str(count))

    if count < threshold:
        sys.exit(0)

    # Reset counter so we don't nag every turn.
    count_file.write_text("0")

    # Advisory — stderr is visible to the agent but doesn't block.
    print(
        f"Context tip: {count} turns since last compaction. "
        f"If you're between tasks, consider running /compact to free up "
        f"context window. Compacting mid-task risks losing implementation context.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""PostCompact hook — re-inject current task context after context compaction.

When Claude's context window is compacted, it loses track of what task it was
working on. This hook finds the active task and spec, and re-injects them so
Claude can pick up where it left off.

Adapted from dixus/claudeframework.
"""

import json
import os
import sys

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "standard")


def main():
    # Read stdin (may be empty for PostCompact)
    try:
        json.loads(sys.stdin.read())
    except Exception:
        pass

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    if not project.is_dir():
        sys.exit(0)

    parts = []

    # Git branch
    git_head = project / ".git" / "HEAD"
    if git_head.exists():
        try:
            ref = git_head.read_text().strip()
            if ref.startswith("ref: refs/heads/"):
                parts.append(f"Branch: {ref[16:]}")
        except Exception:
            pass

    # Find active task
    active_dir = project / "docs" / "tasks" / "active"
    task_file = None
    if active_dir.is_dir():
        tasks = sorted(active_dir.glob("*.md"))
        if tasks:
            task_file = tasks[-1]  # most recent by name (highest NNN)
            try:
                preview = "\n".join(
                    task_file.read_text(encoding="utf-8").splitlines()[:20]
                )
                parts.append(f"Active task ({task_file.name}):\n{preview}")
            except Exception:
                parts.append(f"Active task: {task_file.name}")

    # Find corresponding test spec (tech projects)
    if task_file:
        spec_name = task_file.stem + "-test-spec.md"
        spec_file = project / "docs" / "tasks" / "test-specs" / spec_name
        if spec_file.exists():
            try:
                preview = "\n".join(
                    spec_file.read_text(encoding="utf-8").splitlines()[:15]
                )
                parts.append(f"Test spec ({spec_name}):\n{preview}")
            except Exception:
                parts.append(f"Test spec: {spec_name}")

    # Research project context
    research_log = project / "docs" / "research-log.md"
    if research_log.exists():
        try:
            lines = research_log.read_text(encoding="utf-8").splitlines()
            # Show last 10 non-empty lines (most recent activity)
            recent = [l for l in lines if l.strip()][-10:]
            if recent:
                parts.append("Recent research log:\n" + "\n".join(recent))
        except Exception:
            pass

    outline = project / "docs" / "outline.md"
    if outline.exists():
        try:
            preview = "\n".join(
                outline.read_text(encoding="utf-8").splitlines()[:15]
            )
            parts.append(f"Outline:\n{preview}")
        except Exception:
            pass

    # Check for plan skeleton
    plans_dir = Path.home() / ".claude" / "plans"
    if plans_dir.is_dir():
        plan_files = sorted(
            plans_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True
        )
        if plan_files:
            try:
                content = plan_files[0].read_text(encoding="utf-8")
                if "## Tasks" in content:
                    # Find unchecked tasks
                    unchecked = [
                        line.strip()
                        for line in content.splitlines()
                        if line.strip().startswith("- [ ]")
                        or line.strip().startswith("1. [ ]")
                        or "[ ]" in line
                    ][:5]
                    if unchecked:
                        parts.append(
                            "Next tasks from plan:\n" + "\n".join(unchecked)
                        )
            except Exception:
                pass

    if not parts:
        sys.exit(0)

    context = "[Post-compact context recovery]\n" + "\n\n".join(parts)

    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostCompact",
                    "additionalContext": context,
                }
            }
        )
    )


if __name__ == "__main__":
    main()

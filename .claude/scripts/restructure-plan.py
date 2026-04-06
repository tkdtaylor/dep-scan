#!/usr/bin/env python3
"""PostToolUse hook for ExitPlanMode — plan-to-tasks restructuring.

Adapted from plan-plus (github.com/RandyHaylor/plan-plus) for create-project
task-based workflow. When Claude exits plan mode, this script:

1. Splits plan steps into task files in docs/tasks/backlog/
2. Creates test spec stubs for tech projects
3. Updates the coverage tracker
4. Backs up the full plan to docs/plans/
5. Replaces the plan with a lightweight skeleton

Only activates in create-project structured projects (detected via docs/tasks/).
"""

import json
import os
import re
import sys
from pathlib import Path


def read_stdin():
    try:
        return json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        return {}


def find_plan_file(hook_input):
    """Locate the plan file from hook input, with fallback to most recent."""
    for accessor in [
        lambda d: d.get("tool_input", {}).get("planFilePath"),
        lambda d: d.get("tool_response", {}).get("filePath"),
        lambda d: d.get("tool_response", {}).get("data", {}).get("filePath"),
    ]:
        try:
            path = accessor(hook_input)
            if path and os.path.isfile(path):
                return path
        except (TypeError, AttributeError):
            continue
    # Fallback: most recently modified plan file
    plans_dir = Path.home() / ".claude" / "plans"
    if plans_dir.is_dir():
        files = sorted(
            plans_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True
        )
        if files:
            return str(files[0])
    return None


def slugify(text, max_len=50):
    text = re.sub(r"[^\w\s-]", "", text.lower()).strip()
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-")
    return text[:max_len] if text else "unnamed"


def clean_header(header):
    """Strip common plan step prefixes like 'Step 1:', 'Phase 2 —', etc."""
    cleaned = re.sub(
        r"^(step|phase|part)\s*\d+\s*[:.—\-]\s*", "", header, flags=re.IGNORECASE
    ).strip()
    return cleaned or header


CONTEXT_KEYWORDS = {
    "context",
    "background",
    "overview",
    "summary",
    "introduction",
    "about",
}


def split_plan(content):
    """Split on ## headers -> (preamble, context_sections, step_sections)."""
    lines = content.splitlines(keepends=True)
    preamble, ctx, steps = [], [], []
    cur_header, cur_lines = None, []

    for line in lines:
        if re.match(r"^## ", line):
            if cur_header is not None:
                bucket = (
                    ctx
                    if cur_header.lower().strip() in CONTEXT_KEYWORDS
                    else steps
                )
                bucket.append((cur_header, "".join(cur_lines).strip()))
            cur_header = line.strip().lstrip("#").strip()
            cur_lines = []
        elif cur_header is None:
            preamble.append(line)
        else:
            cur_lines.append(line)

    if cur_header is not None:
        bucket = (
            ctx if cur_header.lower().strip() in CONTEXT_KEYWORDS else steps
        )
        bucket.append((cur_header, "".join(cur_lines).strip()))

    return "".join(preamble).strip(), ctx, steps


def next_task_id(cwd):
    """Find the next available task ID across all task directories."""
    max_id = 0
    for sub in ("active", "backlog", "completed"):
        d = Path(cwd) / "docs" / "tasks" / sub
        if d.is_dir():
            for f in d.iterdir():
                m = re.match(r"^(\d+)-", f.name)
                if m:
                    max_id = max(max_id, int(m.group(1)))
    return max_id + 1


def summarize(content, max_parts=2):
    """Extract a brief summary from section content."""
    parts = []
    for line in content.splitlines():
        s = line.strip()
        if not s or s.startswith("```") or s.startswith("---"):
            continue
        if (
            re.match(r"^[-*]\s", s)
            or re.match(r"^\d+[.)]\s", s)
            or (len(s) < 120 and not s.startswith("#"))
        ):
            clean = re.sub(r"^[-*#\d.)\s]+", "", s).strip()
            if clean and len(clean) > 5:
                parts.append(clean)
                if len(parts) >= max_parts:
                    break
    return "; ".join(parts) if parts else ""


def main():
    hook_input = read_stdin()
    cwd = (
        hook_input.get("cwd")
        or os.environ.get("CLAUDE_PROJECT_DIR")
        or os.getcwd()
    )

    if not cwd or not Path(cwd).is_dir():
        sys.exit(0)

    tasks_dir = Path(cwd) / "docs" / "tasks"
    if not tasks_dir.is_dir():
        sys.exit(0)

    plan_file = find_plan_file(hook_input)
    if not plan_file:
        sys.exit(0)

    plan_path = Path(plan_file)
    try:
        content = plan_path.read_text(encoding="utf-8")
    except Exception:
        sys.exit(0)

    # Already restructured — skip
    if "task-executor" in content and "## Tasks" in content:
        sys.exit(0)

    preamble, context_sections, step_sections = split_plan(content)
    if not step_sections:
        sys.exit(0)

    is_tech = (tasks_dir / "test-specs").is_dir()
    start_id = next_task_id(cwd)
    backlog_dir = tasks_dir / "backlog"
    backlog_dir.mkdir(parents=True, exist_ok=True)

    task_entries = []
    tracker_rows = []

    for i, (raw_header, body) in enumerate(step_sections):
        header = clean_header(raw_header)
        tid = start_id + i
        num = f"{tid:03d}"
        slug = slugify(header)
        task_file = f"{num}-{slug}.md"
        spec_file = f"{num}-{slug}-test-spec.md"

        # Write task file
        (backlog_dir / task_file).write_text(
            f"# Task {num} — {header}\n\n{body}\n", encoding="utf-8"
        )

        # Write test spec stub (tech projects only)
        if is_tech:
            spec_path = tasks_dir / "test-specs" / spec_file
            if not spec_path.exists():
                spec_path.write_text(
                    f"# Test Spec: {num} — {header}\n\n"
                    f"## Acceptance criteria\n\n"
                    f"<!-- Complete before starting implementation -->\n\n"
                    f"## Test cases\n\n"
                    f"<!-- Define test cases with inputs and expected outputs -->\n",
                    encoding="utf-8",
                )
            tracker_rows.append(
                f"| {num} | {header} | {spec_file} | \u23f3 | \U0001f4cb Backlog |"
            )

        # Build skeleton entry
        brief = summarize(body)
        desc = f"{header}: {brief}" if brief else header
        entry = f"{i + 1}. [ ] **{num}** \u2014 {desc}"
        entry += f"\n   task-executor \u2014 task: docs/tasks/backlog/{task_file}"
        if is_tech:
            entry += f", spec: docs/tasks/test-specs/{spec_file}"
        task_entries.append(entry)

    # Update coverage tracker
    if is_tech and tracker_rows:
        tracker = tasks_dir / "test-specs" / "coverage-tracker.md"
        if tracker.exists():
            try:
                text = tracker.read_text(encoding="utf-8").rstrip("\n")
                tracker.write_text(
                    text + "\n" + "\n".join(tracker_rows) + "\n", encoding="utf-8"
                )
            except Exception:
                pass

    # Back up full plan
    plans_dir = Path(cwd) / "docs" / "plans"
    plans_dir.mkdir(parents=True, exist_ok=True)
    plan_name = plan_path.stem
    (plans_dir / f"plan-full-{plan_name}.md").write_text(content, encoding="utf-8")

    # Save context/preamble
    if preamble or context_sections:
        parts = [preamble] if preamble else []
        parts += [f"## {h}\n\n{b}" for h, b in context_sections]
        (plans_dir / f"plan-context-{plan_name}.md").write_text(
            "# Plan Context\n\n" + "\n\n".join(parts) + "\n", encoding="utf-8"
        )

    # Write skeleton
    skeleton = (
        f"# Plan: {plan_name}\n\n"
        f"## Instructions\n"
        f"- Use the **task-executor** agent for each task \u2014 pass the task and spec paths\n"
        f"- One agent call per task \u2014 do not combine\n"
        f"- Agent context is ephemeral \u2014 keeps this conversation lean\n"
        f"- Complete test specs before implementation\n"
        f"- Commit and push after every completed task\n"
        f"- Mark tasks done here as you complete them\n\n"
        f"Full plan: docs/plans/plan-full-{plan_name}.md\n\n"
        f"## Tasks\n" + "\n".join(task_entries) + "\n"
    )
    plan_path.write_text(skeleton, encoding="utf-8")

    # Hook output
    n = len(step_sections)
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": (
                        f"Plan restructured into {n} task files in docs/tasks/backlog/. "
                        + (
                            "Test spec stubs in docs/tasks/test-specs/. "
                            if is_tech
                            else ""
                        )
                        + f"Full plan backed up to docs/plans/plan-full-{plan_name}.md. "
                        f"Work through tasks using the task-executor agent \u2014 "
                        f"one task per call. Start with the first unchecked task."
                    ),
                }
            }
        )
    )


if __name__ == "__main__":
    main()

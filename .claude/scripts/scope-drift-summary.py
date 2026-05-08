#!/usr/bin/env python3
"""Stop hook — print a one-screen summary of how the current diff lines up
against the active task's spec.

This is advisory: it prints to stderr (visible to the agent on the next turn,
not blocking). The goal is to surface scope drift before the agent commits —
"you said the task was about X, but the diff also touches Y" or "spec lists
3 TCs but only 2 appear in test files."

Cheap mechanical version of the spec-verifier agent — runs on every Stop,
costs no tokens, catches obvious mismatches. The agent is responsible for
acting on the summary; this hook only surfaces it.

Skips silently when:
  - There is no active task / spec
  - There are no uncommitted changes
  - The diff is trivially small (< 5 lines added)
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "standard")

TC_MARKER_RE = re.compile(r"\bTC-\d+(?:-[A-Za-z0-9]+)?\b")


def run(cmd: list[str], project: Path) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5, cwd=str(project),
        )
        return result.stdout
    except Exception:
        return ""


def main():
    try:
        json.loads(sys.stdin.read())
    except Exception:
        pass

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    if not (project / ".git").exists():
        sys.exit(0)

    # Skip if no uncommitted changes — nothing to summarize.
    porcelain = run(["git", "status", "--porcelain"], project)
    if not porcelain.strip():
        sys.exit(0)

    # Find active task + spec.
    active_dir = project / "docs" / "tasks" / "active"
    spec_dir = project / "docs" / "tasks" / "test-specs"

    if not active_dir.is_dir():
        sys.exit(0)

    tasks = sorted(active_dir.glob("*.md"))
    if not tasks:
        sys.exit(0)

    task_file = tasks[-1]
    spec_file = spec_dir / f"{task_file.stem}-test-spec.md"
    if not spec_file.exists():
        sys.exit(0)

    try:
        spec_text = spec_file.read_text(encoding="utf-8")
    except OSError:
        sys.exit(0)

    tc_markers = sorted(set(TC_MARKER_RE.findall(spec_text)))

    # Diff stats.
    numstat = run(["git", "diff", "HEAD", "--numstat"], project)
    files_changed: list[tuple[str, int, int]] = []  # (path, added, removed)
    total_added = 0
    for line in numstat.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        added_s, removed_s, path = parts
        try:
            added, removed = int(added_s), int(removed_s)
        except ValueError:
            continue
        files_changed.append((path, added, removed))
        total_added += added

    if total_added < 5:
        # Trivial change — don't nag.
        sys.exit(0)

    # Find which TC markers appear in the diff (test added) vs. the existing tests.
    diff_text = run(["git", "diff", "HEAD"], project)
    tc_in_diff = {tc for tc in tc_markers if tc in diff_text}

    # Also check existing test files for TCs not in this diff (already-tested).
    test_files: list[Path] = []
    for pattern in ("tests/**/*", "src/**/*test*", "src/**/*_test.*", "**/__tests__/**/*"):
        test_files.extend(
            p for p in project.glob(pattern)
            if p.is_file() and p.suffix in {".py", ".rs", ".ts", ".tsx", ".js", ".jsx", ".go", ".rb", ".java", ".kt"}
        )

    test_blob = ""
    for tf in test_files:
        try:
            test_blob += tf.read_text(encoding="utf-8", errors="ignore") + "\n"
        except OSError:
            continue

    tc_existing = {tc for tc in tc_markers if tc in test_blob}
    tc_covered = tc_in_diff | tc_existing
    tc_missing = [tc for tc in tc_markers if tc not in tc_covered]

    # Classify changed files: src vs test vs docs.
    src_files = [f for f, _, _ in files_changed if f.startswith("src/") and "test" not in f.lower()]
    test_files_in_diff = [f for f, _, _ in files_changed if "test" in f.lower() or "/tests/" in f]
    doc_files = [f for f, _, _ in files_changed if f.startswith("docs/")]
    other_files = [
        f for f, _, _ in files_changed
        if f not in src_files and f not in test_files_in_diff and f not in doc_files
    ]

    # Build the summary. Stay under ~10 lines.
    lines = [
        f"[scope-drift-summary] active task: {task_file.stem}",
    ]

    if tc_markers:
        coverage = f"{len(tc_covered)}/{len(tc_markers)} test cases referenced"
        if tc_missing:
            lines.append(
                f"  spec coverage: {coverage} — missing: {', '.join(tc_missing)}"
            )
        else:
            lines.append(f"  spec coverage: {coverage} ✓")

    diff_summary_parts = []
    if src_files:
        diff_summary_parts.append(f"src({len(src_files)})")
    if test_files_in_diff:
        diff_summary_parts.append(f"test({len(test_files_in_diff)})")
    if doc_files:
        diff_summary_parts.append(f"docs({len(doc_files)})")
    if other_files:
        diff_summary_parts.append(f"other({len(other_files)}: {', '.join(other_files[:3])})")

    if diff_summary_parts:
        lines.append(f"  diff scope: +{total_added} lines across " + ", ".join(diff_summary_parts))

    if other_files:
        lines.append(
            f"  ⚠ files outside src/tests/docs — confirm they belong to this task"
        )

    if tc_missing:
        lines.append(
            f"  ⚠ before commit: ensure each missing TC has a test that asserts it"
        )

    if len(lines) == 1:
        # No interesting signals. Stay quiet.
        sys.exit(0)

    print("\n".join(lines), file=sys.stderr)


if __name__ == "__main__":
    main()

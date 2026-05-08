#!/usr/bin/env python3
"""PreToolUse hook for Bash — block `git commit` when the active task's
test spec has TC-NNN-XX assertions that don't appear in any test file.

This is the cheap, mechanical version of spec-adherence checking. It catches
the "smoke test where spec asks for assertion" failure mode (see
CLAUDE.md → Failure modes) by ensuring every spec marker has at least one
test file referencing it. It does NOT verify the test actually asserts the
behavior — that's the spec-verifier agent's job. This hook is the fast
pre-commit gate.

Bypass for genuinely WIP commits — either set in the parent shell, or as a
shell prefix on the command itself (the prefix form is detected before
shell evaluation since pre-bash hooks fire before the shell parses the line):
    CLAUDE_SKIP_SPEC_COVERAGE=1 git commit ...
    export CLAUDE_SKIP_SPEC_COVERAGE=1; git commit ...
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

# TC marker patterns we recognize in test specs.
# Examples: TC-001, TC-369-01, TC-369-A1
TC_MARKER_RE = re.compile(r"\bTC-\d+(?:-[A-Za-z0-9]+)?\b")

# Task file naming: NNN-slug.md (zero-padded sequential ID)
TASK_NAME_RE = re.compile(r"^(\d{3,})-")


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    if os.environ.get("CLAUDE_SKIP_SPEC_COVERAGE"):
        sys.exit(0)

    cmd = hook_input.get("tool_input", {}).get("command", "")
    if not cmd:
        sys.exit(0)

    # Also honour the bypass when the env-var assignment appears as a shell
    # prefix in the command string itself (e.g. `CLAUDE_SKIP_SPEC_COVERAGE=1
    # git commit …`). Claude Code pre-bash hooks run BEFORE the shell
    # interprets the command, so the env var is not yet in os.environ at
    # hook time. Checking the command string makes the documented bypass
    # actually work.
    if "CLAUDE_SKIP_SPEC_COVERAGE=1" in cmd:
        sys.exit(0)

    # Only act on `git commit` (not amend-only, not status, not log).
    # Match `git commit` at a word boundary, and exclude `git commit --amend`
    # only if the user passes `--amend` without other staged changes — we
    # still want to gate amend commits with new content, so check unconditionally.
    if not re.search(r"\bgit\s+commit\b", cmd):
        sys.exit(0)

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    if not (project / ".git").exists():
        sys.exit(0)

    # Find the active task. Prefer the highest-numbered file in active/.
    active_dir = project / "docs" / "tasks" / "active"
    spec_dir = project / "docs" / "tasks" / "test-specs"

    if not active_dir.is_dir() or not spec_dir.is_dir():
        sys.exit(0)

    active_tasks = sorted(active_dir.glob("*.md"))
    if not active_tasks:
        # No active task — let the commit proceed. The spec-verifier agent
        # is responsible for catching this case if invoked.
        sys.exit(0)

    task_file = active_tasks[-1]
    m = TASK_NAME_RE.match(task_file.name)
    if not m:
        sys.exit(0)
    task_id = m.group(1)

    # Find the matching spec file. Convention: <task-stem>-test-spec.md
    spec_file = spec_dir / f"{task_file.stem}-test-spec.md"
    if not spec_file.exists():
        # Fall back to glob by ID prefix.
        candidates = list(spec_dir.glob(f"{task_id}-*-test-spec.md"))
        if not candidates:
            # Spec missing entirely — block. CLAUDE.md says no impl without spec.
            print(
                f"BLOCKED: task {task_id} has no test spec at "
                f"{spec_file.relative_to(project)} (or matching glob).\n"
                f"Per CLAUDE.md, every task must have a paired test spec.\n"
                f"Bypass with CLAUDE_SKIP_SPEC_COVERAGE=1 if this is a "
                f"docs/refactor commit unrelated to the active task.",
                file=sys.stderr,
            )
            sys.exit(2)
        spec_file = candidates[0]

    # Parse TC markers from the spec.
    try:
        spec_text = spec_file.read_text(encoding="utf-8")
    except OSError:
        sys.exit(0)

    tc_markers = sorted(set(TC_MARKER_RE.findall(spec_text)))
    if not tc_markers:
        # Spec has no TC markers — nothing to check. Allow.
        sys.exit(0)

    # Search test files for each marker. We look in conventional test dirs
    # plus any test file mentioned in `git diff --cached`.
    test_globs = [
        "tests/**/*",
        "src/**/*test*",
        "src/**/*_test.*",
        "src/**/*.test.*",
        "**/__tests__/**/*",
    ]
    test_files: set[Path] = set()
    for pattern in test_globs:
        test_files.update(
            p for p in project.glob(pattern)
            if p.is_file() and p.suffix in {".py", ".rs", ".ts", ".tsx", ".js", ".jsx", ".go", ".rb", ".java", ".kt"}
        )

    # Also include any staged file that looks like a test.
    try:
        staged = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True, timeout=5, cwd=str(project),
        )
        for line in staged.stdout.splitlines():
            p = project / line.strip()
            if p.is_file() and ("test" in p.name.lower() or "/tests/" in str(p)):
                test_files.add(p)
    except Exception:
        pass

    if not test_files:
        # No test files visible — likely a non-code commit. Allow.
        sys.exit(0)

    # Concatenate test text once for cheap substring search.
    test_blob = ""
    for tf in test_files:
        try:
            test_blob += tf.read_text(encoding="utf-8", errors="ignore") + "\n"
        except OSError:
            continue

    missing = [tc for tc in tc_markers if tc not in test_blob]

    if not missing:
        sys.exit(0)

    print(
        f"BLOCKED: spec coverage check failed for task {task_id}.\n"
        f"Spec: {spec_file.relative_to(project)}\n"
        f"Test cases declared in spec: {', '.join(tc_markers)}\n"
        f"No test file references these markers: {', '.join(missing)}\n"
        f"\n"
        f"Add a test that references the marker (e.g. as a comment, test name, "
        f"or doc-string) so this gate can verify it exists. The spec-verifier "
        f"agent then checks whether the test actually asserts the behavior.\n"
        f"\n"
        f"Bypass: CLAUDE_SKIP_SPEC_COVERAGE=1 git commit ...  (use sparingly).",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    main()

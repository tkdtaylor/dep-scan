#!/usr/bin/env python3
"""Stop hook — batch format and typecheck all files edited this turn.

Reads the edit list accumulated by edit-tracker.py, deduplicates, and runs
available formatters and type checkers once. Much more efficient than running
lint after every individual Edit.

Auto-detects installed tools: biome, prettier, eslint, ruff, black, gofmt,
rustfmt for formatting; tsc, mypy for type checking.

Inspired by format-typecheck from everything-claude-code.
"""

import json
import os
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "strict")

STATE_DIR = Path.home() / ".claude" / ".hook-state"


def run_cmd(cmd, cwd, timeout=30):
    """Run a command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return False, "timed out"
    except FileNotFoundError:
        return True, ""  # Tool not installed — skip silently.


def main():
    try:
        json.loads(sys.stdin.read())
    except Exception:
        pass

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project_name = Path(cwd).name

    edits_file = STATE_DIR / project_name / "edited-files"
    if not edits_file.exists():
        sys.exit(0)

    # Read, deduplicate, and clear the accumulated list.
    files = list(
        dict.fromkeys(
            line.strip()
            for line in edits_file.read_text().splitlines()
            if line.strip()
        )
    )
    edits_file.unlink(missing_ok=True)

    # Filter to files that still exist.
    files = [f for f in files if Path(f).exists()]
    if not files:
        sys.exit(0)

    issues = []

    # --- Formatters (detect and run the first available) ---

    js_exts = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
    py_exts = (".py",)
    go_exts = (".go",)
    rs_exts = (".rs",)

    js_files = [f for f in files if f.endswith(js_exts)]
    py_files = [f for f in files if f.endswith(py_exts)]
    go_files = [f for f in files if f.endswith(go_exts)]
    rs_files = [f for f in files if f.endswith(rs_exts)]

    # JavaScript / TypeScript
    if js_files:
        if shutil.which("biome"):
            ok, out = run_cmd(["biome", "check", "--write"] + js_files, cwd)
            if not ok and out:
                issues.append(f"Biome:\n{out[:500]}")
        elif shutil.which("prettier"):
            run_cmd(["prettier", "--write"] + js_files, cwd)

    # Python
    if py_files:
        if shutil.which("ruff"):
            ok, out = run_cmd(["ruff", "check", "--fix"] + py_files, cwd)
            if not ok and out:
                issues.append(f"Ruff lint:\n{out[:500]}")
            run_cmd(["ruff", "format"] + py_files, cwd)
        elif shutil.which("black"):
            run_cmd(["black", "--quiet"] + py_files, cwd)

    # Go
    if go_files and shutil.which("gofmt"):
        for f in go_files:
            run_cmd(["gofmt", "-w", f], cwd)

    # Rust
    if rs_files and shutil.which("rustfmt"):
        run_cmd(["rustfmt"] + rs_files, cwd)

    # --- Type checkers ---

    if js_files and shutil.which("tsc"):
        ts_files = [f for f in js_files if f.endswith((".ts", ".tsx"))]
        if ts_files:
            ok, out = run_cmd(["tsc", "--noEmit"], cwd, timeout=60)
            if not ok and out:
                issues.append(f"TypeScript:\n{out[:500]}")

    if py_files and shutil.which("mypy"):
        ok, out = run_cmd(["mypy"] + py_files, cwd, timeout=60)
        if not ok and out:
            issues.append(f"Mypy:\n{out[:500]}")

    if issues:
        print("\n---\n".join(issues), file=sys.stderr)


if __name__ == "__main__":
    main()

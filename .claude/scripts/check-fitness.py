#!/usr/bin/env python3
"""Stop hook — run architectural fitness functions and report failures.

Fitness functions are executable checks that verify architectural invariants:
no module cycles, layering rules, performance budgets, security thresholds,
coupling limits. They are declared in `docs/spec/fitness-functions.md` and
implemented behind a single entry point so they can be run uniformly:

  - Preferred: `make fitness`
  - Fallback: `./scripts/fitness.sh`

This hook runs that entry point at Stop and prints failures to stderr.
It does not block — fitness violations may be intentional during a refactor,
and stopping the agent mid-flow is more disruptive than the surfaced warning.

Exits silently when:
  - Profile is not strict
  - Neither `make fitness` nor `scripts/fitness.sh` is available
  - The runner reports success (returncode 0)

Output format mirrors batch-format-typecheck.py — the failing runner's
stdout/stderr is truncated to the first ~800 chars and prefixed so the agent
can see it on the next turn.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "strict")


def has_make_target(cwd: Path, target: str) -> bool:
    """Return True if a Makefile exists and declares the given target."""
    makefile = cwd / "Makefile"
    if not makefile.exists() or not shutil.which("make"):
        return False
    try:
        text = makefile.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    # Match target at start of a line, followed by ':' (allow whitespace).
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(f"{target}:") or stripped.startswith(f"{target} :"):
            return True
    return False


def run_cmd(cmd, cwd, timeout=120):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=str(cwd),
        )
        return result.returncode, (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "fitness check timed out"
    except FileNotFoundError:
        return None, ""


def main():
    try:
        json.loads(sys.stdin.read())
    except Exception:
        pass

    cwd = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())

    # Pick the runner. Prefer Makefile target so fitness rules and other
    # quality targets share one entry point.
    if has_make_target(cwd, "fitness"):
        cmd = ["make", "fitness"]
    elif (cwd / "scripts" / "fitness.sh").exists() and os.access(
        cwd / "scripts" / "fitness.sh", os.X_OK
    ):
        cmd = ["./scripts/fitness.sh"]
    else:
        sys.exit(0)

    rc, out = run_cmd(cmd, cwd)
    if rc is None or rc == 0:
        sys.exit(0)

    label = " ".join(cmd)
    truncated = out[:800] + ("…" if len(out) > 800 else "")
    print(
        f"[check-fitness] `{label}` failed (exit {rc}) — architectural "
        f"invariants violated. Review and fix or update spec/fitness-functions.md "
        f"if the rule is no longer correct.\n{truncated}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()

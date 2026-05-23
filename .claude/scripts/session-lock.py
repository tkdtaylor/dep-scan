#!/usr/bin/env python3
"""SessionStart hook — record a session lock and clean stale ones.

Each Claude Code session that opens this project writes a lock file under
`.claude/sessions/<session_id>.lock`. Before writing our own lock we sweep
out any lock that hasn't been touched in the staleness window (default 4
hours) — those represent sessions that crashed, were killed, or were left
idle long enough that "concurrent" is no longer meaningful.

The lock count is what the task-executor reads in its Step 0 to decide
between branch-per-task (solo) and worktree-per-task (concurrent). One
active lock = us = solo. Two or more = concurrent, escalate to worktree.

The lock file is intentionally NOT removed at SessionEnd because Claude
Code's hook events don't fire reliably on all session-end paths (kill,
crash, terminal close). Aging out via mtime is the robust default.

Stop hook touches the lock to extend its TTL — see `session-lock-touch.py`
(installed alongside this script).

Locks live under `.claude/sessions/`, which is added to `.gitignore` by
the scaffold so they never commit to the repo.
"""

import json
import os
import sys
import time
import uuid
from pathlib import Path

sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "minimal")

# How long a lock can sit untouched before we consider its session gone.
STALENESS_SECONDS = 4 * 60 * 60  # 4 hours


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        hook_input = {}

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    if not project.is_dir():
        sys.exit(0)

    sessions_dir = project / ".claude" / "sessions"
    try:
        sessions_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        sys.exit(0)

    # Sweep stale locks (mtime older than the staleness window).
    now = time.time()
    for lock in sessions_dir.glob("*.lock"):
        try:
            mtime = lock.stat().st_mtime
        except OSError:
            continue
        if now - mtime > STALENESS_SECONDS:
            try:
                lock.unlink()
            except OSError:
                pass

    # Record our lock keyed by session id (falls back to a uuid if Claude
    # Code did not provide one in the hook payload).
    session_id = hook_input.get("session_id") or f"unknown-{uuid.uuid4().hex[:12]}"
    our_lock = sessions_dir / f"{session_id}.lock"
    try:
        our_lock.write_text(
            json.dumps(
                {
                    "session_id": session_id,
                    "cwd": str(project),
                    "started_at": int(now),
                    "pid": os.getppid(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except OSError:
        sys.exit(0)

    # Recount after our write — this is the value the task-executor reads.
    active = [p for p in sessions_dir.glob("*.lock") if p.is_file()]
    try:
        (sessions_dir / ".lock-count").write_text(f"{len(active)}\n", encoding="utf-8")
    except OSError:
        pass

    if len(active) > 1:
        others = len(active) - 1
        print(
            f"[session-lock] {others} other Claude Code session(s) active on this "
            f"project. task-executor will isolate new tasks in worktrees.",
            file=sys.stderr,
        )

    sys.exit(0)


if __name__ == "__main__":
    main()

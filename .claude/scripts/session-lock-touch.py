#!/usr/bin/env python3
"""Stop hook — refresh this session's lock file mtime.

The session lock (`.claude/sessions/<session_id>.lock`) is written at
SessionStart and ages out via mtime after the staleness window. To keep
the lock live for the whole life of an active session, we touch it on
every Stop event (i.e. each time the assistant finishes a turn).

This avoids needing a SessionEnd hook (which doesn't fire reliably on
all termination paths) — the lock stays "fresh" while the session is
working, and naturally goes stale once turns stop landing.
"""

import json
import os
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "minimal")


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        hook_input = {}

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = Path(cwd)

    session_id = hook_input.get("session_id")
    if not session_id:
        # No session_id → we don't know which lock to touch; skip silently.
        sys.exit(0)

    lock = project / ".claude" / "sessions" / f"{session_id}.lock"
    if not lock.exists():
        # Either SessionStart hook didn't fire or the lock was swept.
        # Re-create it so this session is represented.
        try:
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.write_text(
                json.dumps(
                    {
                        "session_id": session_id,
                        "cwd": str(project),
                        "started_at": int(time.time()),
                        "pid": os.getppid(),
                        "note": "recreated by Stop hook",
                    }
                ),
                encoding="utf-8",
            )
        except OSError:
            pass
        sys.exit(0)

    # Touch (update mtime to now).
    try:
        os.utime(lock, None)
    except OSError:
        pass

    sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Stop hook — sends desktop notification when Claude finishes responding.

Useful during long task-executor runs or when the user has switched windows.
Supports Linux (notify-send), macOS (osascript), and WSL (powershell.exe).

Inspired by desktop-notify from everything-claude-code.
"""

import json
import os
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "strict")


def notify(title: str, message: str):
    """Send a desktop notification on the current platform."""
    try:
        if shutil.which("notify-send"):
            subprocess.run(
                ["notify-send", "--app-name=Claude Code", title, message],
                timeout=5,
            )
        elif shutil.which("osascript"):
            osa_msg = message.replace('"', '\\"')
            osa_title = title.replace('"', '\\"')
            subprocess.run(
                [
                    "osascript",
                    "-e",
                    f'display notification "{osa_msg}" with title "{osa_title}"',
                ],
                timeout=5,
            )
        elif shutil.which("powershell.exe"):
            # WSL → Windows toast notification
            ps = (
                "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')"
                " | Out-Null; "
                "$n = New-Object System.Windows.Forms.NotifyIcon; "
                "$n.Icon = [System.Drawing.SystemIcons]::Information; "
                "$n.Visible = $true; "
                f"$n.ShowBalloonTip(5000, '{title}', '{message}', 'Info'); "
                "Start-Sleep -Seconds 6; $n.Dispose()"
            )
            subprocess.run(["powershell.exe", "-Command", ps], timeout=15)
    except Exception:
        pass  # Notification is best-effort — never block on failure.


def main():
    try:
        json.loads(sys.stdin.read())
    except Exception:
        pass

    notify("Claude Code", "Response complete — check your terminal.")


if __name__ == "__main__":
    main()

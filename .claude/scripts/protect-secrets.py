#!/usr/bin/env python3
"""PreToolUse hook for Write|Edit — blocks writes to sensitive files.

Exit code 2 hard-blocks the tool call (stderr is shown to Claude).
Exit code 0 allows it to proceed.

Adapted from dixus/claudeframework.
"""

import json
import re
import sys

# Files that should never be written by an AI agent inside a project.
# .env is intentionally NOT blocked — it's gitignored and needs to be
# writable during project setup. The risk of committing .env is handled
# by .gitignore, not this hook.
BLOCKED_PATTERNS = [
    r"\.(pem|key|p12|pfx|jks|keystore)$",  # private keys / certs
    r"(^|/)id_(rsa|ed25519|ecdsa|dsa)$",  # SSH private keys
    r"(^|/)service[_-]?account.*\.json$",  # GCP service accounts
    r"(^|/)\.netrc$",  # network auth
    r"(^|/)\.npmrc$",  # npm auth tokens
    r"(^|/)\.pypirc$",  # PyPI auth tokens
    r"(^|/)\.docker/config\.json$",  # Docker registry auth
]

BLOCKED_RE = [re.compile(p) for p in BLOCKED_PATTERNS]


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    file_path = hook_input.get("tool_input", {}).get("file_path", "")
    if not file_path:
        sys.exit(0)

    for pattern in BLOCKED_RE:
        if pattern.search(file_path):
            print(
                f"BLOCKED: write to sensitive file refused: {file_path}\n"
                f"This file may contain secrets or auth tokens.\n"
                f"If intentional, write it manually outside Claude Code.",
                file=sys.stderr,
            )
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()

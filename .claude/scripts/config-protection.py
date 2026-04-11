#!/usr/bin/env python3
"""PreToolUse hook for Write|Edit — blocks modifications to linter/formatter configs.

The agent should fix code to satisfy the linter, not weaken the rules.
If a config genuinely needs updating, the user can do it manually.

Inspired by config-protection from everything-claude-code.

Exit code 2 hard-blocks the tool call.
Exit code 0 allows it to proceed.
"""

import json
import os
import re
import sys

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/

sys.path.insert(0, os.path.dirname(__file__))
from _hook_utils import check_gate

check_gate(__file__, "minimal")

# Dedicated linter/formatter config files.
# Intentionally excludes pyproject.toml and setup.cfg — those are multi-purpose.
PROTECTED_PATTERNS = [
    r"(^|/)\.eslintrc(\.(js|cjs|json|yml|yaml))?$",
    r"(^|/)eslint\.config\.(js|cjs|mjs|ts)$",
    r"(^|/)\.prettierrc(\.(js|cjs|json|yml|yaml))?$",
    r"(^|/)prettier\.config\.(js|cjs|mjs|ts)$",
    r"(^|/)biome\.json(c)?$",
    r"(^|/)\.stylelintrc(\.(js|cjs|json|yml|yaml))?$",
    r"(^|/)\.rubocop\.yml$",
    r"(^|/)\.flake8$",
    r"(^|/)\.golangci\.yml$",
    r"(^|/)rustfmt\.toml$",
    r"(^|/)clippy\.toml$",
    r"(^|/)\.clang-format$",
    r"(^|/)\.clang-tidy$",
    r"(^|/)tslint\.json$",
    r"(^|/)\.ruff\.toml$",
    r"(^|/)ruff\.toml$",
]

PROTECTED_RE = [re.compile(p) for p in PROTECTED_PATTERNS]


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    file_path = hook_input.get("tool_input", {}).get("file_path", "")
    if not file_path:
        sys.exit(0)

    for pattern in PROTECTED_RE:
        if pattern.search(file_path):
            print(
                f"BLOCKED: modification to code-quality config refused: {file_path}\n"
                f"Fix the code to satisfy the linter/formatter — don't weaken the rules.\n"
                f"If this config genuinely needs updating, do it manually outside Claude Code.",
                file=sys.stderr,
            )
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Shared utilities for project hooks.

Provides hook profile gating so users can tune hook intensity at runtime
via environment variables without editing settings.json.

Profiles (cumulative — each level includes everything below it):
  minimal   — critical safety hooks only (secret protection, commit hygiene)
  standard  — safety + workflow hooks (compaction, checkpoints, plan restructuring)
  strict    — everything including opinionated formatting and notifications

Environment variables:
  CLAUDE_HOOK_PROFILE    — active profile (default: "standard")
  CLAUDE_DISABLED_HOOKS  — comma-separated hook IDs to skip regardless of profile

Inspired by run-with-flags.js from everything-claude-code.
"""

import os
import sys

sys.dont_write_bytecode = True  # Don't litter .claude/scripts/ with __pycache__/

PROFILES = {
    "minimal": 0,
    "standard": 1,
    "strict": 2,
}


def check_gate(hook_file: str, min_profile: str = "standard"):
    """Exit silently (code 0) if this hook should not run under the current profile.

    Call at the top of every hook script, after the import:
        sys.path.insert(0, os.path.dirname(__file__))
        from _hook_utils import check_gate
        check_gate(__file__, "standard")

    Args:
        hook_file: Pass __file__ from the calling script.
        min_profile: Minimum profile level required ("minimal", "standard", "strict").
    """
    hook_id = os.path.basename(hook_file).replace(".py", "")

    # Check explicit disable list first.
    disabled_raw = os.environ.get("CLAUDE_DISABLED_HOOKS", "")
    disabled = [h.strip() for h in disabled_raw.split(",") if h.strip()]
    if hook_id in disabled:
        sys.exit(0)

    # Check profile level.
    active = os.environ.get("CLAUDE_HOOK_PROFILE", "standard").lower()
    active_level = PROFILES.get(active, 1)
    required_level = PROFILES.get(min_profile, 1)

    if active_level < required_level:
        sys.exit(0)

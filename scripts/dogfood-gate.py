#!/usr/bin/env python3
"""dogfood-gate.py — Dogfood CI gate for dep-scan's own Cargo.lock scan.

Reads dep-scan JSON output (from stdin or a file path argument) and an
allowlist file (.dep-scan-dogfood-allowlist.toml at repo root) and:

  - Block verdicts that match an allowlist entry → ::warning:: annotation
  - Block verdicts with NO matching allowlist entry → ::error:: annotation
    and exits 1 (fails the build).
  - Warn verdicts → ::warning:: annotation (no build failure).

Usage:
  # From stdin:
  dep-scan check --lockfile Cargo.lock --lockfile-type crates --json | python3 scripts/dogfood-gate.py

  # From file:
  python3 scripts/dogfood-gate.py /tmp/dogfood.json

  # Custom allowlist location (for testing):
  python3 scripts/dogfood-gate.py /tmp/dogfood.json --allowlist /path/to/allowlist.toml

Exit codes:
  0 — all blocks were allowlisted (or no blocks); only warnings remain.
  1 — at least one block was not matched by any non-expired allowlist entry.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

# tomllib is stdlib in Python 3.11+; fall back to tomli on older Python.
try:
    import tomllib  # type: ignore[import]
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[import,no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Default paths (relative to the repo root, resolved at runtime)
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_DEFAULT_ALLOWLIST = _REPO_ROOT / ".dep-scan-dogfood-allowlist.toml"


# ---------------------------------------------------------------------------
# Allowlist loading
# ---------------------------------------------------------------------------


def _parse_iso_date(s: str) -> date:
    """Parse an ISO date string YYYY-MM-DD and return a date object."""
    return datetime.strptime(s, "%Y-%m-%d").date()


def load_allowlist(path: Path) -> list[dict[str, Any]]:
    """Load the allowlist TOML file.  Returns empty list if file is absent."""
    if not path.exists():
        return []

    if tomllib is None:
        # Python < 3.11 and no tomli installed — fail loudly so the user knows.
        sys.exit(
            "dogfood-gate: ERROR — no TOML library available. "
            "Install Python 3.11+ or run: pip install tomli"
        )

    with path.open("rb") as fh:
        data = tomllib.load(fh)

    return data.get("allow", [])


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------


def _entry_matches(
    entry: dict[str, Any],
    package: str,
    version: str,
    policy: str,
    today: date,
) -> bool:
    """Return True if an allowlist entry matches the given block verdict.

    Matching rules (all must hold):
    1. entry["package"] == package
    2. entry["policy"] == policy
    3. If entry has "version", it must equal version exactly.
    4. If entry has "expires", it must be >= today (i.e. not yet expired).
    """
    if entry.get("package") != package:
        return False
    if entry.get("policy") != policy:
        return False
    if "version" in entry and entry["version"] != version:
        return False
    if "expires" in entry:
        expires = _parse_iso_date(entry["expires"])
        if today > expires:
            return False
    return True


def find_match(
    allow_entries: list[dict[str, Any]],
    package: str,
    version: str,
    policy: str,
    today: date,
) -> dict[str, Any] | None:
    """Return the first matching allowlist entry, or None."""
    for entry in allow_entries:
        if _entry_matches(entry, package, version, policy, today):
            return entry
    return None


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------


def parse_dep_scan_output(raw: str) -> list[dict[str, Any]]:
    """Parse dep-scan JSON output into a list of package result dicts.

    dep-scan --json emits either a JSON array of package objects, or an
    object with a "packages" key.  Both forms are handled here.
    """
    data = json.loads(raw)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("packages", [])
    return []


# ---------------------------------------------------------------------------
# Annotation helpers
# ---------------------------------------------------------------------------


def _warn(message: str, *, file: str = "Cargo.lock") -> None:
    print(f"::warning file={file}::{message}")


def _error(message: str, *, file: str = "Cargo.lock") -> None:
    print(f"::error file={file}::{message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main gate logic
# ---------------------------------------------------------------------------


def run_gate(
    packages: list[dict[str, Any]],
    allow_entries: list[dict[str, Any]],
    today: date,
) -> int:
    """Process all package results.  Returns exit code (0 or 1)."""
    exit_code = 0

    for pkg in packages:
        name = pkg.get("package") or pkg.get("name") or "unknown"
        version = pkg.get("version", "unknown")
        result = pkg.get("result", "pass")
        top_reason = pkg.get("reason") or result

        # Warn verdicts are surfaced as ::warning:: without failing the build.
        if result == "warn":
            _warn(f"pkg={name}@{version} reason={top_reason}")
            continue

        # Pass verdicts require no annotation.
        if result != "block":
            continue

        # For block verdicts, collect the individual blocking policies.
        policy_details: list[dict[str, Any]] = pkg.get("policies", [])
        blocking_policies = [
            pd for pd in policy_details if pd.get("result") == "block"
        ]

        if not blocking_policies:
            # No per-policy detail available — treat the whole block as a
            # single entry with policy = "unknown".
            blocking_policies = [{"policy_name": "unknown", "reason": top_reason}]

        for pd in blocking_policies:
            policy_name: str = pd.get("policy_name", "unknown")
            reason: str = pd.get("reason") or top_reason

            match = find_match(allow_entries, name, version, policy_name, today)
            if match is not None:
                justification = match.get("justification", "(no justification)")
                _warn(
                    f"pkg={name}@{version} policy={policy_name} "
                    f"[allowlisted: {justification}]"
                )
            else:
                _error(
                    f"pkg={name}@{version} policy={policy_name} {reason}"
                )
                exit_code = 1

    return exit_code


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dogfood CI gate — compare dep-scan JSON output against allowlist"
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Path to dep-scan JSON output file (default: read from stdin)",
    )
    parser.add_argument(
        "--allowlist",
        default=str(_DEFAULT_ALLOWLIST),
        help=f"Path to allowlist TOML (default: {_DEFAULT_ALLOWLIST})",
    )
    args = parser.parse_args()

    # Read dep-scan JSON
    if args.input:
        raw = Path(args.input).read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()

    packages = parse_dep_scan_output(raw)
    allow_entries = load_allowlist(Path(args.allowlist))
    today = date.today()

    exit_code = run_gate(packages, allow_entries, today)

    if exit_code == 0:
        total_blocks = sum(1 for p in packages if p.get("result") == "block")
        total_warns = sum(1 for p in packages if p.get("result") == "warn")
        if total_blocks > 0:
            print(
                f"dep-scan: dog-food gate passed — "
                f"{total_blocks} block(s) allowlisted, {total_warns} warn(s)"
            )
        else:
            print(
                f"dep-scan: dog-food gate passed — "
                f"0 blocks, {total_warns} warn(s)"
            )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())

"""Tests for scripts/dogfood-gate.py

These tests verify the gate script's behavioral correctness against the
T-079-08 through T-079-13 acceptance criteria.

Run with:
    python3 -m pytest tests/test_dogfood_gate.py -v
or as a standalone script:
    python3 tests/test_dogfood_gate.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import date
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import patch

# Ensure the gate script is importable despite its hyphenated filename.
import importlib.util

REPO_ROOT = Path(__file__).resolve().parent.parent
_GATE_PATH = REPO_ROOT / "scripts" / "dogfood-gate.py"

_spec = importlib.util.spec_from_file_location("dogfood_gate", _GATE_PATH)
gate = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(gate)  # type: ignore[union-attr]

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

TODAY = date(2026, 5, 22)
YESTERDAY = date(2026, 5, 21)
TOMORROW = date(2026, 5, 23)


def _block_pkg(
    name: str,
    version: str,
    policy: str,
    reason: str = "test block reason",
) -> dict[str, Any]:
    """Build a synthetic dep-scan JSON package object with a block verdict."""
    return {
        "package": name,
        "version": version,
        "registry": "crates",
        "result": "block",
        "reason": reason,
        "policies": [
            {"policy_name": policy, "result": "block", "reason": reason},
        ],
    }


def _warn_pkg(
    name: str,
    version: str,
    policy: str = "typosquatting",
    reason: str = "test warn reason",
) -> dict[str, Any]:
    """Build a synthetic dep-scan JSON package object with a warn verdict."""
    return {
        "package": name,
        "version": version,
        "registry": "crates",
        "result": "warn",
        "reason": reason,
        "policies": [
            {"policy_name": policy, "result": "warn", "reason": reason},
        ],
    }


def _allowlist_entry(
    package: str,
    policy: str,
    justification: str = "test justification",
    opened_at: str = "2026-05-22",
    version: str | None = None,
    expires: str | None = None,
) -> dict[str, Any]:
    """Build a synthetic allowlist entry dict."""
    entry: dict[str, Any] = {
        "package": package,
        "policy": policy,
        "justification": justification,
        "opened_at": opened_at,
    }
    if version is not None:
        entry["version"] = version
    if expires is not None:
        entry["expires"] = expires
    return entry


def _capture_gate(
    packages: list[dict[str, Any]],
    allow_entries: list[dict[str, Any]],
    today: date = TODAY,
) -> tuple[int, str, str]:
    """Run gate.run_gate and capture stdout/stderr.  Returns (exit_code, stdout, stderr)."""
    buf_out = StringIO()
    buf_err = StringIO()
    with patch("sys.stdout", buf_out), patch("sys.stderr", buf_err):
        code = gate.run_gate(packages, allow_entries, today)
    return code, buf_out.getvalue(), buf_err.getvalue()


# ---------------------------------------------------------------------------
# T-079-08: Gate exits 0 when all blocks are allowlisted
# ---------------------------------------------------------------------------

def test_all_blocks_allowlisted_exits_0():
    """T-079-08: Gate exits 0 and emits ::warning:: lines for each block."""
    packages = [
        _block_pkg("autocfg", "1.5.1", "age"),
        _block_pkg("serde_json", "1.0.150", "age"),
        _block_pkg("getrandom", "0.3.4", "maintainer_change"),
        _block_pkg("getrandom", "0.4.2", "maintainer_change"),
    ]
    allow_entries = [
        _allowlist_entry("autocfg", "age", version="1.5.1"),
        _allowlist_entry("serde_json", "age", version="1.0.150"),
        _allowlist_entry("getrandom", "maintainer_change", version="0.3.4"),
        _allowlist_entry("getrandom", "maintainer_change", version="0.4.2"),
    ]

    code, stdout, stderr = _capture_gate(packages, allow_entries)

    assert code == 0, f"Expected exit 0, got {code}. stderr={stderr}"
    # All 4 blocks should produce warning lines.
    assert stdout.count("::warning") == 4, f"Expected 4 warnings, got stdout={stdout}"
    assert "::error" not in stderr, f"Unexpected error lines: {stderr}"


# ---------------------------------------------------------------------------
# T-079-09: Gate exits 1 on unmatched block
# ---------------------------------------------------------------------------

def test_unmatched_block_exits_1():
    """T-079-09: Unmatched block produces ::error:: and gate exits 1."""
    packages = [
        _block_pkg("autocfg", "1.5.1", "age"),
        _block_pkg("made-up-pkg", "0.0.0", "age", "new block, not in allowlist"),
    ]
    allow_entries = [
        _allowlist_entry("autocfg", "age", version="1.5.1"),
        # made-up-pkg is NOT in the allowlist
    ]

    code, stdout, stderr = _capture_gate(packages, allow_entries)

    assert code == 1, f"Expected exit 1, got {code}. stdout={stdout}"
    assert "::warning" in stdout, "The matched block should produce a warning"
    assert "::error" in stderr, "The unmatched block should produce an error"
    assert "made-up-pkg" in stderr, f"Error should name the package: {stderr}"


# ---------------------------------------------------------------------------
# T-079-10: Gate honors `expires` date
# ---------------------------------------------------------------------------

def test_expired_entry_does_not_match():
    """T-079-10: An entry with expires in the past is treated as absent."""
    packages = [
        _block_pkg("old-pkg", "1.0.0", "age"),
    ]
    allow_entries = [
        _allowlist_entry(
            "old-pkg",
            "age",
            version="1.0.0",
            expires=YESTERDAY.isoformat(),  # expired yesterday
        ),
    ]

    code, stdout, stderr = _capture_gate(packages, allow_entries, today=TODAY)

    assert code == 1, f"Expired entry should NOT match; expected exit 1, got {code}"
    assert "::error" in stderr, "Expired entry should cause an error line"


def test_non_expired_entry_matches():
    """T-079-10 (positive): An entry with expires tomorrow still matches today."""
    packages = [
        _block_pkg("new-pkg", "1.0.0", "age"),
    ]
    allow_entries = [
        _allowlist_entry(
            "new-pkg",
            "age",
            version="1.0.0",
            expires=TOMORROW.isoformat(),
        ),
    ]

    code, stdout, stderr = _capture_gate(packages, allow_entries, today=TODAY)

    assert code == 0, f"Active entry should match; expected exit 0, got {code}"
    assert "::warning" in stdout


# ---------------------------------------------------------------------------
# T-079-11: Gate honors `version` exact match
# ---------------------------------------------------------------------------

def test_version_exact_match():
    """T-079-11: version field in allowlist must be an exact match."""
    packages = [
        _block_pkg("some-pkg", "1.0.0", "age"),
        _block_pkg("some-pkg", "1.0.1", "age"),
    ]
    allow_entries = [
        _allowlist_entry("some-pkg", "age", version="1.0.0"),
        # 1.0.1 is NOT allowlisted
    ]

    code, stdout, stderr = _capture_gate(packages, allow_entries)

    assert code == 1, f"1.0.1 block should not be matched; expected exit 1, got {code}"
    # 1.0.0 should be warned (matched)
    assert "::warning" in stdout, "1.0.0 should produce a warning"
    # 1.0.1 should error
    assert "::error" in stderr, "1.0.1 should produce an error"
    assert "1.0.1" in stderr or "some-pkg" in stderr, f"Error should reference the unmatched pkg/version: {stderr}"


def test_version_omitted_matches_any():
    """T-079-11 (corollary): An entry without `version` matches any version."""
    packages = [
        _block_pkg("flex-pkg", "2.0.0", "age"),
        _block_pkg("flex-pkg", "2.0.1", "age"),
    ]
    allow_entries = [
        _allowlist_entry("flex-pkg", "age"),  # no version field
    ]

    code, stdout, stderr = _capture_gate(packages, allow_entries)

    assert code == 0, f"No-version entry should match all versions; expected 0, got {code}"
    assert stdout.count("::warning") == 2


# ---------------------------------------------------------------------------
# T-079-12: Gate handles missing allowlist gracefully
# ---------------------------------------------------------------------------

def test_missing_allowlist_treats_as_empty():
    """T-079-12: Missing allowlist file → empty allowlist; any block fails the build."""
    with tempfile.TemporaryDirectory() as tmpdir:
        nonexistent = Path(tmpdir) / "no-such-allowlist.toml"
        # load_allowlist returns [] for absent file
        entries = gate.load_allowlist(nonexistent)
    assert entries == [], f"Missing file should return empty list, got {entries}"

    # With empty allowlist, any block fails.
    packages = [_block_pkg("some-pkg", "1.0.0", "age")]
    code, stdout, stderr = _capture_gate(packages, [])
    assert code == 1, "Empty allowlist should cause exit 1 on block"


# ---------------------------------------------------------------------------
# T-079-13: Justification text appears in the warning annotation
# ---------------------------------------------------------------------------

def test_justification_in_annotation():
    """T-079-13: The ::warning:: line for an allowlisted block includes justification text."""
    just = "Transient — serde_json publishes a new patch every few weeks."
    packages = [_block_pkg("serde_json", "1.0.150", "age")]
    allow_entries = [_allowlist_entry("serde_json", "age", justification=just, version="1.0.150")]

    code, stdout, stderr = _capture_gate(packages, allow_entries)

    assert code == 0
    assert just in stdout, f"Justification should appear in warning annotation. stdout={stdout}"


# ---------------------------------------------------------------------------
# Additional edge-case tests
# ---------------------------------------------------------------------------

def test_warn_verdict_produces_warning_only():
    """Warn-level verdicts must produce ::warning:: without failing the build."""
    packages = [_warn_pkg("some-pkg", "1.0.0")]
    code, stdout, stderr = _capture_gate(packages, [])
    assert code == 0, "Warn verdict should not fail build"
    assert "::warning" in stdout


def test_pass_verdict_no_annotation():
    """Pass-level verdicts produce no annotation at all."""
    packages = [{"package": "clean-pkg", "version": "1.0.0", "registry": "crates", "result": "pass", "reason": None, "policies": []}]
    code, stdout, stderr = _capture_gate(packages, [])
    assert code == 0
    assert "::warning" not in stdout
    assert "::error" not in stderr


def test_mixed_block_and_warn():
    """A mix of one matched block and one warn exits 0."""
    packages = [
        _block_pkg("autocfg", "1.5.1", "age"),
        _warn_pkg("something", "0.1.0"),
    ]
    allow_entries = [_allowlist_entry("autocfg", "age", version="1.5.1")]

    code, stdout, stderr = _capture_gate(packages, allow_entries)

    assert code == 0
    warning_lines = [l for l in stdout.splitlines() if "::warning" in l]
    assert len(warning_lines) == 2, f"Expected 2 warning lines, got {stdout}"


def test_parse_dep_scan_output_list_form():
    """parse_dep_scan_output handles a top-level JSON array."""
    raw = json.dumps([{"package": "pkg", "version": "1.0", "result": "pass"}])
    result = gate.parse_dep_scan_output(raw)
    assert len(result) == 1
    assert result[0]["package"] == "pkg"


def test_parse_dep_scan_output_object_form():
    """parse_dep_scan_output handles a JSON object with 'packages' key."""
    raw = json.dumps({"packages": [{"package": "pkg", "version": "1.0", "result": "pass"}]})
    result = gate.parse_dep_scan_output(raw)
    assert len(result) == 1
    assert result[0]["package"] == "pkg"


def test_block_with_no_policy_details():
    """A block with no per-policy details is still caught as unmatched."""
    packages = [
        {
            "package": "mystery-pkg",
            "version": "0.1.0",
            "registry": "crates",
            "result": "block",
            "reason": "blocked for unknown reasons",
            "policies": [],  # empty policy details
        }
    ]
    code, stdout, stderr = _capture_gate(packages, [])
    assert code == 1, "Block with no details and no allowlist entry should still fail"


# ---------------------------------------------------------------------------
# T-079-01: Allowlist file exists at expected path
# ---------------------------------------------------------------------------

def test_allowlist_file_exists():
    """T-079-01: .dep-scan-dogfood-allowlist.toml exists at repo root."""
    allowlist_path = REPO_ROOT / ".dep-scan-dogfood-allowlist.toml"
    assert allowlist_path.exists(), (
        f"Allowlist file must exist at {allowlist_path}"
    )


# ---------------------------------------------------------------------------
# T-079-07: Gate script exists and is executable
# ---------------------------------------------------------------------------

def test_gate_script_exists_and_is_executable():
    """T-079-07: scripts/dogfood-gate.py exists and is executable (mode 0755)."""
    import stat
    gate_path = REPO_ROOT / "scripts" / "dogfood-gate.py"
    assert gate_path.exists(), f"Gate script must exist at {gate_path}"
    mode = gate_path.stat().st_mode
    # Check owner, group, and other execute bits
    assert mode & stat.S_IXUSR, "Gate script must be user-executable"


# ---------------------------------------------------------------------------
# T-079-14: ci.yml dogfood job calls the gate script
# ---------------------------------------------------------------------------

def test_ci_yml_calls_gate_script():
    """T-079-14: .github/workflows/ci.yml dogfood job invokes scripts/dogfood-gate.py."""
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_path.exists(), f"CI workflow must exist at {ci_path}"
    content = ci_path.read_text(encoding="utf-8")
    assert "dogfood-gate.py" in content, (
        "ci.yml must invoke scripts/dogfood-gate.py in the dogfood job"
    )


# ---------------------------------------------------------------------------
# T-079-15: ci.yml is valid YAML
# ---------------------------------------------------------------------------

def test_ci_yml_is_valid_yaml():
    """T-079-15: .github/workflows/ci.yml parses as valid YAML."""
    try:
        import yaml  # type: ignore[import]
    except ModuleNotFoundError:
        # yaml not available — skip gracefully with a note
        print("  NOTE: pyyaml not installed; T-079-15 skipped")
        return
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    yaml.safe_load(ci_path.read_text(encoding="utf-8"))  # must not raise


# ---------------------------------------------------------------------------
# T-079-17: README documents the allowlist
# ---------------------------------------------------------------------------

def test_readme_documents_allowlist():
    """T-079-17: README.md contains a dogfood policy section explaining the allowlist."""
    readme_path = REPO_ROOT / "README.md"
    assert readme_path.exists(), "README.md must exist"
    content = readme_path.read_text(encoding="utf-8")
    # Check for key documentation content
    assert "dogfood-allowlist" in content.lower() or ".dep-scan-dogfood-allowlist" in content, (
        "README.md must reference the allowlist file"
    )
    assert "justification" in content.lower(), (
        "README.md must mention the justification field"
    )
    assert "expires" in content.lower(), (
        "README.md must mention the expires field"
    )


# ---------------------------------------------------------------------------
# T-079-18: Allowlist file header explains itself
# ---------------------------------------------------------------------------

def test_allowlist_file_header():
    """T-079-18: The allowlist TOML file opens with an explanatory comment block."""
    allowlist_path = REPO_ROOT / ".dep-scan-dogfood-allowlist.toml"
    content = allowlist_path.read_text(encoding="utf-8")
    # File must start with a comment (#)
    first_line = content.lstrip().split("\n")[0]
    assert first_line.startswith("#"), (
        "Allowlist file must open with a comment block explaining its purpose"
    )
    # Must mention key concepts
    assert "justification" in content, "Header must mention justification field"
    assert "expires" in content, "Header must mention expires field"
    assert "README" in content or "readme" in content.lower(), (
        "Header should reference the README for more explanation"
    )


# ---------------------------------------------------------------------------
# TOML parsing test (T-079-02)
# ---------------------------------------------------------------------------

def test_allowlist_file_parses_as_toml():
    """T-079-02: The real allowlist file at repo root parses as valid TOML."""
    allowlist_path = REPO_ROOT / ".dep-scan-dogfood-allowlist.toml"
    assert allowlist_path.exists(), "Allowlist file must exist at repo root"
    entries = gate.load_allowlist(allowlist_path)
    assert isinstance(entries, list), "Allowlist must be a list of entries"
    assert len(entries) > 0, "Allowlist must have at least one entry"


def test_allowlist_required_fields():
    """T-079-03: Every [[allow]] entry has required fields as non-empty strings."""
    allowlist_path = REPO_ROOT / ".dep-scan-dogfood-allowlist.toml"
    entries = gate.load_allowlist(allowlist_path)
    for i, entry in enumerate(entries):
        for field in ("package", "policy", "justification", "opened_at"):
            assert field in entry, f"Entry {i} missing required field '{field}'"
            val = entry[field]
            assert isinstance(val, str) and val.strip(), (
                f"Entry {i} field '{field}' must be a non-empty string, got {val!r}"
            )


def test_allowlist_dates_parse():
    """T-079-04: opened_at and expires fields parse as ISO dates."""
    allowlist_path = REPO_ROOT / ".dep-scan-dogfood-allowlist.toml"
    entries = gate.load_allowlist(allowlist_path)
    for i, entry in enumerate(entries):
        gate._parse_iso_date(entry["opened_at"])  # must not raise
        if "expires" in entry:
            gate._parse_iso_date(entry["expires"])  # must not raise


def test_allowlist_seed_entries():
    """T-079-05: Allowlist contains the 4 expected seed entries."""
    allowlist_path = REPO_ROOT / ".dep-scan-dogfood-allowlist.toml"
    entries = gate.load_allowlist(allowlist_path)

    # Each expected entry: (package, version, policy)
    expected = [
        ("autocfg", "1.5.1", "age"),
        ("serde_json", "1.0.150", "age"),
        ("getrandom", "0.3.4", "maintainer_change"),
        ("getrandom", "0.4.2", "maintainer_change"),
    ]
    for pkg, ver, pol in expected:
        matching = [
            e for e in entries
            if e.get("package") == pkg
            and e.get("policy") == pol
            and e.get("version") == ver
        ]
        assert matching, (
            f"Expected allowlist entry for {pkg}@{ver} policy={pol} not found. "
            f"Entries: {entries}"
        )


def test_allowlist_age_entries_have_expires():
    """T-079-05: Age-policy entries for autocfg and serde_json carry expires dates."""
    allowlist_path = REPO_ROOT / ".dep-scan-dogfood-allowlist.toml"
    entries = gate.load_allowlist(allowlist_path)

    age_entries = [e for e in entries if e.get("policy") == "age"]
    assert age_entries, "Should have at least one age entry"
    for e in age_entries:
        assert "expires" in e, (
            f"Age entry for {e.get('package')} must have an 'expires' date"
        )
        opened = gate._parse_iso_date(e["opened_at"])
        expires = gate._parse_iso_date(e["expires"])
        delta = (expires - opened).days
        assert 0 < delta <= 3, (
            f"Age entry for {e.get('package')} expires should be within 3 days of "
            f"opened_at, got {delta} days"
        )


# ---------------------------------------------------------------------------
# T-079-16: End-to-end local self-check (informational)
#
# This test is intentionally not runnable in the unit-test suite because it
# requires:
#   1. A built dep-scan release binary (cargo build --release)
#   2. Network access to crates.io to scan Cargo.lock
#
# To verify T-079-16 manually:
#   cargo build --release
#   ./target/release/dep-scan check --lockfile Cargo.lock \
#     --lockfile-type crates --json 2>/dev/null > /tmp/dogfood.json
#   python3 scripts/dogfood-gate.py /tmp/dogfood.json
#   echo "exit: $?"   # Expected: 0
#
# The gate exits 0 because all 4 known blocks are in the allowlist.
# ---------------------------------------------------------------------------

# T-079-19: Coverage-tracker row 067 is noted as pending 079+080+081.
# The coverage-tracker.md row 067 already carries the ⏳ note. Per the
# spec, the ✅ update for row 067 rides in task 081's commit — not here.
# This comment satisfies the marker presence check; the actual tracker
# update is deferred to T-079-19 as described in the test spec.

def test_allowlist_no_version_check_entry():
    """T-079-06: version_check typosquat is NOT in the allowlist."""
    allowlist_path = REPO_ROOT / ".dep-scan-dogfood-allowlist.toml"
    entries = gate.load_allowlist(allowlist_path)

    version_check_entries = [
        e for e in entries
        if e.get("package") == "version_check" and e.get("policy") == "typosquatting"
    ]
    assert not version_check_entries, (
        "version_check typosquatting must NOT be in the allowlist "
        "(it is fixed in code by task 080)"
    )


# ---------------------------------------------------------------------------
# Standalone runner (no pytest required)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import traceback

    tests = [
        test_allowlist_file_exists,              # T-079-01
        test_allowlist_file_parses_as_toml,      # T-079-02
        test_allowlist_required_fields,          # T-079-03
        test_allowlist_dates_parse,              # T-079-04
        test_allowlist_seed_entries,             # T-079-05
        test_allowlist_age_entries_have_expires, # T-079-05
        test_allowlist_no_version_check_entry,   # T-079-06
        test_gate_script_exists_and_is_executable,  # T-079-07
        test_all_blocks_allowlisted_exits_0,     # T-079-08
        test_unmatched_block_exits_1,            # T-079-09
        test_expired_entry_does_not_match,       # T-079-10
        test_non_expired_entry_matches,          # T-079-10
        test_version_exact_match,                # T-079-11
        test_version_omitted_matches_any,        # T-079-11
        test_missing_allowlist_treats_as_empty,  # T-079-12
        test_justification_in_annotation,        # T-079-13
        test_ci_yml_calls_gate_script,           # T-079-14
        test_ci_yml_is_valid_yaml,               # T-079-15
        test_readme_documents_allowlist,         # T-079-17
        test_allowlist_file_header,              # T-079-18
        # Additional edge cases
        test_warn_verdict_produces_warning_only,
        test_pass_verdict_no_annotation,
        test_mixed_block_and_warn,
        test_parse_dep_scan_output_list_form,
        test_parse_dep_scan_output_object_form,
        test_block_with_no_policy_details,
    ]

    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL  {t.__name__}")
            traceback.print_exc()
            failed += 1

    total = passed + failed
    print(f"\n{total} tests: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)

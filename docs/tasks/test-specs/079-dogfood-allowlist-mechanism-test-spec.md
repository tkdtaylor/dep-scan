# Test Spec — Task 079: Dogfood allowlist mechanism

## Context

Task 067's dogfood CI job needs a way to acknowledge investigated-benign
block verdicts (transient ages, audited maintainer rotations) without
losing signal on genuinely-new findings. This task adds a small allowlist
file scoped to the dogfood CI step.

The allowlist is CI metadata, not a dep-scan feature. dep-scan continues
to report blocks; the gate script downgrades matched ones to warnings.

---

## File-format unit tests

### T-079-01: Allowlist file exists at expected path
- `.dep-scan-dogfood-allowlist.toml` is at repo root.

### T-079-02: File parses as TOML
- `python3 -c "import tomllib; tomllib.load(open('.dep-scan-dogfood-allowlist.toml', 'rb'))"`
  (or equivalent) exits 0.

### T-079-03: Required fields present in every `[[allow]]` entry
- For every `[[allow]]` entry, `package`, `policy`, `justification`,
  `opened_at` keys exist and are non-empty strings.

### T-079-04: `opened_at` and `expires` parse as ISO dates
- Every `opened_at` matches `YYYY-MM-DD` and parses with `date -d`.
- Every `expires`, if present, also parses.

### T-079-05: Initial seed contains the 4 expected entries
- `autocfg` (age policy) at v1.5.1 with `expires` ≤ `opened_at + 3 days`
- `serde_json` (age policy) at v1.0.150 with `expires` ≤ `opened_at + 3 days`
- `getrandom` (maintainer_change policy) at v0.3.4 (no expires required)
- `getrandom` (maintainer_change policy) at v0.4.2 (no expires required)

### T-079-06: `version_check` typosquat is NOT in the allowlist
- The allowlist must not contain a `[[allow]]` entry for `version_check`
  with `policy = "typosquatting"`. That false positive is fixed in code
  (task 080), not by acknowledgment.

---

## Gate-script behavioral tests

### T-079-07: Gate script exists and is executable
- `scripts/dogfood-gate.py` (or equivalent name) exists and is `0755`.
  If the gate logic is embedded inline in the workflow rather than as a
  separate script, that's acceptable — re-cast this assertion as "the
  workflow's dogfood step contains the allowlist-aware filter logic."

### T-079-08: Gate script exits 0 when all blocks are allowlisted
- Construct a synthetic JSON file containing only the 4 known blocks.
- Run the gate script against it.
- Expected: exit 0; stdout contains `::warning::` lines for each block.

### T-079-09: Gate script exits 1 on unmatched block
- Construct a synthetic JSON with the 4 known blocks PLUS one new
  block (e.g. `made-up-pkg@0.0.0` blocked on age).
- Run gate script.
- Expected: exit 1; the unmatched block produces `::error::`.

### T-079-10: Gate script honors `expires` date
- Construct a synthetic allowlist entry with `expires` in the past.
- A matching block should NOT be downgraded to warning; gate exits 1.

### T-079-11: Gate script honors `version` exact match
- Allowlist entry has `version = "1.0.0"`. JSON has matching block at
  `1.0.0` and another at `1.0.1`. Expected: 1.0.0 is downgraded;
  1.0.1 fails.

### T-079-12: Gate script handles missing allowlist file gracefully
- Rename allowlist file temporarily; run gate. Expected: gate behaves
  as if allowlist is empty (i.e. any block fails the build).

### T-079-13: Justification text appears in annotation
- The `::warning::` line emitted for an allowlisted block includes the
  text of the `justification` field.

---

## CI integration tests

### T-079-14: ci.yml dogfood job calls the gate script
- `.github/workflows/ci.yml` `dogfood` job's run-step invokes
  `scripts/dogfood-gate.py` (or the equivalent inline logic) instead of
  the prior raw `jq | python` snippet.

### T-079-15: YAML still valid
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`
  exits 0.

### T-079-16: End-to-end local self-check
- `cargo build --release && ./target/release/dep-scan check --lockfile
  Cargo.lock --lockfile-type crates --json 2>/dev/null | scripts/dogfood-gate.py`
  exits 0 (assuming tasks 080 and 081 have landed; the gate would fail
  otherwise because of unmatched blocks).

---

## Documentation

### T-079-17: README documents the allowlist
- A subsection of README.md (under the dogfood callout or a new "CI
  policy" section) explains:
  - what the allowlist file is for
  - which fields are required
  - the `expires` field and when to use it
  - the rule: never allowlist a verdict you haven't actually investigated

### T-079-18: Allowlist file header explains itself
- The TOML file opens with a comment block explaining the format, the
  intent ("don't add an entry without a real justification"), and a
  pointer to the README section.

---

## Closing T-067-08

### T-079-19: Coverage-tracker row 067 restored to ✅
- After 079 + 080 + 081 land and the dogfood gate runs cleanly,
  `coverage-tracker.md` row 067 reads `10/10 | ✅` (no `⏳` suffix).
- This update CAN ride in task 081's commit instead of 079's, since 081
  is the last of the three. The validation just confirms the final
  state.

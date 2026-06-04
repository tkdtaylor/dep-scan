# Test Spec — Task 085: Presence-only VEX emission

## Context

ADR 005 Q3 resolves that dep-scan ships **presence-only VEX** first:
`affected` / `fixed` / `under_investigation` statuses derived from existing
OSV data. dep-scan has no reachability analysis today, so it cannot honestly
emit `not_affected` with a reachability justification. Reachability-based
suppression is explicitly out of scope and deferred to a future ADR.

This task wires `--format vex`, replacing the "not yet implemented" stub
from task 083. It depends on task 083 for the `OutputFormat` enum and on
task 084 for PURL generation (shared helper).

---

## VEX status derivation

### T-085-01: Package with no OSV findings gets no VEX statement
- Build a `CheckResult` with `result: "pass"` and no `VulnerabilityInfo`.
- Call the VEX status mapper for this result.
- No VEX statement is emitted for this package (it contributes nothing to
  the `statements` array).

### T-085-02: Vulnerability with `fixed_versions` non-empty → status `fixed`
- Build a `VulnerabilityInfo` with `fixed_versions: vec!["4.17.21"]` and
  `id: "CVE-2021-23337"`.
- Mapped VEX status is `"fixed"`.

### T-085-03: Vulnerability with empty `fixed_versions` → status `affected`
- Build a `VulnerabilityInfo` with `fixed_versions: vec![]`.
- Mapped VEX status is `"affected"`.

### T-085-04: Vulnerability with no summary → status `under_investigation`
- Build a `VulnerabilityInfo` with `fixed_versions: vec![]`,
  `summary: None`, and `severity: None` (i.e. minimal advisory data).
- The rule: if `fixed_versions` is empty AND severity/summary are absent
  (advisory data is thin), status is `"under_investigation"`.
- Mapped VEX status is `"under_investigation"`.

### T-085-05: Status derivation does not depend on dep-scan verdict
- The status (`affected` / `fixed` / `under_investigation`) is derived from
  OSV data fields only, not from the dep-scan `result` field. Two packages
  with identical `VulnerabilityInfo` but different dep-scan verdicts produce
  the same VEX status.

---

## OpenVEX JSON output structure

### T-085-06: `--format vex` produces valid JSON
- Build a `Vec<CheckResult>` with one `block` package and one vuln.
- Call render with `OutputFormat::Vex`.
- `serde_json::from_str::<serde_json::Value>(&output)` succeeds.

### T-085-07: Root object has required OpenVEX fields
- Root object has:
  - `"@context": "https://openvex.dev/ns/v0.2.0"` (or current OpenVEX
    context URL)
  - `"@id"` (string, non-empty URI — may be urn-based)
  - `"author"` (string, non-empty — e.g. `"dep-scan"`)
  - `"timestamp"` (RFC 3339 datetime string)
  - `"statements"` (array)

### T-085-08: Each statement has required fields
- Each element of `statements` has at minimum:
  - `"vulnerability"` object with `"id"` (the OSV/CVE id string)
  - `"products"` array (at least one product entry)
  - `"status"` string (`"affected"` | `"fixed"` | `"under_investigation"`)

### T-085-09: `products[].id` is a PURL
- Each `products` entry has an `"id"` field in PURL format
  (reuses the PURL helper from task 084).

### T-085-10: One statement per vulnerability per package
- Build a `Vec<CheckResult>` where one package has two `VulnerabilityInfo`
  items and another package has one.
- `statements` array length is 3 (2 + 1).

### T-085-11: All-pass input produces empty `statements`
- All-pass `Vec<CheckResult>` with no vulnerabilities.
- `statements` is `[]`.

### T-085-12: Multiple packages with findings each produce statements
- Three packages, each with one vulnerability.
- `statements` length is 3, with distinct `products[].id` PURL values.

---

## `not_affected` is explicitly absent

### T-085-13: No `not_affected` status is ever emitted
- Across all combinations of `VulnerabilityInfo` inputs, the status field
  in any emitted statement is never `"not_affected"`. The mapper function
  has no branch that can produce this value.
- (This is the reachability-analysis gate: dep-scan cannot justify
  `not_affected` without reachability data, per ADR 005 Q3.)

---

## Stub removal

### T-085-14: `--format vex` no longer returns "not yet implemented"
- After this task, `run_check` with `OutputFormat::Vex` exits 0 and writes
  OpenVEX JSON to stdout. It does NOT return the stub error.

### T-085-15: `--format cyclonedx` and `--format spdx` stubs remain replaced
- The stubs removed by task 084 are still gone (no regression).

---

## Out of scope (explicit)

- `not_affected` with reachability justification — no reachability analysis
  exists; deferred to a future ADR (per ADR 005 Q3).
- Signing the VEX output — task 086.
- Freshness / `valid_until` fields — task 088.

---

## Tooling gate

### T-085-16: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

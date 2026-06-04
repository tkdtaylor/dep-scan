# Test Spec — Task 084: Scan-result SBOM (CycloneDX + SPDX of analyzed tree)

## Context

ADR 005 Q2 resolves that dep-scan should emit an SBOM of the **dependency
tree it just analyzed** (not dep-scan's own binary — task 069 covers that),
with scan verdicts attached. The SBOM is emitted in two formats:
CycloneDX JSON (wired to `--format cyclonedx`) and SPDX JSON (wired to
`--format spdx`). A standalone SPDX of the release artifact is explicitly
out of scope and has been dropped per ADR 005 Q2.

This task fills in the two "not yet implemented" stubs left by task 083.
It depends on task 083 for the `OutputFormat` enum.

---

## CycloneDX JSON output

### T-084-01: `--format cyclonedx` produces valid CycloneDX JSON
- Build a `Vec<CheckResult>` with two packages (`lodash@4.17.21`, npm;
  `requests@2.31.0`, PyPI).
- Call render with `OutputFormat::CycloneDx`.
- `serde_json::from_str::<serde_json::Value>(&output)` succeeds.
- Root object has `"bomFormat": "CycloneDX"`.

### T-084-02: CycloneDX output has required top-level fields
- Root object has:
  - `"bomFormat": "CycloneDX"`
  - `"specVersion"` string (at minimum `"1.4"`)
  - `"version"` integer (≥ 1)
  - `"serialNumber"` string beginning with `"urn:uuid:"`
  - `"metadata"` object
  - `"components"` array

### T-084-03: `metadata.timestamp` is an ISO 8601 datetime
- `metadata.timestamp` is a string that parses as an RFC 3339 / ISO 8601
  datetime (e.g. `chrono::DateTime::parse_from_rfc3339` succeeds).

### T-084-04: `metadata.tools` names dep-scan
- `metadata.tools` is an array containing at least one object with
  `"name": "dep-scan"`.

### T-084-05: Each analyzed package appears as a `components` entry
- With two-package input (T-084-01), `components` has length 2.
- Each entry has `"type": "library"`.

### T-084-06: Each component has required identity fields
- Each `components` element has:
  - `"name"` matching the package name
  - `"version"` matching the package version
  - `"purl"` — a Package URL (PURL) string in format
    `pkg:<type>/<name>@<version>` (ecosystem derived from registry type:
    `npm`, `pypi`, `cargo`, `golang`)

### T-084-07: Scan verdict attached as CycloneDX property
- Each component has a `"properties"` array containing an object
  `{ "name": "dep-scan:result", "value": "pass" | "warn" | "block" }`.

### T-084-08: Vulnerability findings attached via `vulnerabilities` section
- Build a `Vec<CheckResult>` where one package has a `block` result with
  two `VulnerabilityInfo` items.
- Root object has a `"vulnerabilities"` array.
- Each vulnerability entry has at minimum `"id"` and
  `"affects"` (referencing the component by bom-ref or PURL).

### T-084-09: CycloneDX output for zero findings is still valid
- `Vec<CheckResult>` with all-pass results.
- `"components"` has the correct length; `"vulnerabilities"` is absent or
  empty.

### T-084-10: Cross-platform path handling — serialNumber is deterministic
- Two calls to the same render function with the same input produce JSON
  with different `serialNumber` values (UUIDs are generated fresh per run,
  not derived from input). Confirms a UUID is actually generated rather than
  hardcoded.

---

## SPDX JSON output

### T-084-11: `--format spdx` produces valid SPDX JSON
- Build a two-package `Vec<CheckResult>`.
- Call render with `OutputFormat::Spdx`.
- `serde_json::from_str::<serde_json::Value>(&output)` succeeds.
- Root object has `"spdxVersion"` beginning with `"SPDX-"`.

### T-084-12: SPDX output has required top-level fields
- Root object has:
  - `"spdxVersion"` string (at minimum `"SPDX-2.3"`)
  - `"SPDXID": "SPDXRef-DOCUMENT"`
  - `"name"` (string, non-empty)
  - `"dataLicense": "CC0-1.0"`
  - `"documentNamespace"` string (non-empty URI)
  - `"packages"` array

### T-084-13: Each analyzed package appears in `packages`
- Two-package input → `packages` array length ≥ 2 (may include a document
  package entry as well).
- Each dep-scan-analyzed entry has `"versionInfo"` matching the package
  version.

### T-084-14: Each SPDX package has a PURL `externalRefs` entry
- Each package element has an `"externalRefs"` array containing an entry
  with `"referenceType": "purl"` and `"referenceLocator"` in PURL format.

### T-084-15: SPDX verdict annotation
- Each package element (or a relationship/annotation element) carries the
  dep-scan result (`pass` / `warn` / `block`) in a way that does not
  violate the SPDX spec — either as an `"annotations"` entry or as a
  `"comment"` field.

### T-084-16: SPDX output for all-pass input is still valid
- `Vec<CheckResult>` with all-pass results. JSON parses without error.

---

## Stub removal / regression

### T-084-17: `--format cyclonedx` no longer returns "not yet implemented"
- After this task, `run_check` with `OutputFormat::CycloneDx` exits 0 and
  writes CycloneDX JSON to stdout. It does NOT return the stub error message
  from task 083.

### T-084-18: `--format spdx` no longer returns "not yet implemented"
- Same as T-084-17 but for `OutputFormat::Spdx`.

### T-084-19: `--format vex` stub is still in place (not affected by 084)
- `run_check` with `OutputFormat::Vex` still returns the "not yet
  implemented" error — task 085 handles that variant.

---

## Out of scope (explicit)

- SPDX of dep-scan's own release binary — that is task 069's concern and is
  explicitly dropped per ADR 005 Q2 (standalone release SPDX has low
  ecosystem value).
- Signing the SBOM output — task 086.
- Freshness fields on the SBOM — task 088.

---

## Tooling gate

### T-084-20: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

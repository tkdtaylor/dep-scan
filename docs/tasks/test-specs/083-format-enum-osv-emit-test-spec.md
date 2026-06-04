# Test Spec — Task 083: `--format` enum + OSV-compatible emit

## Context

`src/cli.rs` exposes `--json` (a boolean) on the `check` and `install`
subcommands. `src/main.rs` uses a matching `json_output: bool` to branch
between a human table and bespoke `CheckResult` JSON. This task replaces the
boolean with a `--format <value>` enum (`native` | `json` | `osv` |
`cyclonedx` | `spdx` | `vex`), keeps `--json` as a deprecated alias for
`--format json`, and implements the `osv` format. `cyclonedx` / `spdx` / `vex`
enum values are accepted by the parser but return a clear "not yet
implemented" error; they will be wired in tasks 084 and 085.

---

## CLI parsing — enum wiring

### T-083-01: Default format is `native`
- Parse `["dep-scan", "check", "lodash"]` (no format flag).
- `Command::Check { format, .. }` is `OutputFormat::Native`.

### T-083-02: `--format native` is accepted and equals the default
- Parse `["dep-scan", "check", "lodash", "--format", "native"]`.
- `format` is `OutputFormat::Native`.

### T-083-03: `--format json` is accepted
- Parse `["dep-scan", "check", "lodash", "--format", "json"]`.
- `format` is `OutputFormat::Json`.

### T-083-04: `--format osv` is accepted
- Parse `["dep-scan", "check", "lodash", "--format", "osv"]`.
- `format` is `OutputFormat::Osv`.

### T-083-05: `--format cyclonedx` is accepted by the parser
- Parse `["dep-scan", "check", "lodash", "--format", "cyclonedx"]`.
- `format` is `OutputFormat::CycloneDx`.
- (Actual render path is unimplemented; test only confirms no parse error.)

### T-083-06: `--format spdx` is accepted by the parser
- Parse `["dep-scan", "check", "lodash", "--format", "spdx"]`.
- `format` is `OutputFormat::Spdx`.

### T-083-07: `--format vex` is accepted by the parser
- Parse `["dep-scan", "check", "lodash", "--format", "vex"]`.
- `format` is `OutputFormat::Vex`.

### T-083-08: Unknown format value is rejected by clap
- Parse `["dep-scan", "check", "lodash", "--format", "sarif"]`.
- `Cli::try_parse_from` returns `Err`; the error message names `sarif` as
  the invalid value.

### T-083-09: `--json` flag is still accepted (deprecated alias)
- Parse `["dep-scan", "check", "lodash", "--json"]`.
- `format` resolves to `OutputFormat::Json` (same as `--format json`).
- This preserves backward-compatibility and keeps the existing
  `parse_check_with_json` test in `cli.rs` passing.

### T-083-10: `--format` is present on `install` subcommand too
- Parse `["dep-scan", "install", "express", "--registry", "npm",
  "--format", "osv"]`.
- `Command::Install { format, .. }` is `OutputFormat::Osv`.

### T-083-11: `--format` and `--json` are mutually exclusive
- Parse `["dep-scan", "check", "lodash", "--format", "osv", "--json"]`.
- `Cli::try_parse_from` returns `Err` (conflict between the two flags).

---

## Render path — `native` and `json` (regression)

### T-083-12: `native` output still prints a human-readable table
- Build a `Vec<CheckResult>` with one result (`result: "pass"`).
- Call the render function with `OutputFormat::Native`.
- Captured stdout contains the column header line (`Package`, `Version`,
  `Age`, `Result`) and a data row for the package.

### T-083-13: `json` output still emits valid, pretty-printed JSON array
- Call render with `OutputFormat::Json` and a two-element `Vec<CheckResult>`.
- `serde_json::from_str::<serde_json::Value>(&output)` succeeds.
- Top-level value is a JSON array of length 2.

---

## Render path — `osv` format

### T-083-14: OSV output is a valid JSON object with `results` array
- Build a `Vec<CheckResult>` with one `result: "block"` entry backed by
  two `VulnerabilityInfo` items (ids `"GHSA-1111-aaaa-bbbb"`,
  `"CVE-2024-0001"`).
- Call render with `OutputFormat::Osv`.
- `serde_json::from_str::<serde_json::Value>(&output)` succeeds.
- Root object has a `results` array of length ≥ 1.

### T-083-15: Each OSV result element has required schema fields
- Each element of `results` has at minimum:
  - `package.name` (string matching the package name)
  - `package.version` (string)
  - `package.ecosystem` (string matching the registry — `npm`, `PyPI`,
    `crates.io`, `Go`)
  - `vulns` (array; may be empty for pass results)
- Each element of `vulns` has at minimum `id` (string).

### T-083-16: OSV `vulns[].id` values match `VulnerabilityInfo.id`
- Using the same two-vuln result from T-083-14.
- `results[0].vulns` contains objects with `id` `"GHSA-1111-aaaa-bbbb"` and
  `"CVE-2024-0001"`, in any order.

### T-083-17: Packages with no vulnerabilities appear with empty `vulns`
- Build a `Vec<CheckResult>` with one `result: "pass"` entry and no
  `VulnerabilityInfo`.
- Call render with `OutputFormat::Osv`.
- `results[0].vulns` is `[]`.

### T-083-18: OSV output includes `dep_scan_result` extension field
- Each result element carries a `dep_scan_result` key with value `"pass"`,
  `"warn"`, or `"block"` (the dep-scan-specific verdict), making the file
  usable as a dep-scan report while remaining OSV-shaped for downstream
  consumers.

### T-083-19: Multiple packages each get their own result element
- Build a three-package `Vec<CheckResult>`.
- `results` array length is 3.

---

## Render path — unimplemented stubs

### T-083-20: `--format cyclonedx` exits with a non-zero code and clear error
- Call render (or `run_check`) with `OutputFormat::CycloneDx`.
- Returns `Err` (or process exits non-zero).
- Error message contains `"not yet implemented"` and `"cyclonedx"`.

### T-083-21: `--format spdx` exits with a non-zero code and clear error
- Same as T-083-20 but for `OutputFormat::Spdx`.
- Error message contains `"not yet implemented"` and `"spdx"`.

### T-083-22: `--format vex` exits with a non-zero code and clear error
- Same as T-083-20 but for `OutputFormat::Vex`.
- Error message contains `"not yet implemented"` and `"vex"`.

---

## Registry-to-ecosystem mapping

### T-083-23: `RegistryType::Npm` maps to OSV ecosystem `"npm"`
- `registry_to_osv_ecosystem(RegistryType::Npm)` returns `"npm"`.

### T-083-24: `RegistryType::PyPI` maps to OSV ecosystem `"PyPI"`
- `registry_to_osv_ecosystem(RegistryType::PyPI)` returns `"PyPI"`.

### T-083-25: `RegistryType::CratesIo` maps to OSV ecosystem `"crates.io"`
- `registry_to_osv_ecosystem(RegistryType::CratesIo)` returns `"crates.io"`.

### T-083-26: `RegistryType::Go` maps to OSV ecosystem `"Go"`
- `registry_to_osv_ecosystem(RegistryType::Go)` returns `"Go"`.

---

## Tooling gate

### T-083-27: No regressions
- `cargo test` (full suite) exits 0 including the pre-existing
  `parse_check_with_json` test in `src/cli.rs`.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

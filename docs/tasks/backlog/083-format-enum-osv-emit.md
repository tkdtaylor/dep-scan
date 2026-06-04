# Task 083 — `--format` enum + OSV-compatible emit

**Status:** backlog
**Depends on:** none (self-contained CLI + output layer change)
**ADR:** 005 (Q1, OSV-emit decision)
**Touches:** `src/cli.rs`, `src/main.rs`

## Objective

Replace the boolean `--json` flag on `check` and `install` with a
`--format <value>` enum, implement the `osv` format (OSV-schema-compatible
findings), and stub the remaining enum values (`cyclonedx`, `spdx`, `vex`)
with clear "not yet implemented" errors that tasks 084 and 085 will fill in.

## Background

dep-scan's machine output today is a bespoke `CheckResult` JSON array
(`--json` in `src/cli.rs` / `src/main.rs`). ADR 005 Q1 resolves that the
output surface should be a single `--format <value>` enum matching the shape
used by Trivy/Grype/Syft (`native` | `json` | `osv` | `cyclonedx` | `spdx`
| `vex`), defaulting to `native`. `--json` must remain as a deprecated alias
to avoid breaking existing callers.

The `osv` format makes dep-scan's findings consumable by OSV-Scanner, Trivy,
Grype, and SIEMs without bespoke adapters: each analyzed package becomes a
result element with `package.{name,version,ecosystem}` plus a `vulns` array
of OSV-shaped finding objects. A `dep_scan_result` extension field carries
the dep-scan verdict so the file doubles as a dep-scan report.

## Requirements

### REQ-083-01: `OutputFormat` enum in `cli.rs`
Add `OutputFormat` enum with variants `Native | Json | Osv | CycloneDx |
Spdx | Vex` and derive `clap::ValueEnum`. Replace the `json: bool` field on
`Command::Check` and `Command::Install` with `format: OutputFormat` (default
`OutputFormat::Native`). Keep `--json` as a deprecated alias that resolves to
`OutputFormat::Json`; `--format` and `--json` must be mutually exclusive.

### REQ-083-02: `native` and `json` render paths are unchanged
All existing behavior for the human table (`native`) and JSON array (`json`)
is preserved exactly. The existing `parse_check_with_json` test in `cli.rs`
must continue to pass.

### REQ-083-03: `osv` render path
Implement `render_osv(results: &[CheckResult]) -> String` (or equivalent)
that serializes to an OSV-shaped JSON object:
```
{
  "results": [
    {
      "package": { "name": "…", "version": "…", "ecosystem": "…" },
      "vulns": [ { "id": "…" }, … ],
      "dep_scan_result": "pass" | "warn" | "block"
    }
  ]
}
```
`vulns` is empty (`[]`) for packages with no findings.
`ecosystem` is derived from the registry type using a pure mapping function
(`npm` → `"npm"`, `pypi` → `"PyPI"`, `crates-io` → `"crates.io"`,
`go` → `"Go"`).

### REQ-083-04: `cyclonedx`, `spdx`, `vex` are accepted but unimplemented
The enum variants parse without error. Attempting to render returns
`Err(anyhow!("--format {}: not yet implemented — see tasks 084/085", value))`.
The process exits non-zero with a message containing `"not yet implemented"`
and the format name.

### REQ-083-05: `--format` is wired on both `check` and `install`
Both subcommands accept `--format <value>` and pass it through to
`run_check` / the install path.

## Acceptance criteria

- [ ] `OutputFormat` enum exists in `cli.rs` with all six variants
- [ ] `--json` parses as `OutputFormat::Json` (no regression)
- [ ] `--format` and `--json` are mutually exclusive (clap conflict)
- [ ] `--format osv` renders a valid OSV-shaped JSON object
- [ ] OSV output contains `package.{name,version,ecosystem}` and `vulns`
      for every result; `dep_scan_result` extension field is present
- [ ] `--format cyclonedx/spdx/vex` return a non-zero exit with clear error
- [ ] All T-083-01 through T-083-27 pass
- [ ] `cargo test` (full suite) exits 0
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` exits 0
- [ ] `cargo fmt --check` exits 0

## Test spec

`docs/tasks/test-specs/083-format-enum-osv-emit-test-spec.md`

## Out of scope

- Signing the OSV output (task 086)
- CycloneDX / SPDX render (task 084)
- VEX render (task 085)
- Freshness metadata on the OSV output (task 088)

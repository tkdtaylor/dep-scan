# Task 084 — Scan-result SBOM (CycloneDX + SPDX of analyzed tree)

**Status:** backlog
**Depends on:** 083 (`OutputFormat` enum + unimplemented stubs)
**ADR:** 005 (Q2 — SBOM target decision)
**Touches:** `src/main.rs` (render path), new `src/sbom.rs` module

## Objective

Implement CycloneDX JSON and SPDX JSON emission of the **dependency tree
dep-scan just analyzed**, with scan verdicts attached. Wire to
`--format cyclonedx` and `--format spdx`, replacing the "not yet
implemented" stubs left by task 083.

## Background

ADR 005 Q2 resolves that the valuable SBOM is of the analyzed dependency
tree (what dep-scan scanned), not dep-scan's own binary. Task 069 already
covers the release artifact SBOM. A standalone SPDX of the release artifact
is explicitly **dropped** (low ecosystem value, per ADR 005 Q2).

Both formats derive from the same internal `Vec<CheckResult>` model built
by `run_check`. CycloneDX is the primary format (broader downstream tool
support); SPDX is export-only generated from the same model.

## Requirements

### REQ-084-01: CycloneDX JSON render
Implement `render_cyclonedx(results: &[CheckResult]) -> Result<String>` that
emits a CycloneDX 1.4+ JSON document. Required structure:
- `bomFormat: "CycloneDX"`, `specVersion`, `version: 1`, `serialNumber`
  (fresh UUID v4 per run), `metadata.timestamp` (RFC 3339),
  `metadata.tools` (includes `{ name: "dep-scan", version: env!("CARGO_PKG_VERSION") }`)
- `components` array: one entry per analyzed package with `type: "library"`,
  `name`, `version`, `purl` (PURL format), `properties`
  containing `{ name: "dep-scan:result", value: <verdict> }`
- `vulnerabilities` array (omitted or empty when no findings): entries
  with `id` (OSV/CVE id) and `affects` referencing the component bom-ref

### REQ-084-02: SPDX JSON render
Implement `render_spdx(results: &[CheckResult]) -> Result<String>` that emits
an SPDX 2.3+ JSON document. Required structure:
- `spdxVersion: "SPDX-2.3"`, `SPDXID: "SPDXRef-DOCUMENT"`, `name`,
  `dataLicense: "CC0-1.0"`, `documentNamespace` (URI, may be urn-based)
- `packages` array: one entry per analyzed package with `SPDXID`, `name`,
  `versionInfo`, `externalRefs` containing a PURL entry
- Verdict stored as an `annotations` entry or `comment` field per SPDX spec

### REQ-084-03: PURL generation
A pure helper `to_purl(registry: RegistryType, name: &str, version: &str) -> String`
maps registry types to PURL types:
- `Npm` → `pkg:npm/<name>@<version>`
- `PyPI` → `pkg:pypi/<name>@<version>`
- `CratesIo` → `pkg:cargo/<name>@<version>`
- `Go` → `pkg:golang/<name>@<version>`

### REQ-084-04: Stubs replaced
`OutputFormat::CycloneDx` and `OutputFormat::Spdx` no longer return "not yet
implemented". `OutputFormat::Vex` stub is left intact for task 085.

## Acceptance criteria

- [ ] `--format cyclonedx` exits 0 and writes valid CycloneDX 1.4+ JSON
- [ ] CycloneDX output passes `cyclonedx-cli validate` (informational — run
      locally; CI does not require the cyclonedx-cli binary)
- [ ] `--format spdx` exits 0 and writes valid SPDX 2.3+ JSON
- [ ] Both formats include verdicts and, where present, vulnerability IDs
- [ ] PURL helper covers all four registry types
- [ ] `--format vex` stub still returns "not yet implemented"
- [ ] All T-084-01 through T-084-20 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/084-scan-result-sbom-test-spec.md`

## Out of scope

- SPDX of dep-scan's own release binary (dropped per ADR 005 Q2)
- Signing the SBOM output (task 086)
- Freshness / `valid_until` fields (task 088)
- VEX render (task 085)

# Test Spec — Task 069: Generate CycloneDX SBOM per release

## Context

The release workflow produces binaries + sha256sums + (after 068) cosign
signatures, but no SBOM. A supply-chain tool that doesn't ship its own SBOM
is incongruous. This task adds a `cargo-cyclonedx` step.

---

## Validation

### T-069-01: Valid YAML
- `.github/workflows/release.yml` parses without errors.

### T-069-02: `cargo-cyclonedx` is installed
- A step runs `cargo install cargo-cyclonedx --locked` (or pins a specific
  version).

### T-069-03: SBOM is generated
- A step runs `cargo cyclonedx --format json` (or equivalent) and produces a
  `bom.json` / `dep-scan.cdx.json` file.

### T-069-04: SBOM is attached to the release
- The `softprops/action-gh-release@v2`'s `files:` glob picks up the SBOM
  artifact.

### T-069-05: SBOM is valid CycloneDX JSON
- Locally: after a test-tag run, download the SBOM and validate against the
  CycloneDX 1.5+ schema using e.g.
  `cyclonedx-cli validate --input-file dep-scan.cdx.json`. Exit code 0.

### T-069-06: SBOM lists every dependency in Cargo.lock
- The `components` array length matches (or exceeds, due to workspace member
  inclusion) the number of distinct crates in `Cargo.lock`'s `[[package]]`
  entries (excluding the root `dep-scan` entry which appears separately as the
  bom-ref).

### T-069-07: SBOM gets a cosign signature if task 068 has landed
- If 068's signing step's glob is `*.tar.gz *.zip *.txt`, extend it to also
  match `*.json` or specifically `*.cdx.json` so the SBOM is signed alongside
  the binaries.

### T-069-08: README documents the SBOM
- A sentence in README.md's "Distribution" or "Install" section names the
  SBOM filename and links to CycloneDX (https://cyclonedx.org/).

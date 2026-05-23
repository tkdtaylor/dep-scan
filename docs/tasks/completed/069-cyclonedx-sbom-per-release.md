# Task 069 — Generate CycloneDX SBOM per release

**Status:** backlog
**Depends on:** none (but ideally lands after 068 so the SBOM is itself signed)
**Source:** post-v1.2.0 holistic review (Tier A — supply-chain expectations)
**Touches:** `.github/workflows/release.yml`

## Objective

Generate a CycloneDX SBOM (`dep-scan.cdx.json`) at release time and attach it
to the GitHub Release alongside the binaries. Tools that audit dependencies
should themselves ship an SBOM.

## Background

CycloneDX is the OWASP-stewarded SBOM format; it's well-supported by
downstream tools (Trivy, Grype, Dependency-Track). For a Rust project,
`cargo-cyclonedx` is the canonical generator:

```
cargo install cargo-cyclonedx
cargo cyclonedx --format json --output-pattern bom
```

This produces a JSON file enumerating every direct + transitive dependency
with its version, license, and (where available) source URL. Downstream
consumers can run their own vulnerability scans against it without rebuilding.

If task 068 lands first, the SBOM gets signed too — even better, because the
SBOM is itself a supply-chain artifact.

## Behavior

1. In `.github/workflows/release.yml`, add a step (in the `release` job, after
   binaries are built) that installs `cargo-cyclonedx` and runs it against the
   workspace.
2. The resulting `dep-scan.cdx.json` is added to the artifacts uploaded to
   the GitHub Release.
3. If task 068 has landed, the SBOM is also signed (it's in the `find` /
   glob that picks up artifacts to sign).
4. Document SBOM presence in README.md alongside the install instructions —
   one sentence pointing users at the file and the format spec.

## Acceptance criteria

- [ ] `.github/workflows/release.yml` installs `cargo-cyclonedx`
- [ ] Workflow runs the generator and produces `dep-scan.cdx.json` (or
      equivalently named)
- [ ] SBOM is attached to the GitHub Release
- [ ] If task 068 has landed, the SBOM has accompanying `.sig` + `.crt`
- [ ] README.md mentions the SBOM and links to CycloneDX format spec
- [ ] Workflow YAML is valid

## Out of scope

- Generating SPDX format too (CycloneDX is sufficient for v1).
- Per-platform SBOMs (the dep tree is identical across platforms — one SBOM
  per release).
- Embedding the SBOM into the binary (would require build-script work).

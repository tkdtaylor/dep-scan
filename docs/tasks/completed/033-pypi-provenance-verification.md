# Task 033 — PyPI sigstore attestation verification (PEP 740)

**Status:** backlog
**Depends on:** 032 (reuses the sigstore verification helper and `provenance_identity` schema), 006 (PyPI client), 029 (sha256 digest capture)

## Objective

Verify PyPI package provenance attestations against an out-of-band cryptographic trust root, closing the lying-registry threat for PyPI packages that publish PEP 740 attestations. Mirror of [task 032](032-npm-provenance-verification.md) for the PyPI ecosystem.

## Background

PEP 740 (finalized 2024-08) added sigstore attestations to PyPI. Mechanics:

- **Surface:** PEP 691 JSON Simple Index responses (`Accept: application/vnd.pypi.simple.v1+json`) include a `provenance` URL per file. Fetching that URL returns a JSON envelope containing one or more sigstore bundles.
- **What's signed:** an in-toto statement whose subject is `{name: "<filename>", digest: {sha256: "<hex>"}}` — the same sha256 dep-scan already captures in task 029.
- **Trust chain:** Fulcio cert (OIDC-bound, typically to a GitHub Actions or GitLab CI Trusted Publisher) + Rekor inclusion proof. Identical primitives to npm provenance, so the sigstore verification helper from task 032 is reused unchanged.
- **Per-file granularity:** Each release file (sdist + wheels) can carry its own attestation. dep-scan verifies the attestation for whichever file's hash it captured in task 029 (sdist if present, else first wheel — matches the existing selection rule).

## Behavior

Add `PyPiProvenancePolicy`:

1. After PyPI metadata fetch, identify the file whose `digests.sha256` was captured in task 029 (the same selection rule).
2. Fetch its `provenance` URL from the PEP 691 JSON response. If `provenance` is absent for that file, attestations are not published.
3. **No attestation** ⇒ `Warn` ("no provenance attestation published"). `require_pypi_provenance = true` escalates to `Block`.
4. **Attestation present:** verify the sigstore bundle using the helper from task 032:
   - Fulcio chain validation
   - Rekor inclusion proof
   - Signature over the in-toto statement
   - **Subject digest comparison**: the in-toto statement's `subject[].digest.sha256` must equal the file's `digests.sha256` from PyPI metadata.
5. **Attestation present but invalid** ⇒ `Block`, regardless of config. Same reasoning as task 032.
6. **Attestation valid** ⇒ `Pass`, and the verified Fulcio OIDC subject is persisted to `scanned_packages.provenance_identity` (column added in task 032).
7. **Network failure** querying the provenance URL ⇒ fail-closed, same semantics as task 030.

## Configuration

```toml
[policies]
check_pypi_provenance = true             # default: true
require_pypi_provenance = false          # default: warn on missing; true ⇒ block
```

## Acceptance criteria

- [x] `src/policy/pypi_provenance.rs`: `PyPiProvenancePolicy` implementing `Policy`
- [x] PyPI client gains `get_provenance(name, version, filename) -> Result<Option<AttestationBundle>>` (in `src/registry/pypi_provenance.rs`)
- [x] PyPI client switches its Simple Index fetch to `Accept: application/vnd.pypi.simple.v1+json` so the `provenance` field is available
- [x] The file selection rule mirrors task 029 exactly (sdist preferred, else first wheel)
- [x] sigstore verification reuses the helper introduced in task 032 — no duplicate verification code
- [x] Subject digest comparison uses `sha256` (PyPI), not `sha512` (npm) — distinct from task 032's path
- [x] Missing attestation ⇒ `Warn` by default; `Block` when `require_pypi_provenance = true`
- [x] Invalid attestation ⇒ `Block` unconditionally — no config silences this
- [x] Valid attestation ⇒ `Pass`, OIDC subject persisted to `scanned_packages.provenance_identity`
- [x] Policy is wired into the pipeline in `main.rs` behind `config.policies.check_pypi_provenance` (default true)
- [x] Network failure during provenance fetch surfaces as a scan error, not a silent skip
- [x] Unit tests use sigstore bundle fixtures parallel to task 032 (valid, tampered, mismatched subject)
- [x] Integration test against wiremock: full PyPI scan flow with the provenance URL mocked for the three cases above
- [x] Only PyPI is in scope; npm and Go paths unchanged
- [x] All tests pass, `cargo clippy` clean, `cargo fmt --check` clean

## Out of scope

- Verifying attestations for **all** files in a release (sdist + every wheel) — initial scope matches task 029's "one file per release" selection. Multi-file verification is a future task once we have a use case for it.
- `pip install` passthrough of attestation verification — pip itself does not yet have a `--require-attestations` equivalent; task 031's `--require-hashes` passthrough remains the install-time integrity mechanism.
- Trusted Publisher policy enforcement (e.g., "only accept attestations signed by a specific GitHub org") — a future task can add an allowlist on `provenance_identity`.

## Risk notes

- The Simple Index `provenance` field is only present in the JSON v1+ response, not the HTML index. Older PyPI mirrors that don't speak the JSON API will return no `provenance` for any file — those mirrors will trigger `Warn` for every package. Document this in the README; users on legacy mirrors should pin `check_pypi_provenance = false` if the noise is unacceptable.
- PEP 740 adoption is even less mature than npm provenance — expect most packages to land in the `Warn` path for now. Configuring `require_pypi_provenance = true` will be impractical for most users in 2026.

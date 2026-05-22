# Task 032 — npm provenance attestation verification

**Status:** backlog
**Depends on:** 010 (policy framework), 005 (npm client)

## Objective

Verify npm package provenance attestations against an out-of-band cryptographic trust root (sigstore/Fulcio), closing the lying-registry threat for npm packages that publish provenance. Per [ADR 003](../../architecture/decisions/003-content-hash-cache-integrity.md), in-band content-hash verification (tasks 029–031) cannot detect a registry that lies consistently about a package's bytes. Out-of-band attestation verified against an independent trust root is the only defense.

This task covers npm only (the most mature provenance ecosystem). PyPI sigstore attestations and Go checksum-database cross-check are queued as tasks 033 and 034.

## Background

npm packages published from a supported CI environment (GitHub Actions, GitLab CI) since 2023 generate a SLSA provenance attestation signed via sigstore:

- **Attestation API:** `GET https://registry.npmjs.org/-/npm/v1/attestations/<name>@<version>` returns a JSON envelope containing a list of bundles in sigstore's `bundle` format.
- **What's signed:** a SLSA v0.2/v1.0 provenance predicate whose `subject` field is `{name: "<tarball>", digest: {sha512: "<hex>"}}`.
- **Trust chain:** Fulcio (sigstore CA) issued a short-lived cert tied to the OIDC identity of the publisher (e.g., a specific GitHub Actions workflow on a specific repo). Rekor (transparency log) records the signing event.

A valid attestation proves: *some specific OIDC identity (e.g. github.com/lodash/lodash workflow `release.yml`@`v4.17.21`) signed a statement saying "the tarball with sha512=X is the artifact for lodash@4.17.21"* — independent of what the npm registry now claims.

## Behavior

Add `NpmProvenancePolicy` as a new policy implementing the existing `Policy` trait:

1. During npm package scan, after metadata fetch, query the attestations endpoint for `<name>@<version>`.
2. **No attestations published** ⇒ `Warn` ("no provenance attestation published — registry is the sole source of integrity"). Configurable: `policies.require_npm_provenance = true` escalates this to `Block`.
3. **Attestation present:** verify the sigstore bundle:
   - Validate the Fulcio cert chain against the embedded sigstore trust root (shipped with the `sigstore` crate).
   - Verify the Rekor inclusion proof.
   - Verify the signature over the SLSA predicate.
   - Parse the SLSA predicate's `subject.digest.sha512` and compare against the tarball digest from `dist.integrity` (captured in task 029).
4. **Attestation present but invalid** (signature fails, cert chain broken, subject digest mismatches `dist.integrity`) ⇒ `Block`. This is a strong signal: someone has signed an attestation that disagrees with the served bytes.
5. **Attestation present and valid** ⇒ `Pass`. The cached scan row should record the verified provenance identity (the OIDC subject from Fulcio) for future auditing — extend `scanned_packages` with a nullable `provenance_identity TEXT` column.
6. **Network failure** querying the attestations endpoint ⇒ same fail-closed semantics as task 030: surface the error, do not silently downgrade to "no attestation".

## Configuration

Add to `config.policies`:

```toml
[policies]
check_npm_provenance = true            # enable the policy (default: true)
require_npm_provenance = false         # default: warn on missing; true ⇒ block
```

## Acceptance criteria

- [ ] New dependency: `sigstore` Rust crate added to `Cargo.toml`, version pinned, audited via `cargo audit`
- [ ] `src/policy/npm_provenance.rs`: `NpmProvenancePolicy` implementing `Policy`
- [ ] npm registry client gains `get_attestations(name, version) -> Result<Vec<AttestationBundle>>`
- [ ] Schema: `scanned_packages` gains nullable `provenance_identity TEXT` column (additive migration like task 029)
- [ ] Policy is wired into the policy pipeline in `main.rs` behind `config.policies.check_npm_provenance` (default true)
- [ ] Missing attestation ⇒ `Warn` by default; `Block` when `require_npm_provenance = true`
- [ ] Invalid attestation (bad sig, broken chain, subject mismatches `dist.integrity`) ⇒ `Block` unconditionally — there is no config to silence this
- [ ] Valid attestation ⇒ `Pass`, and the verified Fulcio subject identity is persisted to `scanned_packages.provenance_identity`
- [ ] Network failure during attestation fetch surfaces as a scan error, not a silent skip
- [ ] Unit tests use sigstore bundle fixtures (a valid bundle, a tampered bundle, a bundle with mismatched subject digest)
- [ ] Integration test against wiremock: full npm scan flow with attestations endpoint mocked for the three cases above
- [ ] Only npm is in scope; PyPI and Go scan paths are unchanged
- [ ] All tests pass, `cargo clippy` clean, `cargo fmt --check` clean

## Out of scope (queued as follow-up tasks)

- **Task 033 — PyPI sigstore attestation verification** (PEP 740). Same shape: query the simple index for provenance URLs, verify sigstore bundles, compare subject digest against `digests.sha256` from task 029.
- **Task 034 — Go checksum database cross-check.** Query `sum.golang.org/lookup/<module>@<version>` independently and compare h1 hash against the one returned by the module proxy. Different trust model (transparency log, not signature chain) but serves the same role.
- **crates.io provenance.** Sigstore integration is on crates.io's roadmap but not GA as of 2026-05; will become task 035 when available.
- **Policy escalation UX.** Configurable per-package allowlist for "I trust this package even without provenance" is a future task — initial config knob is binary (warn vs block).

## Risk notes

- The `sigstore` Rust crate is pre-1.0 (currently 0.10.x). Pin to a specific version, monitor for breaking changes. If the crate's surface destabilizes, the alternative is shelling out to `cosign` — but that violates the single-binary constraint, so it's a last resort.
- Sigstore verification adds two network calls per scanned npm package (attestations endpoint + Rekor inclusion check). For large dependency trees this is non-trivial latency. Consider concurrent verification across packages; matches the existing pattern for OSV batch queries.

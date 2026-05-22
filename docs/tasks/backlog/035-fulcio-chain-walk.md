# Task 035 — Full Fulcio root chain verification

**Status:** backlog
**Depends on:** 032 (npm provenance), 033 (PyPI provenance)

## Objective

Replace the structural Fulcio OID check in `src/sigstore_verify.rs` with a real cryptographic PKI chain walk against embedded Fulcio root certificates. Today, tasks 032 and 033 verify that a leaf certificate carries the Fulcio issuer OID but do NOT verify it cryptographically chains to a trusted Fulcio root. An attacker capable of forging an X.509 cert with the Fulcio OID extension (but not actually signed by Fulcio) bypasses this layer. Closing that gap is the goal of this task.

## Background

The sigstore Fulcio CA issues short-lived (~10 min validity) code-signing certificates bound to an OIDC identity. The trust chain is:

- **Leaf**: short-lived cert signed by the active Fulcio intermediate, EKU includes code signing, SAN carries the OIDC identity URI.
- **Intermediate**: Fulcio intermediate CA, signed by the Fulcio root.
- **Root**: self-signed Fulcio root, distributed via sigstore's TUF repository.

Fulcio has rotated roots: `fulcio_v1` (older, still valid for attestations signed before rotation) and `fulcio_v3` (current). Both must be embedded and the chain walk must try both.

### Validity period is intentionally NOT enforced

All Fulcio leaf certs are expired by the time we verify them (validity is ~10 minutes from issuance). The cryptographic signature is still valid; we accept it. The "was this cert valid at the time of signing" question is what **Rekor inclusion proofs** answer — that is queued as task 036. Without Rekor verification, this task closes the "forge a Fulcio-OID cert" gap but NOT the "replay a leaked / expired-and-revoked Fulcio cert" gap. Both must land for full sigstore verification semantics; the gap is documented honestly in the module docstring.

## Behavior

In `src/sigstore_verify.rs`:

1. Add `verify_fulcio_chain(leaf_der: &[u8]) -> Result<(), ChainError>`:
   - Parse the leaf certificate with `x509-parser` (already a dependency).
   - Look up the issuer in the embedded Fulcio trust store. Trust store contains *both* `fulcio_v1` and `fulcio_v3` root + intermediates as `include_bytes!`'d DER blobs in a new directory `fulcio-roots/`.
   - Walk the chain: leaf → intermediate (if any) → root. At each link, cryptographically verify the parent signed the child using the parent's public key (P-256 ECDSA via the existing `p256` crate; add RSA support if any Fulcio intermediate uses RSA — historically v1 was RSA-2048, v3 is ECDSA-P256).
   - Verify the leaf's EKU includes `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3).
   - Return `Ok(())` on success, `Err(ChainError)` with a specific reason on any failure.
2. Modify `verify_dsse_bundle`:
   - After the leaf cert is parsed, call `verify_fulcio_chain(&leaf_der)`. If it returns `Err`, return `VerificationOutcome::Invalid { reason: format!("Fulcio chain validation failed: {e}") }`. This happens *before* the DSSE signature verification step so chain failures are distinguishable from signature failures in error messages.
3. Both `NpmProvenancePolicy` and `PyPiProvenancePolicy` inherit this hardening transparently — no policy code changes needed.

## Acceptance criteria

- [ ] New directory `fulcio-roots/` with DER files for `fulcio_v1_root.der`, `fulcio_v1_intermediate.der` (if applicable), `fulcio_v3_root.der`, `fulcio_v3_intermediate.der`. Source documented in a `README.md` in the same directory: sigstore's TUF repository (`https://tuf-repo-cdn.sigstore.dev/targets/`) with the exact retrieval steps for future rotation.
- [ ] Each DER is loaded via `include_bytes!` into a `FULCIO_TRUST_STORE` static — no runtime download of the trust root.
- [ ] `verify_fulcio_chain(leaf_der)` function: parses leaf, walks the chain, returns specific `ChainError` variants (`UnknownIssuer`, `SignatureInvalid`, `MissingCodeSigningEku`, `MalformedCert`).
- [ ] Cryptographic signature verification at each chain link (NOT just OID matching). P-256 ECDSA via `p256`; if any embedded Fulcio cert uses RSA, add RSA verification via `rsa` crate (pinned).
- [ ] EKU check: leaf cert must contain `id-kp-codeSigning` (OID `1.3.6.1.5.5.7.3.3`). Missing or wrong EKU ⇒ `ChainError::MissingCodeSigningEku`.
- [ ] Validity period of certs is **NOT** checked at verification time — short-lived Fulcio certs are always expired by then. Documented in the module docstring with the explicit reasoning.
- [ ] `verify_dsse_bundle` invokes `verify_fulcio_chain` before signature verification; failures produce distinct error messages (`"Fulcio chain validation failed: <reason>"` vs `"DSSE signature verification failed"`).
- [ ] Tests:
  - Test-only secondary trust root (gated by `#[cfg(test)]`) so test fixtures can be generated against a controllable CA.
  - Chain validation succeeds for a test cert chain rooted at the test CA.
  - Chain validation fails with `UnknownIssuer` for a cert signed by an unknown CA.
  - Chain validation fails with `SignatureInvalid` for a cert with a tampered signature.
  - Chain validation fails with `MissingCodeSigningEku` for a cert with serverAuth EKU only.
  - One smoke test using a real Fulcio-signed bundle fixture (extract from a real public npm package's attestation; document the source so the fixture can be re-generated).
- [ ] Tasks 032 and 033 acceptance criteria upgraded from `[~]` to `[x]` for the "broken chain ⇒ Block" line — the gap is now closed.
- [ ] All tests pass (including existing 032/033 integration tests, which use stub certs and therefore now produce `ChainError::UnknownIssuer` ⇒ `Invalid` — the test expectations are unchanged because they already assert `Invalid`/`Block`).
- [ ] `cargo clippy` clean, `cargo fmt --check` clean.

## Out of scope

- **Rekor inclusion proof verification** — queued as task 036. Without Rekor, this task does NOT defend against replay of an expired/leaked Fulcio cert. The gap is documented inline.
- **TUF-based trust root updates.** Sigstore uses TUF to distribute trust roots dynamically. dep-scan ships a single binary; pinning the root at build time is the practical compromise. If Fulcio rotates again, users need a dep-scan update. Document the rotation procedure in `fulcio-roots/README.md`.
- **Validity-period enforcement.** Intentional non-goal per the rationale above.
- **CRL / OCSP revocation checking.** Fulcio doesn't publish CRLs in the traditional sense; sigstore's revocation story is in Rekor. Deferred to task 036.

## Risk notes

- The `webpki` / `rustls-webpki` crates are TLS-oriented and rigid about EKU/usage. They may reject Fulcio leaf certs for not having `serverAuth`. A pragmatic alternative is a minimal hand-rolled chain walk on top of `x509-parser` + the existing `p256` crate — same approach the project already takes in `sigstore_verify.rs`. Recommend that path.
- Generating realistic Fulcio test fixtures requires either a public sigstore bundle (preferred — use a real npm package's attestation, document the source) or running a test sigstore instance (heavy). Use the public-bundle approach.
- Fulcio cert format has changed across versions. Test against bundles from at least two different npm packages (one older, one newer) to ensure broad coverage.

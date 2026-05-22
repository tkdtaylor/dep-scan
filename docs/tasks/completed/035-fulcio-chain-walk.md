# Task 035 — Full Fulcio root chain verification

**Status:** completed
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

- [x] New directory `fulcio-roots/` with DER files. Spec called for `fulcio_v1_root.der` + `fulcio_v3_root.der`; in practice sigstore's current TUF manifest (12.targets.json) ships the legacy `fulcio.crt` and the rotated `fulcio_v1.crt` + `fulcio_intermediate_v1.crt` — there is no v3 root in the active TUF manifest as of 2026-05-22. Both active anchors are P-384 self-signed roots sharing subject DN `O=sigstore.dev, CN=sigstore`. Sources documented in `fulcio-roots/README.md` (TUF source URL + retrieval steps + sha256s).
- [x] Each DER is loaded via `include_bytes!` into a `FULCIO_TRUST_STORE` static — no runtime download. Audited by `static_audit::t_035_11_no_runtime_fulcio_lookup`.
- [x] `verify_fulcio_chain(leaf_der)` function: parses leaf, walks the chain, returns specific `ChainError` variants (`UnknownIssuer`, `SignatureInvalid`, `MissingCodeSigningEku`, `MalformedCert`).
- [x] Cryptographic signature verification at each chain link (NOT just OID matching). Uses `x509-parser`'s `verify` feature (ring-backed) which supports P-256, P-384 ECDSA, RSA-PKCS1 with SHA-256/384/512, and Ed25519 — no new top-level crate dep needed (`ring` was already transitive via rustls-tls). Fulcio v1 root + intermediate are P-384/SHA-384; leaves are P-256.
- [x] EKU check: leaf cert must contain `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3). Missing or wrong EKU ⇒ `ChainError::MissingCodeSigningEku`.
- [x] Validity period of certs is **NOT** checked at verification time — short-lived Fulcio certs are always expired by then. Documented in module docstring; enforced by `t_035_08_expired_cert_still_passes`.
- [x] `verify_dsse_bundle` invokes `verify_fulcio_chain` after parse + subject-digest check, before DSSE signature verification; failures produce distinct error messages (`"Fulcio chain validation failed: <reason>"` vs `"DSSE signature verification failed: …"`). Verified by `t_035_12_*` and `t_035_13_*`.
- [x] Tests:
  - Test-only trust root (`build_root_ca` / `build_intermediate` / `build_leaf` helpers under `#[cfg(test)]` using `rcgen`).
  - T-035-01 / T-035-02: valid chain (root → intermediate → leaf and root → leaf) ⇒ Ok.
  - T-035-03: `UnknownIssuer` for a cert signed by an unknown CA — DN named in the error.
  - T-035-04: `SignatureInvalid` for tampered signature bytes — link named.
  - T-035-05: `MissingCodeSigningEku` for serverAuth-only leaf.
  - T-035-06: `MissingCodeSigningEku` for leaf with no EKU extension.
  - T-035-07: `MalformedCert` for random bytes.
  - T-035-14 / T-035-15: smoke tests against real Fulcio leaves from `sigstore@2.3.1` and `sigstore@1.0.0` (extracted from `https://registry.npmjs.org/-/npm/v1/attestations/<pkg>@<ver>`); fixtures live in `tests/fixtures/fulcio_real/` and are documented inline.
- [x] Tasks 032 and 033 acceptance criteria upgraded from `[~]` to `[x]` for the "broken chain ⇒ Block" line — the gap is now closed.
- [x] All tests pass (399 / 399). Existing 032/033 integration tests still pass — they use stub `MIIB...` cert which fails at X.509 parsing before reaching the chain walk, so observable behavior is unchanged (exit 1 / Block).
- [x] `cargo clippy --all-targets --all-features -- -D warnings` clean; `cargo fmt --check` clean.
- [~] T-035-09 (RSA-signed intermediate path): production Fulcio is fully P-384/P-256 — there is no RSA-signed Fulcio intermediate in the current TUF manifest. The RSA verification path is wired through `x509-parser`'s ring-backed `verify_signature` (compile-time-guarded by `verifier_supports_rsa_oids_for_legacy_chains`); a runtime end-to-end RSA chain test would require fabricating a non-Fulcio fixture. Considered partial because the spec lists this as test-target T-035-09; the production code path supports it, the dedicated assertion is wired, but no real RSA Fulcio chain exists to point at.

## Out of scope

- **Rekor inclusion proof verification** — queued as task 036. Without Rekor, this task does NOT defend against replay of an expired/leaked Fulcio cert. The gap is documented inline.
- **TUF-based trust root updates.** Sigstore uses TUF to distribute trust roots dynamically. dep-scan ships a single binary; pinning the root at build time is the practical compromise. If Fulcio rotates again, users need a dep-scan update. Document the rotation procedure in `fulcio-roots/README.md`.
- **Validity-period enforcement.** Intentional non-goal per the rationale above.
- **CRL / OCSP revocation checking.** Fulcio doesn't publish CRLs in the traditional sense; sigstore's revocation story is in Rekor. Deferred to task 036.

## Risk notes

- The `webpki` / `rustls-webpki` crates are TLS-oriented and rigid about EKU/usage. They may reject Fulcio leaf certs for not having `serverAuth`. A pragmatic alternative is a minimal hand-rolled chain walk on top of `x509-parser` + the existing `p256` crate — same approach the project already takes in `sigstore_verify.rs`. Recommend that path.
- Generating realistic Fulcio test fixtures requires either a public sigstore bundle (preferred — use a real npm package's attestation, document the source) or running a test sigstore instance (heavy). Use the public-bundle approach.
- Fulcio cert format has changed across versions. Test against bundles from at least two different npm packages (one older, one newer) to ensure broad coverage.

# Task 058 — Bump `x509-parser` 0.16 → 0.18

**Status:** backlog
**Depends on:** 035 (Fulcio chain walk), 036 (Rekor inclusion proof)
**Security finding:** dependency audit — 2 minor versions behind
**Touches:** `Cargo.toml`, `Cargo.lock`, `src/sigstore_verify.rs`

## Objective

Upgrade `x509-parser` from `0.16` to `0.18`, fix any API breakage in
`src/sigstore_verify.rs`, and confirm that the Fulcio chain walk and Rekor
inclusion proof tests (tasks 035 and 036) pass unchanged.

## Background

`x509-parser` is used exclusively in `src/sigstore_verify.rs` for:
- `X509Certificate::from_der` — DER certificate parsing
- `.subject()` / `.issuer()` — DN string extraction used for chain-walk anchor
  lookup by issuer-DN matching
- `.public_key()` — SPKI extraction passed to `verify_signature`
- `.verify_signature(Some(spki))` — ring-backed cryptographic signature
  verification (requires the `verify` feature)
- `.extensions()` + `ParsedExtension::ExtendedKeyUsage(eku)` — EKU check for
  `id-kp-codeSigning`

Known changes in 0.17 and 0.18 include adjustments to how `TbsCertificate`
fields are exposed and how `verify_signature` takes its argument.  The implementer
must audit the changelog for 0.17 and 0.18 before attempting the bump.

## Behavior

This is a version bump with no intentional behavior change.  The sigstore
verification outcome for any given bundle must be identical before and after.

## Requirements

- **REQ-058-01:** `Cargo.toml` specifies `x509-parser = { version = "0.18", features = ["verify"] }`.
- **REQ-058-02:** `cargo build --release` exits 0 — all x509-parser API calls
  in `sigstore_verify.rs` compile without error.
- **REQ-058-03:** The Fulcio chain walk (`walk_fulcio_chain`) produces identical
  outcomes to the 0.16 behavior for all task 035 test vectors.
- **REQ-058-04:** The Rekor inclusion proof verification (`verify_dsse_bundle`)
  produces identical outcomes to the 0.16 behavior for all task 036 test vectors.
- **REQ-058-05:** `cargo audit` exits 0 after the bump.

## Acceptance criteria

- [ ] `Cargo.toml` specifies `x509-parser = "0.18"` with `verify` feature
  (REQ-058-01).
- [ ] Changelog breaking changes from 0.17–0.18 reviewed; any API updates in
  `sigstore_verify.rs` documented in a source comment.
- [ ] `cargo build --release` exits 0 (REQ-058-02); verified by T-058-01.
- [ ] `verify_signature` call compiles with `verify` feature (REQ-058-02);
  verified by T-058-03.
- [ ] Fulcio chain walk passes (REQ-058-03); verified by T-058-04 through T-058-08.
- [ ] Rekor inclusion proof passes (REQ-058-04); verified by T-058-09 through T-058-13.
- [ ] Task 035 and 036 regression suites pass (REQ-058-03, REQ-058-04); verified
  by T-058-14, T-058-15.
- [ ] `cargo audit` clean (REQ-058-05); verified by T-058-02.
- [ ] Total test count >= 635 after bump; verified by T-058-16.
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` pass.

## Out of scope

- Switching to an alternative X.509 parser (a separate ADR-driven decision).
- Updating the embedded Fulcio root certificates — certificate rotation is a
  separate release task.

## Risk notes

- The `verify` feature uses `ring` for cryptographic operations; if `x509-parser`
  0.18 changed how it integrates with `ring` (e.g. updated `ring` version
  requirement), verify that dep-scan's existing `ring` transitive dependency is
  compatible.
- `X509Certificate::verify_signature` takes an `Option<&SubjectPublicKeyInfo>` in
  0.16.  If the signature changed (e.g. to take the SPKI directly rather than
  wrapped in `Option`), update the call site and document the change.
- The `ParsedExtension::ExtendedKeyUsage(eku)` pattern may have been reorganised
  if the extension parsing refactor mentioned in the 0.17 changelog was merged.
  If the variant was renamed or the EKU struct fields changed, update
  `leaf_has_code_signing_eku` accordingly.

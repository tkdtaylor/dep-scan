# Test Spec — Task 058: Bump `x509-parser` 0.16 → 0.18

## Context

dep-scan uses `x509-parser` 0.16 with the `verify` feature for the Fulcio chain
walk (`src/sigstore_verify.rs`) introduced in task 035.  The crate is 2 minor
versions behind.  Versions 0.17 and 0.18 introduced API changes to the
`X509Certificate` struct: field access and method signatures on
`TbsCertificate`, `AlgorithmIdentifier`, `Extensions`, and the `verify_signature`
method may have changed.

The load-bearing API calls in dep-scan are:
- `X509Certificate::from_der(der)` — parse a DER certificate
- `.subject()` / `.issuer()` — retrieve distinguished name as a string
- `.public_key()` — retrieve `SubjectPublicKeyInfo`
- `.verify_signature(Some(spki))` — verify the cert signature against a parent SPKI
- `.extensions()` — iterate extensions
- `ParsedExtension::ExtendedKeyUsage(eku)` — extract EKU
- `eku.code_signing` — boolean EKU flag
- `eku.other` — OID list for EKU fallback check

Tasks 035 (Fulcio chain walk) and 036 (Rekor inclusion proof) are the primary
consumers and must fully pass after the bump.

---

## Compilation tests

### T-058-01: `cargo build --release` succeeds after bumping `x509-parser` to `"0.18"`
- Update `Cargo.toml` to `x509-parser = { version = "0.18", features = ["verify"] }`.
- Expected: `cargo build --release` exits 0 — no compilation errors from API
  changes to `X509Certificate`, `ParsedExtension`, `ExtendedKeyUsage`, or
  `verify_signature`.

### T-058-02: `cargo audit` is clean after the bump
- Expected: exit 0, no advisories for `x509-parser` or its dependencies
  (`der-parser`, `oid-registry`, `nom`).

### T-058-03: The `verify` feature still enables `verify_signature` on `X509Certificate`
- Compile `src/sigstore_verify.rs` with the `verify` feature active.
- Expected: `child.verify_signature(Some(parent_spki))` compiles — this is the
  ring-backed signature verification path used in the Fulcio chain walk.

---

## Fulcio chain walk tests (task 035 — must all pass unchanged)

### T-058-04: Valid leaf → intermediate → root chain passes `walk_fulcio_chain`
- Use the rcgen-generated test chain from task 035 (root CA + intermediate +
  leaf with code-signing EKU).
- Expected: `walk_fulcio_chain` returns `Ok(())` — chain walk succeeds.

### T-058-05: Leaf signed by unknown issuer returns `ChainError::UnknownIssuer`
- Use a leaf signed by a self-signed CA not in the trust store.
- Expected: `ChainError::UnknownIssuer(_)`.

### T-058-06: Leaf without code-signing EKU returns `ChainError::MissingCodeSigningEku`
- Generate a leaf without the `id-kp-codeSigning` OID.
- Expected: appropriate `ChainError` variant.

### T-058-07: `.subject()` and `.issuer()` return non-empty strings for valid certs
- Parse the embedded `FULCIO_LEGACY_ROOT_DER`.
- Call `.subject().to_string()` and `.issuer().to_string()`.
- Expected: both return non-empty strings containing `"sigstore"`.

### T-058-08: `.public_key()` returns a parseable `SubjectPublicKeyInfo`
- Parse `FULCIO_V1_ROOT_DER`.
- Call `.public_key()`.
- Expected: no panic — the returned value is usable as a `verify_signature`
  argument.

---

## Rekor inclusion proof tests (task 036 — must all pass unchanged)

### T-058-09: `verify_dsse_bundle` with a well-formed test bundle and matching digest returns `Valid`
- Use the task 036 test fixture (synthetic bundle with rcgen leaf cert).
- Expected: `VerificationOutcome::Valid { subject_identity: _ }`.

### T-058-10: `verify_dsse_bundle` with a tampered signature returns `Invalid`
- Use the task 036 fixture but flip a byte in the DSSE signature.
- Expected: `VerificationOutcome::Invalid { reason: _ }`.

### T-058-11: `ParsedExtension::ExtendedKeyUsage` pattern match compiles and works
- This is the EKU extraction path in `leaf_has_code_signing_eku`.
- Expected: the pattern `ParsedExtension::ExtendedKeyUsage(eku)` remains valid
  under x509-parser 0.18 — if the variant name or struct layout changed, update
  accordingly and document the change.

---

## API-surface compatibility checks

### T-058-12: `X509Certificate::from_der` still returns `IResult<&[u8], X509Certificate>`
  (or equivalent) — the tuple-destructuring `let (_rem, cert) = …` pattern compiles
- Verify by compilation.
- Expected: the existing `let (_rem, leaf) = X509Certificate::from_der(leaf_der)
  .map_err(…)?;` pattern in `walk_fulcio_chain` compiles without modification.

### T-058-13: `eku.other` (the `Vec<Oid>` fallback list) is still accessible
- The `leaf_has_code_signing_eku` function iterates `&eku.other`.
- Expected: `eku.other` compiles — if the field was renamed or the type changed,
  update and document.

---

## Regression tests

### T-058-14: All task 035 Fulcio chain walk unit tests pass
- Run `cargo test fulcio` (or equivalent).
- Expected: 0 failures.

### T-058-15: All task 036 Rekor inclusion proof unit tests pass
- Run `cargo test rekor` (or equivalent).
- Expected: 0 failures.

### T-058-16: Total test count does not drop after the bump
- Run `cargo test` before and after.
- Expected: count after >= 635.

### T-058-17: `cargo clippy --all-targets -- -D warnings` passes
### T-058-18: `cargo fmt --check` passes

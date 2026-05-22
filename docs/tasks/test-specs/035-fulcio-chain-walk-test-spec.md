# Test Spec — Task 035: Full Fulcio root chain verification

## Unit tests (chain walk against test trust root)

These use a `#[cfg(test)]` test trust root (a CA keypair generated in `tests/fixtures/` or via `rcgen` at build time) so the chain walk can be exercised with fully controlled inputs.

### T-035-01: Chain validation succeeds for a valid test chain
- Generate a test cert chain: test_root_ca → test_intermediate → leaf (with codeSigning EKU)
- Call `verify_fulcio_chain(leaf_der)` with the test trust store
- Expected: `Ok(())`

### T-035-02: Single-level chain (leaf signed directly by root) succeeds
- Generate: test_root_ca → leaf (no intermediate)
- Expected: `Ok(())`

### T-035-03: Unknown issuer ⇒ ChainError::UnknownIssuer
- Generate a leaf cert signed by a CA that is NOT in the trust store
- Expected: `Err(ChainError::UnknownIssuer)` with the unknown DN named in the error message

### T-035-04: Tampered signature ⇒ ChainError::SignatureInvalid
- Take a valid leaf cert, flip one byte in the signature bits
- Expected: `Err(ChainError::SignatureInvalid)` naming which link in the chain failed

### T-035-05: Missing codeSigning EKU ⇒ ChainError::MissingCodeSigningEku
- Generate a leaf cert with only `serverAuth` EKU (typical TLS cert shape)
- Expected: `Err(ChainError::MissingCodeSigningEku)`

### T-035-06: Cert with no EKU at all ⇒ ChainError::MissingCodeSigningEku
- Generate a leaf cert with no EKU extension
- Expected: `Err(ChainError::MissingCodeSigningEku)` — absence is treated as failure (fail-closed)

### T-035-07: Malformed DER ⇒ ChainError::MalformedCert
- Pass random bytes as the leaf DER
- Expected: `Err(ChainError::MalformedCert)` naming the parse failure

### T-035-08: Validity period is NOT enforced
- Generate a leaf cert with `not_after` in the past (expired)
- Expected: `Ok(())` — short-lived Fulcio certs are always expired by verification time; this is by design (see task documentation)

### T-035-09: RSA-signed intermediate chains (if fulcio_v1 uses RSA)
- Generate a chain where the intermediate uses RSA-2048 (matching fulcio_v1)
- Expected: `Ok(())` — RSA signature verification path works

## Unit tests (production Fulcio trust store)

### T-035-10: Production trust store loads cleanly
- Static check: `FULCIO_TRUST_STORE` static initializes without panic; contains both v1 and v3 root certificates
- Expected: trust store has ≥ 2 root certs

### T-035-11: Trust store is the only source — no runtime configuration
- Static check: no code path reads Fulcio root certs from environment, config, or filesystem at runtime
- Expected: all root cert references go through `include_bytes!` of files in `fulcio-roots/`

## Integration tests (verify_dsse_bundle with chain walk)

### T-035-12: Stub cert (used by task 032/033 integration tests) ⇒ UnknownIssuer ⇒ Invalid
- Use a stub leaf cert (not signed by any real CA, as in tests/npm_provenance_integration.rs)
- Call `verify_dsse_bundle` with the stub bundle
- Expected: `VerificationOutcome::Invalid { reason: "Fulcio chain validation failed: ..." }` — the existing 032/033 integration tests must continue to pass because they only assert `Invalid`/`Block`, not the specific reason

### T-035-13: Chain failure messages are distinct from signature failure messages
- Compare error reasons from (a) a cert with an unknown issuer and (b) a cert with a tampered DSSE signature
- Expected: reasons differ — operators can tell chain failures from signature failures

### T-035-14: Real Fulcio-signed bundle smoke test
- Fixture: a real sigstore bundle from a published npm package (document the source — e.g., `sigstore@2.x` from npm, or `@sigstore/bundle` test data). The bundle's leaf is a real Fulcio-signed cert.
- Call `verify_fulcio_chain(real_leaf_der)`
- Expected: `Ok(())` — production trust store accepts a real Fulcio chain

### T-035-15: Real Fulcio bundle from a different package (chain coverage)
- Same as T-035-14 but with a bundle from a different package, ideally one signed under fulcio_v1 (older) vs fulcio_v3 (newer)
- Expected: both `Ok(())` — both root versions in the embedded trust store work

## Regression tests (existing 032/033 behavior preserved)

### T-035-16: All task 032 tests still pass with chain walk active
- Run `cargo test npm_provenance` after task 035 lands
- Expected: 0 failures — stub-cert paths produce `UnknownIssuer ⇒ Invalid` (same outcome as before; only the error message changes)

### T-035-17: All task 033 tests still pass with chain walk active
- Run `cargo test pypi_provenance`
- Expected: 0 failures, same reasoning as T-035-16

## Documentation tests

### T-035-18: Module docstring honestly states the Rekor gap
- Static check: `src/sigstore_verify.rs` module-level docstring mentions that Rekor inclusion proof verification is still NOT performed, with a reference to task 036
- Expected: matching text present

### T-035-19: fulcio-roots/README.md documents rotation procedure
- Static check: `fulcio-roots/README.md` exists, names the TUF source URL, and gives step-by-step retrieval instructions
- Expected: file exists with the documented procedure

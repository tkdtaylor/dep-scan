# Test Spec — Task 036: Rekor inclusion proof verification

## Unit tests (Merkle path verification, RFC 6962 style)

### T-036-01: Single-leaf tree
- Leaf hash = `sha256(0x00 || <leaf-bytes>)` per RFC 6962; root = leaf hash
- Empty audit path
- Expected: verification succeeds

### T-036-02: Two-leaf tree, left position
- Leaves a, b; root = `sha256(0x01 || H(a) || H(b))`
- Verifying leaf a: audit path = `[H(b)]`, index = 0
- Expected: succeeds

### T-036-03: Two-leaf tree, right position
- Same tree; verifying leaf b: audit path = `[H(a)]`, index = 1
- Expected: succeeds

### T-036-04: Deep path (8 leaves)
- Standard RFC 6962 test vector
- Expected: each leaf verifies with its respective audit path

### T-036-05: Tampered intermediate node ⇒ failure
- Valid path but one audit node is altered
- Expected: `RekorError::InclusionProofInvalid`

### T-036-06: Wrong root hash ⇒ failure
- Valid path but the claimed root doesn't match the computed root
- Expected: `RekorError::InclusionProofInvalid`

### T-036-07: Index out of range for tree size ⇒ failure
- index ≥ tree_size
- Expected: `RekorError::MalformedProof`

## Unit tests (Rekor signed tree head)

### T-036-08: Valid Ed25519 signature against pinned key
- Test-only secondary key for fixtures; production key embedded as `const`
- Expected: signature verifies, returned tree head accepted

### T-036-09: Tampered tree-head signature ⇒ failure
- One byte flipped in signature bits
- Expected: `RekorError::TreeHeadSignatureInvalid`

### T-036-10: Signature from a different key ⇒ failure
- Signed by a non-Rekor keypair
- Expected: `RekorError::TreeHeadSignatureInvalid`

### T-036-11: Rekor public key is hardcoded, not runtime-configurable
- Static check: no env, config, or filesystem path reads `REKOR_PUBLIC_KEY`
- Expected: only `include_str!`/`include_bytes!` source

## Unit tests (entry kind handling)

### T-036-12: `dsse` entry kind hash computed correctly
- Build a known DSSE envelope; compute its Rekor entry hash
- Expected: matches sigstore's `cosign verify` output for the same envelope (test vector)

### T-036-13: `hashedrekord` entry kind hash computed correctly
- Similar to T-036-12 but for the older entry kind
- Expected: matches test vector

### T-036-14: Unsupported entry kind ⇒ fail-closed
- Bundle with `entryKind = "intoto"` or some other unrecognized string
- Expected: `RekorError::UnsupportedKind`, NOT silently accepted

## Unit tests (timestamp window vs cert validity)

### T-036-15: `integratedTime` inside `[notBefore, notAfter]` ⇒ accept
- Construct a Fulcio-style cert valid `[T, T+10min]`; Rekor entry `integratedTime = T+5min`
- Expected: timestamp check passes

### T-036-16: `integratedTime` before `notBefore` ⇒ reject
- `integratedTime = T-1s`
- Expected: `RekorError::TimestampBeforeCertValidity`

### T-036-17: `integratedTime` after `notAfter` ⇒ reject
- `integratedTime = T+10min+1s`
- Expected: `RekorError::TimestampAfterCertValidity`

### T-036-18: Replay attack scenario — old timestamp, current verification
- Cert valid `[T, T+10min]`; verification "now" = `T + 1 year`; `integratedTime` = `T+5min`
- Expected: succeeds (this is the whole point — Rekor timestamp proves the cert was alive at signing time even though it's expired now)

## Integration tests (verify_dsse_bundle end-to-end)

### T-036-19: Real Fulcio + Rekor bundle ⇒ end-to-end Pass
- Real sigstore bundle from a public npm package (fixture from task 035, augmented to ensure the Rekor entry is intact)
- Run through full `verify_dsse_bundle`
- Expected: `VerificationOutcome::Valid { subject_identity }` — chain walk + DSSE + Rekor + timestamp all pass

### T-036-20: Bundle with tampered Rekor proof ⇒ Block
- Same bundle as T-036-19 but with one audit-path byte flipped
- Expected: `Invalid { reason: "Rekor verification failed: ..." }`

### T-036-21: Bundle with mismatched Rekor `integratedTime` ⇒ Block
- Hand-craft a bundle with `integratedTime` falling outside the leaf cert's validity window
- Expected: `Invalid { reason: <timestamp-window message> }`

### T-036-22: Stub bundles from 032/033 ⇒ chain walk fails first (regression)
- Stub bundles still produce `Invalid` — but the failure should be `Fulcio chain validation failed` (from task 035), not "Rekor verification failed", because the chain walk runs first
- Expected: existing 032/033 integration tests pass; failure message ordering is preserved

## Regression tests

### T-036-23: All 032 + 033 unit tests still pass with Rekor verification enabled
- Unit tests in `policy::npm_provenance::tests` and `policy::pypi_provenance::tests` use `MockVerifier` and don't reach the Rekor path — they continue to behave as before
- Expected: 0 failures

### T-036-24: Documentation update — ADR 003 and module docstring
- Static check: `src/sigstore_verify.rs` module docstring no longer mentions "Rekor verification is NOT performed" — it now describes the full verification pipeline
- ADR 003's "What this does *not* defend against" section: lying-registry npm and PyPI entries are removed; only the unaddressed threats remain (lying registry without provenance, metadata/bytes inconsistency, local cache DB tampering)
- Expected: matching text present

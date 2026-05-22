# Test Spec — Task 036: Rekor inclusion proof verification

## Re-scoping note (2026-05-22)

Empirical verification against real bundles showed:
- npm provenance uses `(intoto, 0.0.2)` — not `dsse`.
- PyPI provenance uses `(dsse, 0.0.1)`.
- `hashedrekord` is not used by either; removed from supported kinds.
- `AttestationBundle` parser must be extended to carry `tlog_entries`.
- Rekor tree head uses signed-note format (same as Go sumdb in task 034); extracted to shared `src/signed_note.rs`.

T-036-13 changes: `hashedrekord` ⇒ `intoto` v0.0.2. T-036-14 unsupported example: `helm`. New cases added for the parser extension (T-036-25) and intoto payload-binding (T-036-26 / T-036-27).

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

### T-036-13: `intoto` v0.0.2 entry kind hash computed correctly
- Build an intoto v0.0.2 body (the format real npm bundles use); compute its Rekor entry hash
- Expected: matches sigstore/Rekor reference vector for the same envelope

### T-036-14: Unsupported entry kind ⇒ fail-closed
- Bundle with `kindVersion = (helm, 0.0.1)` or any other unrecognized pair
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
- ADR 003's "What this does *not* defend against" section: lying-registry npm and PyPI entries are amended (provenanced packages defended; non-provenanced packages still a gap); only the unaddressed threats remain (lying registry without provenance, metadata/bytes inconsistency, local cache DB tampering)
- Expected: matching text present

## New tests (rescope additions)

### T-036-25: AttestationBundle parsers carry tlog_entries from real JSON
- Two sub-cases:
  - npm: parse a real npm attestations response → `AttestationBundle.tlog_entries` has length 1, with `kind_version = ("intoto", "0.0.2")`, `integrated_time` populated, `inclusion_proof` populated.
  - PyPI: parse a real PEP 740 provenance response → `kind_version = ("dsse", "0.0.1")`.
- Expected: both populate correctly; legacy unit tests (which use empty bundles) continue to pass after the field is added with `tlog_entries: vec![]`.

### T-036-26: intoto v0.0.2 payload binding — payloadHash mismatch ⇒ Block
- Construct an intoto v0.0.2 body whose `spec.content.envelope.payloadHash` does not equal `sha256(decoded_dsse_payload)`.
- Expected: `RekorError::PayloadBindingFailed` with a message naming "payloadHash mismatch".

### T-036-27: intoto v0.0.2 payload binding — envelope hash mismatch ⇒ Block
- Construct an intoto v0.0.2 body whose `spec.content.hash` does not equal `sha256(canonical_dsse)`.
- Expected: `RekorError::PayloadBindingFailed` with a message naming "canonical envelope hash mismatch".

### T-036-28: signed_note module extracted from task 034
- Static check: `src/signed_note.rs` exists with `Verifier` and `verify` exposed publicly.
- `src/policy/go_sumdb.rs` imports from `crate::signed_note` rather than carrying its own parser/verifier.
- Task 034's existing 22 tests (in `go_sumdb` module and `tests/go_sumdb_integration.rs`) continue to pass without modification.

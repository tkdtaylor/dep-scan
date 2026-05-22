# Task 036 — Rekor inclusion proof verification

**Status:** completed
**Depends on:** 032 (npm provenance), 033 (PyPI provenance), 034 (sumdb signed-note primitive — to be extracted for shared use), 035 (Fulcio chain walk)

## Re-scoping note (2026-05-22)

Initial draft assumed Rekor entry kinds `dsse` and `hashedrekord` covered npm + PyPI. Empirical verification by the first executor attempt against 7 real npm bundles and 1 real PyPI bundle showed:

- **npm uses `intoto` v0.0.2** (not `dsse`).
- **PyPI uses `dsse` v0.0.1** (matches the original draft).
- **`hashedrekord`** is not used by either npm or PyPI provenance in practice.

The supported-kinds set is therefore `dsse` v0.0.1 + `intoto` v0.0.2. `hashedrekord` is removed. T-036-14's unsupported-kind example switches to `helm` (Helm chart entries — definitely unrelated to dep-scan's scope, unambiguously unsupported).

The first executor also discovered that `AttestationBundle` (in both `src/registry/npm_attestation.rs` and `src/registry/pypi_provenance.rs`) silently drops the bundle's `tlogEntries` field — necessary input data for this task that isn't currently parsed. Adding it is now explicitly in scope.

The Rekor tree-head signature uses the same **signed-note format** as Go's sumdb. Task 034 already implemented note parsing + Ed25519 verification in `src/policy/go_sumdb.rs`. This task extracts that primitive to a new shared module `src/signed_note.rs` and reuses it for Rekor.

## Objective

Verify that each sigstore-signed attestation was recorded in Rekor's public transparency log at the time of signing, closing the "replay an expired Fulcio cert" gap that remains after task 035. Together, tasks 035 + 036 deliver full sigstore verification semantics.

## Background

A Fulcio leaf cert is valid for ~10 minutes. By verification time it is always expired. Task 035 verifies the cert chains to a trusted Fulcio root but does NOT verify the cert was *valid at the time of signing* — meaning an attacker who somehow obtained a leaked Fulcio cert (or who compromised an OIDC identity briefly) could replay the signed attestation indefinitely.

**Rekor** is sigstore's tamper-evident, append-only transparency log. Every signing event produces a Rekor inclusion proof: a Merkle-tree-based proof that the (cert, signature, payload) tuple was committed to the log at a specific signed tree head. Verifying the inclusion proof — and that the proof's timestamp falls inside the leaf cert's validity window — proves the cert was alive when it signed, even though it's now expired.

The bundle format already includes the Rekor proof in `verificationMaterial.tlogEntries[].inclusionProof` and `inclusionPromise`. We just need to actually use it.

## Behavior

### Data-model prerequisite

`AttestationBundle` currently drops `tlogEntries`. Add a `tlog_entries: Vec<TlogEntry>` field. `TlogEntry` carries:

```rust
pub struct TlogEntry {
    pub log_index: u64,
    pub log_id: String,                  // base64 sha256 of the log's public key
    pub kind_version: KindVersion,       // { kind: String, version: String }
    pub integrated_time: i64,            // unix seconds
    pub canonicalized_body: Vec<u8>,     // base64-decoded "body" — the canonical-JSON entry
    pub inclusion_proof: InclusionProof, // tree size, root hash, hash list, log_index
    pub checkpoint: Option<String>,      // signed-note envelope (Rekor tree head)
}
```

Both `npm_attestation::parse_attestation_response` and `pypi_provenance::parse_provenance_response` populate this from `verificationMaterial.tlogEntries`. Existing tests that constructed `AttestationBundle` literals get updated with `tlog_entries: vec![]`.

### Shared signed-note primitive

Extract task 034's signed-note parsing + Ed25519 verification from `src/policy/go_sumdb.rs` into `src/signed_note.rs` with a verifier API parameterized by `key_name` and `pinned_public_key`. `go_sumdb` and `sigstore_verify` both call into it. Task 034's tests must continue to pass unchanged.

### Verification logic

In `src/sigstore_verify.rs`:

1. Add `verify_rekor_inclusion(bundle: &AttestationBundle, canonical_dsse: &[u8], leaf_cert: &X509Certificate) -> Result<RekorEntry, RekorError>`:
   - Take the first `TlogEntry` from `bundle.tlog_entries` (real bundles have exactly one; reject ≥2 with `RekorError::UnexpectedMultipleEntries`).
   - Validate `kind_version` against the supported-kinds set: `(dsse, 0.0.1)` and `(intoto, 0.0.2)`. Anything else ⇒ `RekorError::UnsupportedKind`.
   - Compute the **entry hash** per Rekor's spec for the given kind:
     - For `dsse` v0.0.1: `sha256(canonicalized_body)` where the body's `spec.envelopeHash.value` already binds the DSSE envelope.
     - For `intoto` v0.0.2: `sha256(canonicalized_body)` where the body's `spec.content.envelope.payloadHash` binds the payload; verify `payloadHash == sha256(decoded_dsse_payload)` and `spec.content.hash == sha256(canonical_dsse)` before accepting.
   - Walk the inclusion proof's Merkle path (RFC 6962): leaf prefix `0x00`, internal-node prefix `0x01`, SHA-256 throughout. Result must equal `inclusion_proof.root_hash`.
   - If `checkpoint` is present, parse it as a signed note using `signed_note::verify` with the pinned Rekor public key and key-hash; reject on signature failure. The note's text lines must include the tree size and root hash matching the `inclusion_proof`.
   - Return `RekorEntry { integrated_time, log_id }`.
2. In `verify_dsse_bundle`, after the chain walk (035) and DSSE signature verification:
   - Call `verify_rekor_inclusion(bundle, canonical_dsse, leaf_cert)`.
   - Compare `RekorEntry.integrated_time` against the leaf cert's `[notBefore, notAfter]` window. Outside ⇒ `Invalid { reason: <timestamp-window message> }`.
   - On any Rekor failure ⇒ `Invalid { reason: format!("Rekor verification failed: {e}") }`.
3. Both npm and PyPI provenance policies inherit this transparently.

## Acceptance criteria

- [x] `src/signed_note.rs` — new shared module with `parse`, `verify_ed25519`, `verify_ecdsa_p256` exposed publicly. Extracted from task 034's `src/policy/go_sumdb.rs` parsing/verification logic. `go_sumdb::verify_signed_note` is now a thin wrapper that delegates to `signed_note::verify_ed25519`; task 034's existing 22/22 tests continue to pass without modification.
- [x] `AttestationBundle` gains `tlog_entries: Vec<TlogEntry>` field. Populated from `verificationMaterial.tlogEntries` by `npm_attestation::parse_attestation_response`; PyPI parser now also handles the **real** PEP 740 shape (`attestation_bundles[].attestations[].verification_material.transparency_entries`). Existing unit tests updated to include `tlog_entries: vec![]` in their literals.
- [x] Rekor public key embedded as `const REKOR_PUBLIC_KEY` from `rekor-roots/rekor.pub` (PEM-encoded ECDSA P-256 SPKI — **NOTE:** the task description specified Ed25519 but the real Rekor signing key is ECDSA P-256; the signed-note format is the same, only the signing algorithm differs). Use `include_str!` matching task 034's pattern. Added `rekor-roots/README.md` documenting source + rotation procedure.
- [x] `verify_rekor_inclusion` function: parses tlog entry, validates kind, verifies intoto / dsse payload binding, walks Merkle inclusion path, verifies signed-note tree head via `signed_note::verify_ecdsa_p256` and cross-checks the embedded tree-size + root-hash against the inclusion proof.
- [x] Merkle path verification: SHA-256-based, RFC 6962-style (leaf prefix `0x00`, internal-node prefix `0x01`); verified against the real production npm + PyPI Rekor proofs (T-036-12 / T-036-13).
- [x] Entry kind support: `(dsse, 0.0.1)` (PyPI) and `(intoto, 0.0.2)` (npm). Anything else ⇒ `RekorError::UnsupportedKind` and fail-closed (Block). T-036-14 uses `helm` as the unsupported example per the rescope.
- [~] For `intoto` v0.0.2: `payloadHash.value` (when present) is verified against `sha256(decoded_dsse_payload)`; the canonical envelope hash binding is enforced **by checking the body's `spec.content.envelope.signatures[*].sig` against the bundle's DSSE signatures byte-for-byte** rather than by recomputing `sha256(canonical_dsse)`. Rekor's own source explicitly documents that the canonical-envelope hash is NOT reproducible client-side (the canonical form inlines server-added public keys), so the signature-bytes comparison is the equivalent verifiable binding. The two error messages remain distinct as required by T-036-26 / T-036-27 ("payloadHash mismatch" vs "canonical envelope hash mismatch").
- [x] Timestamp window check: `integrated_time` must fall within the leaf cert's `[notBefore, notAfter]`. Outside the window ⇒ `Invalid` with a distinct error message (the actual replay defense).
- [x] All failure modes (proof invalid, signed-note signature invalid, kind unsupported, timestamp out of window, payload binding mismatch) produce distinct error messages.
- [x] Pinned Rekor key is the only acceptable signer — no runtime override, no env var. Statically audited by T-036-11.
- [x] Tests: 28/28 spec markers covered.  See `docs/tasks/test-specs/036-rekor-inclusion-proof-test-spec.md` for the per-marker mapping. Integration via the existing `verify_dsse_bundle` pipeline; real-bundle T-036-19 asserts the Rekor sub-step (the wider pipeline still requires task-029-style content-hash inputs which are out of scope for an offline unit test).
- [x] Tasks 032 and 033 acceptance criteria: the implementation-notes section gets a final entry stating Rekor verification is now in place. (Captured in this task file + ADR 003 update; no separate edit needed to 032/033 task files.)
- [x] ADR 003 "What this does *not* defend against" section: the "Consistently-lying registry" entry is amended to reflect that npm + PyPI packages WITH provenance are now fully defended (modulo TUF rotation).  Packages WITHOUT provenance remain a gap.
- [x] `src/sigstore_verify.rs` module docstring: the "Rekor verification is NOT performed" caveat is removed; the docstring now describes the full 6-step pipeline including Rekor inclusion + timestamp window.
- [x] All tests pass (435 passing), `cargo clippy --all-targets --all-features -- -D warnings` clean, `cargo fmt --check` clean.

## Out of scope

- **Online Rekor lookups.** This task verifies offline proofs (already in the bundle). Fetching the Rekor log over HTTP to cross-check is a future task — bundles already carry the inclusion proof, so offline verification is sufficient against an attacker who can't both forge a Merkle proof AND sign a tree head with Rekor's key.
- **CRL / OCSP.** Same as task 035: sigstore's revocation story is the transparency log; if a cert is leaked, the response is "remove from Rekor" which forces consistency proofs that we don't track across scans. A determined attacker with a leaked cert and pre-revocation Rekor inclusion still passes this task. Documented inline.
- **TUF-based key rotation for Rekor.** If sigstore rotates the Rekor key, users need a dep-scan update. Document in `rekor-roots/README.md`.

## Risk notes

- Rekor's `hashedrekord` and `dsse` entry kinds have evolved. Pin the exact entry-kind versions accepted; if sigstore introduces a new kind, dep-scan should fail-closed rather than silently accept.
- Merkle proof verification is implementation-sensitive: a wrong hash function, wrong byte ordering, or off-by-one in the path index produces silent false-positives that pass tests but fail in production. Test against canonical test vectors from RFC 6962 or sigstore's own test corpus.
- The `integratedTime` field's timezone semantics (UTC, seconds since epoch) must match what's compared against `notBefore`/`notAfter` in the X.509 cert.

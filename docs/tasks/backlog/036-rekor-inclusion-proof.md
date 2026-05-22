# Task 036 — Rekor inclusion proof verification

**Status:** backlog
**Depends on:** 032 (npm provenance), 033 (PyPI provenance), 035 (Fulcio chain walk — strongly recommended first)

## Objective

Verify that each sigstore-signed attestation was recorded in Rekor's public transparency log at the time of signing, closing the "replay an expired Fulcio cert" gap that remains after task 035. Together, tasks 035 + 036 deliver full sigstore verification semantics.

## Background

A Fulcio leaf cert is valid for ~10 minutes. By verification time it is always expired. Task 035 verifies the cert chains to a trusted Fulcio root but does NOT verify the cert was *valid at the time of signing* — meaning an attacker who somehow obtained a leaked Fulcio cert (or who compromised an OIDC identity briefly) could replay the signed attestation indefinitely.

**Rekor** is sigstore's tamper-evident, append-only transparency log. Every signing event produces a Rekor inclusion proof: a Merkle-tree-based proof that the (cert, signature, payload) tuple was committed to the log at a specific signed tree head. Verifying the inclusion proof — and that the proof's timestamp falls inside the leaf cert's validity window — proves the cert was alive when it signed, even though it's now expired.

The bundle format already includes the Rekor proof in `verificationMaterial.tlogEntries[].inclusionProof` and `inclusionPromise`. We just need to actually use it.

## Behavior

In `src/sigstore_verify.rs`:

1. Add `verify_rekor_inclusion(bundle: &AttestationBundle, signed_payload: &[u8]) -> Result<RekorEntry, RekorError>`:
   - Parse the bundle's `verificationMaterial.tlogEntries[0]`.
   - Compute the expected Rekor entry hash from the DSSE envelope + leaf cert (per Rekor's `hashedrekord` or `dsse` entry kind specification).
   - Verify the inclusion proof: walk the Merkle path from the entry hash to the signed tree head's root hash. Each hop is a SHA-256 of `(left || right)`.
   - Verify the signed tree head's Ed25519 signature against the **pinned Rekor public key** (similar pattern to task 034's sumdb key — embed as a `const &str` from sigstore's TUF repository).
   - Extract `integratedTime` from the entry. Return it in `RekorEntry`.
2. In `verify_dsse_bundle`, after the chain walk (035) and DSSE signature verification:
   - Call `verify_rekor_inclusion(bundle, signed_payload)`.
   - Compare `RekorEntry.integratedTime` against the leaf cert's validity window (from task 035's parsed cert). If `integratedTime` is outside `[not_before, not_after]`, return `Invalid { reason: "Rekor entry timestamp falls outside Fulcio cert validity window" }`.
   - On any Rekor verification failure ⇒ `Invalid { reason: format!("Rekor verification failed: {e}") }`.
3. Both npm and PyPI provenance policies inherit this transparently.

## Acceptance criteria

- [ ] Rekor Ed25519 public key embedded as `const REKOR_PUBLIC_KEY` from `rekor-roots/rekor.pub` (source documented). Use `include_str!` matching task 034's pattern.
- [ ] `verify_rekor_inclusion` function: parses tlog entry, computes entry hash, verifies Merkle inclusion, verifies signed tree head signature.
- [ ] Merkle path verification: SHA-256-based, RFC 6962-style; tested against the canonical empty / single-leaf / two-leaf trees with known root hashes.
- [ ] Entry hash computation supports both `hashedrekord` and `dsse` entry kinds. npm and PyPI use `dsse`; older attestations may use `hashedrekord`. If a bundle uses an unsupported kind ⇒ `RekorError::UnsupportedKind` and fail-closed (Block).
- [ ] Timestamp window check: `integratedTime` must fall within the leaf cert's `notBefore..notAfter`. Outside the window ⇒ `Invalid` (this is the actual replay defense).
- [ ] All failure modes (proof invalid, tree head signature invalid, kind unsupported, timestamp out of window) produce distinct error messages.
- [ ] Pinned Rekor key is the only acceptable signer — no runtime override, no env var.
- [ ] Tests:
  - Unit: Merkle path verifier — empty tree, single leaf, two leaves, deep path, tampered intermediate hash, wrong root hash.
  - Unit: tree-head signature — valid, tampered, wrong key.
  - Unit: timestamp window — inside window ⇒ OK; before `notBefore` ⇒ fail; after `notAfter` ⇒ fail.
  - Unit: unsupported entry kind ⇒ `UnsupportedKind` error.
  - Integration: real sigstore bundle (re-use the fixture from task 035) — full chain walk + DSSE + Rekor passes end-to-end.
  - Integration: bundle with tampered Rekor inclusion proof ⇒ Block; existing 032/033 tests with stub bundles continue to produce `Invalid` (now for "Rekor verification failed" reason once the chain walk passes; for stubs the chain walk will fail first, so the message is still chain-related).
- [ ] Tasks 032 and 033 acceptance criteria for "broken chain ⇒ Block" are now fully closed — the lying-registry threat for npm and PyPI is fully defended (modulo the deferred TUF root rotation question).
- [ ] All tests pass, `cargo clippy` clean, `cargo fmt --check` clean.

## Out of scope

- **Online Rekor lookups.** This task verifies offline proofs (already in the bundle). Fetching the Rekor log over HTTP to cross-check is a future task — bundles already carry the inclusion proof, so offline verification is sufficient against an attacker who can't both forge a Merkle proof AND sign a tree head with Rekor's key.
- **CRL / OCSP.** Same as task 035: sigstore's revocation story is the transparency log; if a cert is leaked, the response is "remove from Rekor" which forces consistency proofs that we don't track across scans. A determined attacker with a leaked cert and pre-revocation Rekor inclusion still passes this task. Documented inline.
- **TUF-based key rotation for Rekor.** If sigstore rotates the Rekor key, users need a dep-scan update. Document in `rekor-roots/README.md`.

## Risk notes

- Rekor's `hashedrekord` and `dsse` entry kinds have evolved. Pin the exact entry-kind versions accepted; if sigstore introduces a new kind, dep-scan should fail-closed rather than silently accept.
- Merkle proof verification is implementation-sensitive: a wrong hash function, wrong byte ordering, or off-by-one in the path index produces silent false-positives that pass tests but fail in production. Test against canonical test vectors from RFC 6962 or sigstore's own test corpus.
- The `integratedTime` field's timezone semantics (UTC, seconds since epoch) must match what's compared against `notBefore`/`notAfter` in the X.509 cert.

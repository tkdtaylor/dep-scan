# Task 043 — Signed-note multi-signature iteration for key rotation

**Status:** backlog
**Depends on:** 036 (Rekor inclusion proof), 034 (Go sumdb signature verification)
**Security finding:** M-7 (MEDIUM — highest-value MEDIUM)
**Touches:** `src/signed_note.rs`

## Objective

Fix `verify_ed25519` and `verify_ecdsa_p256` so that a key-id mismatch on one
signature line causes the verifier to try the next line rather than returning
`Invalid` immediately.  This prevents false rejection of legitimate Rekor
bundles during key-rotation events, when a signed note may carry both an
old-key signature and a new-key signature for the same key name.

## Background

The current loop body in both verifiers contains:

```rust
if sig.key_id != expected_key_id {
    return NoteVerifyOutcome::Invalid { reason: format!("...") };
}
```

This `return` exits on the first mismatching key-id.  If the pinned key is the
second signature line, verification always fails even though the note is valid.

The format is specifically designed to allow multiple signers (key rotation,
multi-party signing).  Returning `Invalid` on the first mismatch rather than
continuing is a protocol violation.

## Behavior

Replace the early `return` with `continue` in both `verify_ed25519` and
`verify_ecdsa_p256`:

```rust
if sig.key_id != expected_key_id {
    continue; // try next signature line
}
```

Return `NoteVerifyOutcome::Invalid { reason: "no signature line found for key '...'" }`
only after the loop has exhausted all lines without finding one that verifies.

Additionally, if a line's key-id matches but the cryptographic verification
fails (e.g. bad DER, signature mismatch), continue iterating rather than
returning immediately, to handle the edge case where two lines share a key-id
but only one has a valid signature (unusual but not forbidden by the format).

## Requirements

- **REQ-043-01:** When a signature line's key-id does not match the pinned
  key's expected key-id, `verify_ed25519` continues to the next line rather
  than returning `Invalid`.
- **REQ-043-02:** When a signature line's key-id does not match the pinned
  key's expected key-id, `verify_ecdsa_p256` continues to the next line rather
  than returning `Invalid`.
- **REQ-043-03:** A note with two signature lines for the same key name, where
  the first line was signed by the old (non-pinned) key and the second by the
  pinned key, returns `Valid`.
- **REQ-043-04:** A note where no signature line's key-id matches the pinned
  key returns `Invalid` with a message indicating no matching line was found.
- **REQ-043-05:** Existing single-signature behavior (tasks 034 and 036 test
  vectors) is unaffected.

## Acceptance criteria

- [ ] `verify_ed25519`: key-id mismatch uses `continue`, not `return` (REQ-043-01); verified by T-043-14.
- [ ] `verify_ecdsa_p256`: key-id mismatch uses `continue`, not `return` (REQ-043-02); verified by T-043-14.
- [ ] Two-line note, old key first: `Valid` for `verify_ed25519` (REQ-043-03); verified by T-043-03.
- [ ] Two-line note, old key first: `Valid` for `verify_ecdsa_p256` (REQ-043-03); verified by T-043-10.
- [ ] No matching key-id on any line: `Invalid` (REQ-043-04); verified by T-043-05, T-043-11.
- [ ] Existing sumdb and Rekor test cases still pass (REQ-043-05); verified by T-043-08, T-043-13.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Changing the key-rotation procedure itself (which requires a dep-scan release).
- Supporting multi-party signed notes where different key names are present.
- Modifying `parse()` — it already returns all signature lines; only the loop
  logic in the two verifiers needs to change.

## Risk notes

- The change is two-line in each function: one `return` becomes `continue`.
  Risk of regression is low; the existing test suite covers all single-signature
  paths.
- A note that has both a valid old-key signature and an invalid new-key
  signature (e.g. corrupted new-key bytes) will correctly return `Valid` because
  the old-key line's key-id won't match the pinned new-key id and will be
  skipped.  This is the desired behavior.

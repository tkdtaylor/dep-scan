# Test Spec — Task 043: Signed-note multi-signature iteration for key rotation

## Context

`verify_ed25519` and `verify_ecdsa_p256` in `src/signed_note.rs` iterate over
signature lines but return `Invalid` immediately when a line's key-id does not
match the pinned key-id.  During a key-rotation event, a signed note may carry
two signature lines for the same key name — one from the old key and one from
the new key.  If the old key's line appears first, the verifier rejects the
whole note even though the second line would verify correctly against the pinned
key.

The fix: on a key-id mismatch, `continue` to the next line rather than
returning `Invalid`.  Return `Invalid` only after exhausting all lines without
finding one that verifies.

---

## Unit tests — `verify_ed25519`

### T-043-01: Single signature, correct key, verifies
- Build a signed note signed with key K1.
- Call `verify_ed25519(note, key_str_K1)`.
- Expected: `NoteVerifyOutcome::Valid`.

### T-043-02: Single signature, wrong key name, returns Invalid
- Build a signed note signed with key K1.
- Call `verify_ed25519(note, key_str_K2)` where K2 has a different name.
- Expected: `NoteVerifyOutcome::Invalid` with reason containing "no signature line found".

### T-043-03: Two signature lines — old key first, new key second; pinned key is new key — verifies
- Build a signed note with two signature lines:
    - line 1: key_name = `"sum.golang.org"`, signed with K_old (key-id differs from pinned K_new)
    - line 2: key_name = `"sum.golang.org"`, signed with K_new (the pinned key)
- Call `verify_ed25519(note, key_str_K_new)`.
- Expected: `NoteVerifyOutcome::Valid` — the verifier must not short-circuit on line 1's key-id mismatch.

### T-043-04: Two signature lines — new key first, old key second; pinned key is new key — verifies
- Same as T-043-03 but with line order swapped.
- Expected: `NoteVerifyOutcome::Valid`.

### T-043-05: Two signature lines for the same key name, both with wrong key-ids — returns Invalid
- Build a signed note with two signature lines for `"sum.golang.org"`, both signed with keys that differ from the pinned key.
- Expected: `NoteVerifyOutcome::Invalid` with reason containing "no signature line found" or a key-id mismatch message — NOT a panic or crash.

### T-043-06: Two signature lines — correct key-id on first line but bad signature bytes — continues and finds valid second line
- Build a note with:
    - line 1: key_name matches, key-id matches pinned key, but sig_bytes are garbage (fail cryptographic check)
    - line 2: key_name matches, key-id matches, valid signature
- Expected: `NoteVerifyOutcome::Valid` — verifier continues past cryptographic failure on line 1.

### T-043-07: Wrong key-name on all lines — returns Invalid
- Build a note signed with key `"other.registry.dev"`.
- Call `verify_ed25519(note, "sum.golang.org+<hex>+<b64>")`.
- Expected: `NoteVerifyOutcome::Invalid` with reason "no signature line found for key 'sum.golang.org'".

### T-043-08: Regression — existing T-034-06, T-034-07, T-034-08 behavior is preserved
- Single-signature happy path (valid key) → `Valid`.
- Single-signature tampered sig → `Invalid`.
- Single-signature wrong key → `Invalid`.
- Run the existing go_sumdb tests to confirm no regression: `cargo test go_sumdb`.

---

## Unit tests — `verify_ecdsa_p256`

### T-043-09: Single signature, correct ECDSA P-256 key, verifies
- Build a signed note signed with ECDSA key K1.
- Call `verify_ecdsa_p256(note, "rekor.sigstore.dev", pem_K1)`.
- Expected: `NoteVerifyOutcome::Valid`.

### T-043-10: Two signature lines — old Rekor key first, new Rekor key second; pinned key is new key — verifies
- Build a note with two signature lines both named `"rekor.sigstore.dev"`:
    - line 1: signed with K_old ECDSA key (key-id will not match K_new's SHA-256(SPKI)[:4])
    - line 2: signed with K_new ECDSA key (the pinned key)
- Call `verify_ecdsa_p256(note, "rekor.sigstore.dev", pem_K_new)`.
- Expected: `NoteVerifyOutcome::Valid`.

### T-043-11: Two signature lines — both with wrong key-ids — returns Invalid
- Build a note with two lines, both key-ids mismatch the pinned key.
- Expected: `NoteVerifyOutcome::Invalid`.

### T-043-12: Two signature lines — correct key-id, bad DER bytes on first; valid second line — verifies
- line 1: key-id matches, `sig_bytes` is not valid DER (P256Signature::from_der fails)
- line 2: key-id matches, valid DER signature
- Expected: `NoteVerifyOutcome::Valid`.

### T-043-13: Regression — existing T-036-08, T-036-09, T-036-10 behavior is preserved
- Single-signature happy path → `Valid`.
- Tampered signature → `Invalid`.
- Wrong key → `Invalid`.
- Run: `cargo test rekor` or `cargo test signed_note`.

---

## Static / structural checks

### T-043-14: Neither `verify_ed25519` nor `verify_ecdsa_p256` contains an early `return` inside the key-id mismatch branch
- Code review assertion: the `if sig.key_id != expected_key_id` block uses `continue` (or equivalent), not `return NoteVerifyOutcome::Invalid`.
- This is the exact defect described in the finding; verifiable by reading `src/signed_note.rs`.

### T-043-15: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass
- No compilation errors or lint warnings introduced by the change.

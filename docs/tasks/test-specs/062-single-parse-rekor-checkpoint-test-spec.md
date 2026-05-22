# Test Spec — Task 062: Single-parse refactor for `verify_rekor_checkpoint_impl` (N-L-4)

## Context

`verify_rekor_checkpoint_impl` in `src/sigstore_verify.rs` currently parses the
signed-note envelope twice:

1. Inside `signed_note::verify_ecdsa_p256`, which calls `signed_note::parse`
   internally to find and verify the signature.
2. Immediately after, in an explicit `signed_note::parse(envelope)` call to
   extract the note text for tree-size / root-hash validation.

The duplication is bounded by checkpoint size (a few hundred bytes) and is not
a security issue, but it violates the "parse once" principle and complicates
future changes to the parser.

The fix changes `verify_ecdsa_p256` to return `Result<ParsedNote, NoteVerifyOutcome>`
(or an analogous shape), so the caller in `verify_rekor_checkpoint_impl` can
reuse the `ParsedNote.note_text` directly without a second parse call.

---

## Unit tests — refactored `verify_ecdsa_p256` signature

### T-062-01: `verify_ecdsa_p256` returns `Ok(ParsedNote)` on successful verification
- Input: a synthetic Rekor checkpoint envelope signed with the pinned Rekor
  ECDSA P-256 key (or a test key used in existing task-036 fixtures).
- Expected: returns `Ok(parsed)` where `parsed.note_text` is non-empty and
  `parsed.signatures` is non-empty.

### T-062-02: `verify_ecdsa_p256` returns `Err(NoteVerifyOutcome::Invalid)` on key-name mismatch
- Input: a valid envelope but `expected_key_name` does not match the signature
  line's key name.
- Expected: `Err(NoteVerifyOutcome::Invalid { reason: _ })`.

### T-062-03: `verify_ecdsa_p256` returns `Err(NoteVerifyOutcome::Invalid)` on bad signature bytes
- Input: a syntactically valid envelope whose signature bytes are corrupted (e.g.
  all-zero).
- Expected: `Err(NoteVerifyOutcome::Invalid { reason: _ })`.

### T-062-04: `verify_ecdsa_p256` returns `Err(NoteVerifyOutcome::Invalid)` on malformed PEM key
- Input: `pem_pubkey` is a garbage string, not a valid PEM-encoded key.
- Expected: `Err(NoteVerifyOutcome::Invalid { reason: _ })` containing a
  message about key parsing failure.

### T-062-05: `verify_ecdsa_p256` returns `Err(NoteVerifyOutcome::Invalid)` when `parse` fails
- Input: an envelope with no em-dash line (structurally invalid signed note).
- Expected: `Err(NoteVerifyOutcome::Invalid { reason: _ })` containing the
  parse error from `signed_note::parse`.

---

## Unit tests — `verify_rekor_checkpoint_impl` uses parsed note directly

### T-062-06: `verify_rekor_checkpoint_impl` does not call `signed_note::parse` a second time
- Code review assertion: after the refactor, `verify_rekor_checkpoint_impl` does
  not contain a second `signed_note::parse(envelope)` call (or any other
  invocation of `parse` on the same envelope after `verify_ecdsa_p256` has
  already called it).
- Verifiable by reading the function body: the `ParsedNote` returned from
  `verify_ecdsa_p256` is used to extract `note_text`.

### T-062-07: `verify_rekor_checkpoint_impl` extracts tree_size from the returned `ParsedNote`
- Arrange: a valid Rekor checkpoint fixture with known `tree_size` and
  `root_hash_b64` values.
- Call `verify_rekor_checkpoint_impl` with a matching `InclusionProof`.
- Expected: returns `Ok(())` — the tree size and root hash are extracted from
  the `ParsedNote` returned by `verify_ecdsa_p256`, not from a separate parse.

### T-062-08: `verify_rekor_checkpoint_impl` propagates tree-size mismatch correctly
- Arrange: same fixture as T-062-07 but with an `InclusionProof.tree_size` that
  differs from the checkpoint's `tree_size` field.
- Expected: `Err(RekorError::TreeHeadSignatureInvalid(_))` containing
  `"tree-size mismatch"`.

### T-062-09: `verify_rekor_checkpoint_impl` propagates root-hash mismatch correctly
- Arrange: valid checkpoint, `InclusionProof.root_hash_b64` does not match the
  checkpoint.
- Expected: `Err(RekorError::TreeHeadSignatureInvalid(_))` containing
  `"root-hash mismatch"`.

---

## Unit tests — behavioral equivalence with pre-refactor

### T-062-10: All existing task 036 Rekor checkpoint test vectors produce the same outcome after refactor
- For each fixture in the task-036 test suite that exercises
  `verify_rekor_checkpoint_impl` (T-036-08 through T-036-10 and any related
  tests), assert that the refactored code returns the identical pass/fail result
  as the current code.
- Implementation note: run `cargo test rekor` before and after the refactor;
  zero failures in both runs is sufficient.

### T-062-11: All existing task 044 signed-note parser tests produce the same outcome
- `verify_ecdsa_p256` still calls `parse` internally; T-044-01 through T-044-17
  must pass without modification.
- Run `cargo test signed_note`.

---

## Unit tests — optional Ed25519 symmetry (nice-to-have)

### T-062-12 (optional): `verify_ed25519` returns `Ok(ParsedNote)` on success
- If the implementer also refactors `verify_ed25519` for symmetry, assert the
  same shape: `Ok(ParsedNote)` on success, `Err(NoteVerifyOutcome::Invalid)` on
  any failure.
- This is explicitly optional — the Go sumdb call site (`policy/go_sumdb.rs`)
  does not need the `ParsedNote` today, so the refactor may be skipped for
  `verify_ed25519` if it would widen the blast radius.

---

## Regression tests

### T-062-13: All task 036 Rekor inclusion-proof tests still pass
- Run `cargo test rekor`.
- Expected: 0 failures.

### T-062-14: All task 043 multi-sig iteration tests still pass
- Run `cargo test signed_note`.
- Expected: 0 failures.

### T-062-15: All task 034 Go sumdb tests still pass
- Run `cargo test go_sumdb` or equivalent.
- Expected: 0 failures — if `verify_ed25519` is left unchanged (T-062-12
  optional), its callers must not be broken.

### T-062-16: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` all pass.

# Task 062 — Single-parse refactor for `verify_rekor_checkpoint_impl` (N-L-4)

**Status:** backlog
**Depends on:** 034 (Go sumdb), 036 (Rekor inclusion proof), 043 (multi-sig iteration), 044 (em-dash boundary parser)
**Security finding:** N-L-4 (LOW — mild inefficiency, not a security issue)
**Touches:** `src/signed_note.rs`, `src/sigstore_verify.rs`

## Objective

Refactor `verify_ecdsa_p256` in `src/signed_note.rs` to return
`Result<ParsedNote, NoteVerifyOutcome>` so that `verify_rekor_checkpoint_impl`
in `src/sigstore_verify.rs` can reuse the parsed note for tree-size / root-hash
extraction without calling `signed_note::parse` a second time.

## Background

The current implementation:

```rust
// verify_rekor_checkpoint_impl:
match signed_note::verify_ecdsa_p256(envelope, key_name, pem_pubkey) {
    NoteVerifyOutcome::Valid => {}
    NoteVerifyOutcome::Invalid { reason } => { return Err(...); }
}
// Second parse — redundant:
let parsed = signed_note::parse(envelope).map_err(RekorError::TreeHeadSignatureInvalid)?;
let lines: Vec<&str> = parsed.note_text.lines().collect();
```

`verify_ecdsa_p256` already calls `signed_note::parse` internally (line 341 of
`signed_note.rs`).  The second call is bounded by checkpoint size (a few hundred
bytes) and cannot cause data corruption, but it duplicates work and obscures the
intent that the parse result is already available.

## New `verify_ecdsa_p256` return type

Change:

```rust
pub fn verify_ecdsa_p256(
    signed_note: &str,
    expected_key_name: &str,
    pem_pubkey: &str,
) -> NoteVerifyOutcome
```

To:

```rust
pub fn verify_ecdsa_p256(
    signed_note: &str,
    expected_key_name: &str,
    pem_pubkey: &str,
) -> Result<ParsedNote<'_>, NoteVerifyOutcome>
```

All existing failure paths return `Err(NoteVerifyOutcome::Invalid { reason })`.
The success path returns `Ok(parsed)` where `parsed` is the `ParsedNote` from
the internal `signed_note::parse` call.

## Updated call site in `verify_rekor_checkpoint_impl`

```rust
let parsed = signed_note::verify_ecdsa_p256(envelope, key_name, pem_pubkey)
    .map_err(|o| match o {
        NoteVerifyOutcome::Invalid { reason } => RekorError::TreeHeadSignatureInvalid(reason),
        NoteVerifyOutcome::Valid => unreachable!("Ok variant returned as Err"),
    })?;
let lines: Vec<&str> = parsed.note_text.lines().collect();
```

The `NoteVerifyOutcome::Valid` arm in the `map_err` is unreachable given the new
return type (success returns `Ok`), but the `match` must be exhaustive.  An
`unreachable!()` macro is appropriate there.

## Ed25519 symmetry (optional)

`verify_ed25519` could receive the same treatment for consistency, but the only
call site (`policy/go_sumdb.rs`) does not use the returned `ParsedNote`, so the
refactor is optional and should not be done if it widens the change surface
unnecessarily.  The task file leaves this as an implementer decision.

## Requirements

- **REQ-062-01:** `verify_ecdsa_p256` returns `Ok(ParsedNote)` on successful
  verification and `Err(NoteVerifyOutcome::Invalid)` on all failure paths.
- **REQ-062-02:** `verify_rekor_checkpoint_impl` uses the `ParsedNote` from
  `verify_ecdsa_p256` to extract note text without a second `parse` call.
- **REQ-062-03:** All existing task-036 Rekor checkpoint fixtures produce the
  same pass/fail result after the refactor.
- **REQ-062-04:** All task-043 multi-sig, task-044 boundary-parser, and task-034
  Go sumdb tests pass without modification.
- **REQ-062-05:** No behavior change is observable by callers — the refactor is
  internal to the two touched modules.

## Acceptance criteria

- [ ] `verify_ecdsa_p256` returns `Ok(ParsedNote)` on the happy path (REQ-062-01);
  T-062-01.
- [ ] All failure modes return `Err(NoteVerifyOutcome::Invalid)` (REQ-062-01);
  T-062-02, T-062-03, T-062-04, T-062-05.
- [ ] No second `parse` call in `verify_rekor_checkpoint_impl` (REQ-062-02);
  T-062-06.
- [ ] Tree-size and root-hash extracted from `ParsedNote` (REQ-062-02); T-062-07.
- [ ] Tree-size mismatch error still produced (REQ-062-03); T-062-08.
- [ ] Root-hash mismatch error still produced (REQ-062-03); T-062-09.
- [ ] Task 036 regression suite passes (REQ-062-03); T-062-10, T-062-13.
- [ ] Task 044 and 043 suites pass (REQ-062-04); T-062-11, T-062-14.
- [ ] Task 034 Go sumdb suite passes (REQ-062-04); T-062-15.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` pass.

## Out of scope

- Refactoring `verify_ed25519` (optional; see T-062-12).
- Changing the `NoteVerifyOutcome` enum — the `Valid`/`Invalid` shape is shared
  by other callers and must not be modified.
- Any performance measurement or benchmarking — the checkpoint is small; the
  saving is cosmetic.

## Risk notes

- Changing `verify_ecdsa_p256`'s return type is a public-API change within the
  crate.  Check all call sites (currently: `verify_rekor_checkpoint_impl` is the
  only caller in production code; tests may call it directly).  All call sites
  must be updated.
- The lifetime `'_` on `ParsedNote<'_>` is tied to the `signed_note: &str`
  input.  Callers that previously received `NoteVerifyOutcome` (a value type)
  and then called `parse` separately may need lifetime adjustments.
- If the refactor is too invasive due to lifetime issues, an alternative is to
  return `(NoteVerifyOutcome, Option<OwnedParsedNote>)` where `OwnedParsedNote`
  stores `String` copies of the fields.  Document the chosen approach in a
  source comment.

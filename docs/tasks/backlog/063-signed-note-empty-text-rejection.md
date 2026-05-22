# Task 063 — Reject empty note_text in `signed_note::parse` (N-L-5)

**Status:** backlog
**Depends on:** 043 (signed-note multi-sig iteration), 044 (em-dash boundary parser)
**Security finding:** N-L-5 (LOW — structural invariant not enforced at parse time)
**Touches:** `src/signed_note.rs` only

## Objective

Return `Err` from `signed_note::parse` when the computed `note_text` slice is
empty, enforcing the invariant that a valid signed note must contain at least one
byte of text before the signature block.

## Background

`parse` slices `note_text` as `&signed_note[..em_dash_offset - 1]`.  For the
envelope `"\n— key b64sig"` the em-dash is at byte offset 1, so the slice is
`&signed_note[..0]` — an empty `&str`.  The existing code returns `Ok(ParsedNote
{ note_text: "", … })` for this input.

Subsequent callers pass `note_text` to signature verifiers.  The Ed25519 and
ECDSA-P256 paths sign over the note text; no real key should produce a valid
signature over the empty byte string.  So the gap does not lead to a successful
forgery.  However:

1. The structural invariant ("a well-formed note has text") is a precondition
   documented in the format spec, and should be enforced at parse time so
   callers can rely on it.
2. Future callers that inspect `note_text` without first checking for emptiness
   could misbehave.

The fix is a single early-return guard added after computing `note_text`.

## Behavior

In `signed_note::parse`, immediately after the line:

```rust
let note_text = &signed_note[..em_dash_offset - 1];
```

add:

```rust
if note_text.is_empty() {
    return Err("signed note has empty note_text".to_string());
}
```

(Or use a `ParseError::EmptyNoteText` enum variant if the function's error type
is upgraded to a proper `enum`.  Either approach is acceptable — the requirement
is that the error is distinct from the existing "no signature lines" / "missing
blank-line separator" messages.)

## Requirements

- **REQ-063-01:** `parse` returns `Err` when `note_text` is empty (zero bytes)
  after slicing.
- **REQ-063-02:** The error message or variant is distinct from existing parse
  errors; it contains `"empty"` or is named `EmptyNoteText`.
- **REQ-063-03:** Non-empty `note_text` (even a single byte) continues to parse
  normally.
- **REQ-063-04:** All task 044 boundary-parser and task 043 multi-sig tests pass
  without modification.
- **REQ-063-05:** The empty-text check runs before the signature iteration loop.

## Acceptance criteria

- [ ] `parse("\n— key b64")` returns `Err(_)` (REQ-063-01); T-063-01, T-063-02.
- [ ] `parse("\n\n— key b64")` (one-newline note_text) returns `Ok(_)` (REQ-063-03);
  T-063-03.
- [ ] Normal Rekor and sumdb fixtures parse cleanly (REQ-063-03); T-063-04,
  T-063-05.
- [ ] Error message contains `"empty"` (REQ-063-02); T-063-09.
- [ ] Check placed before signature loop (REQ-063-05); T-063-08.
- [ ] `verify_rekor_checkpoint_impl` propagates the error (REQ-063-01); T-063-12.
- [ ] Task 044 and 043 regression suites pass (REQ-063-04); T-063-10, T-063-11.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` pass.

## Out of scope

- Upgrading the error type to a proper `enum` — acceptable if the implementer
  chooses it for consistency, but not required for this task.
- Rejecting notes whose text is only whitespace — the invariant is "at least one
  byte", not "at least one printable character".

## Risk notes

- This is a one-line guard inside a pure parsing function.  Risk of regression
  is low; the existing test suite covers all non-empty shapes.
- The only realistic way this guard fires in production is if a third party sends
  a deliberately malformed signed-note envelope.  Failing closed (returning `Err`)
  is the correct response.

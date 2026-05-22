# Test Spec — Task 063: Reject empty note_text in `signed_note::parse` (N-L-5)

## Context

`signed_note::parse` in `src/signed_note.rs` walks lines to find the first
em-dash line and slices `signed_note[..em_dash_offset - 1]` as `note_text`.
For an envelope of the shape `"\n— key b64sig"` the leading blank line sets
`prev_was_blank = true`, the em-dash matches at byte offset 1, and the slice
becomes `&signed_note[..0]` — an empty string.  The structural invariant "a
valid signed note has at least one byte of text before the signature block"
is not enforced at parse time.

Subsequent crypto verification will fail-closed (no real key signs empty bytes),
so the gap is not exploitable today.  The fix adds an explicit early-return
`Err(ParseError::EmptyNoteText)` — or the equivalent string error — when
`note_text.is_empty()` after slicing, enforcing the invariant structurally.

---

## Unit tests — empty `note_text` rejection

### T-063-01: `parse("\n— key b64sig")` returns `Err` with an empty-note message
- Input: the string `"\n— rekor.sigstore.dev AAAAAAAAAAAABBBBBBBBBB=="` where the
  leading `\n` is the sole content before the blank-line separator.
- Expected: `Err(e)` where `e` (or `e.to_string()`) contains `"empty"` or
  `"note_text"`.

### T-063-02: `parse("\n— k b64")` with a minimal one-character key name returns `Err`
- Input: `"\n— k AAEC"` (one-character key, four bytes of base64).
- Expected: `Err(_)` — any input producing zero-byte `note_text` is rejected
  regardless of signature-line contents.

### T-063-03: `parse("\n\n— key b64")` (two leading newlines, still empty text) returns `Err`
- Input: two blank lines before the em-dash line; `note_text` would be `"\n"` (a
  single newline), which is non-empty.
- Expected: `Ok(parsed)` where `parsed.note_text == "\n"`.
- Rationale: a single newline is one byte of text — not empty.  Only the
  truly-zero-byte case is rejected.

### T-063-04: `parse` of a normal Rekor checkpoint still succeeds
- Input: a realistic Rekor signed-note fixture with non-empty note text (e.g.
  three-line `origin\ntree_size\nroot_hash` body).
- Expected: `Ok(parsed)` with non-empty `note_text`.

### T-063-05: `parse` of a normal sumdb tree-head still succeeds
- Input: a realistic `sum.golang.org` signed-note fixture.
- Expected: `Ok(parsed)` with non-empty `note_text`.

### T-063-06: `parse` returns `Err` for a note whose text is exactly one space character
- Input: `" \n\n— key b64sig"` — `note_text` would be `" "` (one space), which
  is non-empty.
- Expected: `Ok(parsed)` — a single space is not empty; the rejection only applies
  to zero bytes.

### T-063-07: `parse` rejects `"\n— k b64"` even if the base64 is a valid real signature
- Input: same shape as T-063-01, but with a syntactically valid (well-formed)
  base64 payload that decodes to 5+ bytes.
- Expected: `Err(_)` — the empty-text check runs before signature parsing, so
  an otherwise valid signature does not rescue a structurally invalid envelope.

---

## Unit tests — structural / implementation check

### T-063-08: The empty-text check is placed between the `note_text` slice and the signature loop
- Code review assertion: the `note_text.is_empty()` check (or equivalent) in
  `parse` appears after computing `note_text` but before iterating over the
  signature section.
- Verifiable by reading the function body.

### T-063-09: `ParseError::EmptyNoteText` (or an equivalent error message string) is used
- The error returned for zero-byte note text must be distinct from the existing
  `"signed note has no signature lines"` and `"signed note missing blank-line
  separator before signatures"` messages, so callers can distinguish the failure
  mode.
- Expected: the error string contains `"empty"` or a variant named `EmptyNoteText`.

---

## Regression tests

### T-063-10: All task 044 boundary-parser tests still pass
- Run `cargo test signed_note`.
- Expected: 0 failures — T-044-01 through T-044-17 must all continue to pass.

### T-063-11: All task 043 multi-sig iteration tests still pass
- Run `cargo test signed_note`.
- Expected: 0 failures — T-043-01 through T-043-15 must all continue to pass.

### T-063-12: `verify_rekor_checkpoint_impl` with the empty-body fixture propagates the new error
- Arrange: construct a signed-note envelope with empty body and a valid-looking
  ECDSA-P256 signature line.
- Call `verify_rekor_checkpoint_impl` (or `verify_rekor_inclusion_proof` at the
  appropriate level).
- Expected: the call returns `Err(_)` containing `"empty"` — the error from
  `parse` surfaces all the way up rather than being swallowed.

### T-063-13: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` all pass.

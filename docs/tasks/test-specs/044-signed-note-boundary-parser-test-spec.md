# Test Spec — Task 044: Signed-note boundary parser — em-dash walk replaces rfind

## Context

`signed_note::parse` and `sigstore_verify::verify_rekor_checkpoint` both use
`rfind("\n\n")` to locate the boundary between the note text and the signature
section.  The signed-note format specifies that signature lines begin with an
em-dash (`—`, U+2014).  Using `rfind("\n\n")` is brittle: if the note text
itself contains a blank line (two consecutive newlines), the split occurs at the
wrong place — the signature region is included in `note_text` and the tree-size
/ root-hash extraction reads from the wrong lines.

The fix: walk lines from the start and stop at the first line that begins with
an em-dash.  The note text is everything before that line (up to and including
the preceding newline); the signature section is everything from that line
onward.

The same `\n\n`-in-text assumption exists in `verify_rekor_checkpoint` inside
`src/sigstore_verify.rs` (which re-implements the boundary split independently).
Both sites must be fixed.

---

## Unit tests — `signed_note::parse`

### T-044-01: Normal note (no blank lines in text) parses correctly
- Input: a well-formed signed note with 3-line note text and one signature line.
- Expected:
    - `note_text` contains exactly the 3 lines and their trailing newline.
    - `signatures` has exactly one entry with the correct key name and decoded key-id.

### T-044-02: Note text containing a blank line parses correctly
- Input: note text that includes `"\n\n"` internally (e.g. a two-paragraph body),
  followed by the blank-line separator and then a valid signature line.
- Example structure:
  ```
  line one\n
  \n
  line three\n
  \n
  — rekor.sigstore.dev <base64-sig>\n
  ```
- Expected:
    - `note_text` is `"line one\n\nline three\n"` (all three pre-signature lines).
    - `signatures` has one entry.
    - The previous `rfind("\n\n")` implementation would split at the first blank line,
      yielding `note_text = "line one\n"` — this test asserts the correct behavior.

### T-044-03: Note text with multiple blank lines parses correctly
- Input: note text with two internal blank lines, then the signature separator.
- Expected: `note_text` includes all content before the first em-dash line;
  `signatures` is correctly parsed.

### T-044-04: Note with no blank-line separator before signatures returns error
- Input: a string where the signature line appears without any preceding blank line.
- Example: `"line one\n— key AAAA=="` (no `\n` between text and sig).
- Expected: `Err(_)` — structural parse error, not a panic.

### T-044-05: Note with no signature lines returns error
- Input: note text only, no em-dash lines after the final newline.
- Expected: `Err(_)` containing "no signature lines" or similar.

### T-044-06: Malformed signature line (no space after key name) returns error
- Input: valid note text, then a line `"— keyname"` with no space and no base64.
- Expected: `Err(_)` describing the malformed line.

### T-044-07: Multiple valid signature lines are all parsed
- Input: note with three signature lines for different key names.
- Expected: `signatures.len() == 3`; each entry's `key_name` matches the respective line.

### T-044-08: Rekor-style checkpoint (3-line note, em-dash signature) parses correctly
- Use the exact format that `verify_rekor_checkpoint` processes:
  ```
  rekor.sigstore.dev - <logid>\n
  <tree_size>\n
  <root_hash_b64>\n
  \n
  — rekor.sigstore.dev <base64-sig>\n
  ```
- Expected: `note_text` is the first 4 lines (3 metadata lines + trailing newline);
  `signatures` has one entry for `rekor.sigstore.dev`.

---

## Unit tests — `verify_rekor_checkpoint` (in `src/sigstore_verify.rs`)

### T-044-09: Checkpoint with `\n\n` in note text is correctly split and tree-size extracted
- Build a synthetic checkpoint envelope whose note text line 0 (the origin line)
  contains `"\n\n"` embedded (unusual but not impossible if the origin string
  were attacker-supplied via a hostile mirror).
- Expected: `verify_rekor_checkpoint` extracts tree-size from line index 1
  of the actual note text, not from a shifted position caused by the early split.
- If the implementation delegates boundary-splitting to `signed_note::parse`
  (which is the recommended refactor), this test validates that delegation.

### T-044-10: Checkpoint with standard 3-line note and valid ECDSA signature verifies
- Build a checkpoint note with the correct structure, sign with the test ECDSA key.
- Expected: `verify_rekor_checkpoint` returns `Ok(())`.

### T-044-11: Checkpoint where claimed tree-size does not match inclusion proof returns error
- Build a valid checkpoint where the note's tree-size line says `100` but the
  `InclusionProof.tree_size` is `200`.
- Expected: `Err(RekorError::TreeHeadSignatureInvalid(...))` containing "tree-size mismatch".

### T-044-12: Checkpoint where claimed root hash does not match inclusion proof returns error
- Build a valid checkpoint where the note's root-hash line differs from
  `InclusionProof.root_hash_b64`.
- Expected: `Err(RekorError::TreeHeadSignatureInvalid(...))` containing "root-hash mismatch".

---

## Structural / static checks

### T-044-13: `signed_note::parse` does not call `rfind("\n\n")` as the boundary mechanism
- Code review assertion: after the fix, `src/signed_note.rs` does not contain
  `rfind("\n\n")` as the primary split.  The split is derived from line-by-line
  iteration that stops at the first em-dash line.
- Verifiable by reading the function body.

### T-044-14: `verify_rekor_checkpoint` in `sigstore_verify.rs` does not call `rfind("\n\n")` independently
- Code review assertion: either the function delegates to `signed_note::parse`
  (the preferred path) or it performs its own em-dash-based split.
  `rfind("\n\n")` must not remain as the sole boundary mechanism in this function.

### T-044-15: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass
- No compilation errors or lint warnings introduced by the change.

---

## Regression baseline

### T-044-16: All task 034 Go sumdb signed-note tests still pass
- Run `cargo test go_sumdb`.
- Expected: 0 failures — the sumdb notes do not contain blank lines in text,
  so the refactored parser must produce identical results for them.

### T-044-17: All task 036 Rekor inclusion-proof tests still pass
- Run `cargo test rekor`.
- Expected: 0 failures.

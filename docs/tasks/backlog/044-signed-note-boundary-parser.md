# Task 044 — Signed-note boundary parser — em-dash walk replaces rfind

**Status:** backlog
**Depends on:** 043 (signed-note multi-sig iteration), 036 (Rekor inclusion proof)
**Security finding:** M-8 (MEDIUM)
**Touches:** `src/signed_note.rs`, `src/sigstore_verify.rs`

## Objective

Replace the `rfind("\n\n")` boundary detection in `signed_note::parse` and in
`verify_rekor_checkpoint` with a line-walking approach that stops at the first
em-dash (`—`, U+2014) line.  This makes the parser correct for any note whose
text body contains blank lines, and removes a latent mis-parse path.

## Background

The signed-note format does not constrain the note text to be blank-line-free.
The actual boundary indicator is the start of the first signature line (begins
with U+2014).  Using `rfind("\n\n")` finds the *last* blank line, which is
correct when there is only one blank line in the document, but incorrect when
the note text itself contains blank lines.

Current `parse()` (simplified):
```rust
let note_end = signed_note.rfind("\n\n")
    .ok_or_else(|| "missing separator")?;
let note_text = &signed_note[..note_end + 1];
let sig_section = signed_note[note_end + 2..].trim_end_matches('\n');
```

Current `verify_rekor_checkpoint` (simplified):
```rust
let note_end = envelope.rfind("\n\n")
    .ok_or_else(|| RekorError::...)?;
let note_text = &envelope[..note_end];
```

Both sites independently re-implement the same flawed boundary logic.

## Behavior

### `signed_note::parse` — replace `rfind` with em-dash scan

Walk lines from the start.  The first line that begins with `\u{2014}` (em-dash)
marks the start of the signature section.  The note text is the byte slice from
the start of the input up to and including the newline that precedes the
em-dash line.

```
[  note text lines  ][\n][signature lines]
                       ^
                       split point: the \n before the first em-dash line
```

If no em-dash line is found, return `Err("signed note has no signature lines")`.
If the note text is empty before the first em-dash line, that is valid (unusual
but not forbidden).

### `verify_rekor_checkpoint` — delegate to `signed_note::parse`

Instead of re-implementing the boundary split, extract `note_text` from the
`ParsedNote` returned by `signed_note::parse(envelope)`.  The ECDSA verification
in `signed_note::verify_ecdsa_p256` already calls `parse` internally, so
`verify_rekor_checkpoint` only needs the note text for the tree-size and
root-hash cross-check.

Refactor:
```rust
fn verify_rekor_checkpoint(envelope: &str, proof: &InclusionProof) -> Result<(), RekorError> {
    // verify_ecdsa_p256 calls parse internally; we call parse separately
    // only to extract the note lines for the tree-size / root-hash check.
    match signed_note::verify_ecdsa_p256(envelope, REKOR_KEY_NAME, REKOR_PUBLIC_KEY) { ... }

    let parsed = signed_note::parse(envelope)
        .map_err(|e| RekorError::TreeHeadSignatureInvalid(e))?;
    let lines: Vec<&str> = parsed.note_text.lines().collect();
    ...
}
```

This eliminates the duplicate `rfind` call in `sigstore_verify.rs`.

## Requirements

- **REQ-044-01:** `signed_note::parse` determines the note/sig boundary by
  finding the first em-dash line, not by `rfind("\n\n")`.
- **REQ-044-02:** A note whose text contains one or more blank lines is parsed
  correctly — `note_text` includes all content before the first em-dash line.
- **REQ-044-03:** `verify_rekor_checkpoint` does not independently call
  `rfind("\n\n")`; it derives the note text from `signed_note::parse` or from
  the `ParsedNote` returned by the ECDSA verifier path.
- **REQ-044-04:** All existing single-line and multi-line note tests (tasks 034,
  036) continue to pass.
- **REQ-044-05:** A note with no em-dash lines returns `Err(_)` from `parse`.

## Acceptance criteria

- [ ] `parse` uses em-dash walk, not `rfind("\n\n")` (REQ-044-01); verified by T-044-13.
- [ ] Note with `\n\n` in text body parses correctly (REQ-044-02); verified by T-044-02, T-044-03.
- [ ] `verify_rekor_checkpoint` has no independent `rfind("\n\n")` (REQ-044-03); verified by T-044-14.
- [ ] No blank-line separator produces `Err` (REQ-044-05); verified by T-044-04.
- [ ] No em-dash lines produces `Err` (REQ-044-05); verified by T-044-05.
- [ ] Normal checkpoint still verifies (REQ-044-04); verified by T-044-10.
- [ ] Task 034 and 036 regression suites pass (REQ-044-04); verified by T-044-16, T-044-17.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Changing the em-dash character itself — the format is fixed.
- Modifying note producers (Go sumdb, Rekor) — dep-scan is a consumer only.
- Supporting multi-section notes (the format has exactly one note + one sig section).

## Risk notes

- The real-world Go sumdb and Rekor notes do not contain blank lines in their
  text bodies today.  The fix is correctness-first; the practical exploit
  surface is a hostile mirror injecting `\n\n` into the note body to confuse
  the tree-size extraction.  Low exploitability, high correctness value.
- Delegating `note_text` extraction in `verify_rekor_checkpoint` to
  `signed_note::parse` introduces a second call to `parse` inside
  `verify_rekor_checkpoint` (since `verify_ecdsa_p256` also calls it).  This
  is acceptable given the small size of the inputs; if performance is a concern,
  expose the `ParsedNote` as a return value from `verify_ecdsa_p256` instead.

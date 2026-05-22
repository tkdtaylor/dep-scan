# Test Spec — Task 050: parse_tlog_entries missing-field diagnostics

## Context

`parse_tlog_entries` in `src/registry/npm_attestation.rs` uses `unwrap_or(0)`
for both `logIndex` and `treeSize` from `inclusionProof`.  When a field is
absent, the function substitutes zero, which causes `verify_merkle_path` to
fail with `MalformedProof("tree_size is zero")` — a confusing diagnostic that
obscures which field was actually missing.

The fix changes the function signature to return `Vec<Result<TlogEntry, String>>`
(or an equivalent `Option`-based design) and propagates "missing required field"
errors with field-specific messages.  The caller's behavior (rejecting bundles
with no valid tlog entries) is unchanged.

---

## Unit tests — `parse_tlog_entries` error propagation

### T-050-01: Well-formed entry with both logIndex and treeSize as integers is parsed
- Input: a JSON array with one entry containing all required fields as numbers.
- Expected: `parse_tlog_entries` returns a vec of one `Ok(TlogEntry)` (or a non-empty vec if the signature changes to `Vec<TlogEntry>` with entries guaranteed valid — see implementer note).
- The `inclusion_proof.tree_size` is non-zero and the `log_index` matches the input.

### T-050-02: Well-formed entry with logIndex and treeSize as strings is parsed
- Input: entry where `logIndex` and `treeSize` are JSON strings (e.g. `"12345"`).
- Expected: parsed successfully; `tree_size` equals `12345`.

### T-050-03: Entry with missing `treeSize` produces a "missing required field" error, not "tree_size is zero"
- Input: entry where `inclusionProof` is present but `treeSize` key is absent.
- Expected: the entry is skipped or returns an `Err` variant with a message containing
  "treeSize" or "missing" — not `MalformedProof("tree_size is zero")`.
- This is the key diagnostic improvement: the error message must name the missing field.

### T-050-04: Entry with missing `logIndex` produces a "missing required field" error
- Input: entry where `logIndex` key is absent entirely (not `0`, truly absent).
- Expected: the entry is skipped or returns an `Err` variant with a message
  containing "logIndex" or "missing".

### T-050-05: Entry with both `logIndex` and `treeSize` absent produces a "missing required fields" error
- Input: entry with no `logIndex` and no `treeSize`.
- Expected: a single `Err` variant naming both missing fields, or two separate
  errors — implementer's choice, but neither field's absence should silently
  substitute zero.

### T-050-06: `logIndex` present as `0` (valid zero index) is accepted
- Input: `"logIndex": 0`.
- Expected: `TlogEntry.log_index == 0` — zero is a valid log index; only absence
  should produce an error.

### T-050-07: `treeSize` present as `1` (minimum valid tree size) is accepted
- Input: `"treeSize": 1`.
- Expected: `TlogEntry.inclusion_proof.tree_size == 1`.

### T-050-08: Entry array with one good entry and one bad entry returns one valid entry
- Input: two-element array where element 0 is well-formed and element 1 is missing `treeSize`.
- Expected: the function returns a vec containing exactly one successfully parsed entry
  (corresponding to element 0); element 1 is skipped with an error (logged or returned
  as `Err` in the vec).

### T-050-09: Empty input array returns empty vec (existing behavior preserved)
- Input: `serde_json::Value::Array(vec![])`.
- Expected: empty vec, no error.

### T-050-10: Non-array input returns empty vec (existing behavior preserved)
- Input: `serde_json::Value::Null`.
- Expected: empty vec, no error.

---

## Unit tests — downstream diagnostic improvement

### T-050-11: Caller receives a field-specific error message when treeSize is missing
- The consuming verifier (e.g. `verify_rekor_inclusion_proof` or equivalent in
  `sigstore_verify.rs`) receives the "missing field: treeSize" error rather than
  forwarding a `MalformedProof("tree_size is zero")` error.
- Expected: the final `RekorError` or `SigstoreError` message contains "missing"
  and either "treeSize" or "tree_size" — not solely "tree_size is zero".

### T-050-12: Caller receives a field-specific error message when logIndex is missing
- Same as T-050-11 but for `logIndex`.
- Expected: the error message contains "logIndex" or "log_index" and "missing".

---

## Static / structural checks

### T-050-13: `unwrap_or(0)` is not used for `treeSize` or `logIndex` inside `parse_tlog_entries`
- Code review assertion: after the fix, neither `tree_size` nor `log_index` is
  populated by an `unwrap_or(0)` that silently substitutes zero for an absent field.
- Verifiable by reading the function body.

### T-050-14: Implementer note on chosen return type
- The spec accepts two design choices:
    - (A) `Vec<Result<TlogEntry, String>>` — returns both successes and errors; caller filters.
    - (B) `Vec<TlogEntry>` with early `continue` on missing fields after emitting
      a diagnostic log/eprintln — same external interface as today but with explicit
      error messaging instead of silent zero substitution.
  Whichever choice is made, document it with a comment in the source file.

---

## Regression tests

### T-050-15: All task 036 Rekor inclusion-proof tests still pass
- Run `cargo test rekor`.
- Expected: 0 failures — the parser change must not break the common (well-formed)
  path.

### T-050-16: All task 032 npm provenance verification tests still pass
- Run `cargo test npm_provenance`.
- Expected: 0 failures.

### T-050-17: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

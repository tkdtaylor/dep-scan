# Test Spec — Task 061: Verbose-gate `parse_tlog_entries` malformed-entry diagnostic (N-L-3)

## Context

`parse_tlog_entries` in `src/registry/npm_attestation.rs` emits
`eprintln!("dep-scan: skipping malformed tlog entry: {msg}")` unconditionally
whenever `parse_single_tlog_entry` returns `Err`.  The task-053 / L-6 policy
requires user-visible error output to be verbose-gated and outermost-message-only
by default.  The field-names-only content of this message means there is no
actual information leak today, but the policy gap should be closed.

The fix threads a `verbose: bool` flag into `parse_tlog_entries` (or an
equivalent approach) and suppresses the diagnostic unless `verbose` is true.
No new crate dependency is introduced.

---

## Unit tests — `parse_tlog_entries` verbose-gate

### T-061-01: Malformed entry with `verbose: false` produces no output on stderr
- Construct a JSON array containing one malformed tlog entry (e.g. missing
  `treeSize` field so `parse_single_tlog_entry` returns `Err`).
- Call `parse_tlog_entries` (or the updated signature, whichever the implementer
  chooses) with `verbose = false`.
- Capture stderr (or use a test-local writer).
- Expected: no bytes are written to stderr; the function returns an empty vec.

### T-061-02: Malformed entry with `verbose: true` emits the diagnostic to stderr
- Same malformed entry as T-061-01.
- Call with `verbose = true`.
- Expected: stderr contains a line matching `"dep-scan: skipping malformed tlog
  entry:"` followed by the field-specific message (e.g. `"missing treeSize"` or
  equivalent from task 050).

### T-061-03: Well-formed entry with `verbose: false` produces no output and returns one entry
- Input: a JSON array with one fully valid tlog entry.
- Call with `verbose = false`.
- Expected: empty stderr; returns a vec containing exactly one `TlogEntry`.

### T-061-04: Well-formed entry with `verbose: true` produces no output and returns one entry
- Same as T-061-03 but `verbose = true`.
- Expected: no diagnostic line on stderr (the diagnostic is only emitted for
  malformed entries, never for successful parses); returns one entry.

### T-061-05: Mixed array (one good, one malformed) with `verbose: false`
- Input: array with element 0 valid, element 1 missing `logIndex`.
- Call with `verbose = false`.
- Expected: empty stderr; returns a vec of one entry (the valid one).

### T-061-06: Mixed array (one good, one malformed) with `verbose: true`
- Same array as T-061-05.
- Call with `verbose = true`.
- Expected: stderr contains exactly one diagnostic line (for the malformed
  entry); returns one valid entry.

### T-061-07: `verify_merkle_path` rejection on `tree_size == 0` still produces an error (regression)
- Construct a tlog entry with `treeSize: 1` (valid) and an inclusion proof
  path that would fail `verify_merkle_path` for `tree_size == 0`.
- This test verifies the existing `verify_merkle_path` rejection path is not
  accidentally disabled by the verbose-gate change.
- Expected: `verify_rekor_inclusion_proof` (or equivalent) returns `Err`
  containing `"tree_size is zero"` or the task-050 field-specific equivalent.

---

## Unit tests — call-site threading

### T-061-08: The `parse_attestation_response` caller passes the `verbose` flag through to `parse_tlog_entries`
- Arrange: two requests — one with `verbose: false`, one with `verbose: true` —
  against a wiremock attestation response that has one malformed tlog entry.
- Call `parse_attestation_response` (or whatever function calls `parse_tlog_entries`)
  with each verbose setting.
- Expected: no stderr for the `false` call; diagnostic on stderr for the `true`
  call.
- Implementation note: `parse_attestation_response` will need to accept `verbose`
  as a parameter, or the verbose flag must be threaded through whatever path
  reaches `parse_tlog_entries`.

### T-061-09: The `sigstore_verify` call site passes `verbose` correctly
- Arrange: call `verify_dsse_bundle` (or the function in `sigstore_verify.rs` that
  calls into `parse_tlog_entries` indirectly) with `verbose = false` and a bundle
  that has a malformed tlog entry alongside a valid one.
- Expected: no extra stderr output; the verifier uses the valid entry.

---

## Integration tests

### T-061-10: `dep-scan check pkg --registry npm` (no `--verbose`) with a malformed tlog entry suppresses the diagnostic
- wiremock serves an npm attestation response where one `tlogEntries` element is
  missing `treeSize`.
- Run without `--verbose`.
- Expected: stderr does not contain `"skipping malformed tlog entry"`.

### T-061-11: `dep-scan check pkg --registry npm --verbose` with a malformed tlog entry emits the diagnostic
- Same wiremock setup as T-061-10.
- Run with `--verbose`.
- Expected: stderr contains `"skipping malformed tlog entry"`.

---

## Regression tests

### T-061-12: All task 050 `parse_tlog_entries` diagnostic tests still pass
- Run `cargo test parse_tlog` or equivalent.
- Expected: 0 failures — the verbose-gate is additive; the field-specific
  messages introduced in task 050 are still generated (just gated).

### T-061-13: All task 032 npm provenance verification tests still pass
- Run `cargo test npm_provenance`.
- Expected: 0 failures.

### T-061-14: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` all pass.

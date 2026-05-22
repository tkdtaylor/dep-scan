# Task 050 — parse_tlog_entries missing-field diagnostics

**Status:** backlog
**Depends on:** 036 (Rekor inclusion proof), 032 (npm provenance verification)
**Security finding:** M-6 (MEDIUM)
**Touches:** `src/registry/npm_attestation.rs` (`parse_tlog_entries`)

## Objective

Replace `unwrap_or(0)` substitution for absent `logIndex` and `treeSize` fields
in `parse_tlog_entries` with explicit error propagation.  Missing required fields
now produce a diagnostic message that names the missing field instead of
silently substituting zero and causing a downstream `MalformedProof("tree_size is zero")` error.

## Background

Current parser (simplified):

```rust
let log_index = entry["logIndex"].as_u64()
    .or_else(|| entry["logIndex"].as_str().and_then(|s| s.parse::<u64>().ok()))
    .unwrap_or(0);  // <— silently substitutes 0 for absent field

let tree_size = ip["treeSize"].as_u64()
    .or_else(|| ip["treeSize"].as_str().and_then(|s| s.parse::<u64>().ok()))
    .unwrap_or(0);  // <— silently substitutes 0 for absent field
```

When `treeSize` is absent, `tree_size == 0` causes `verify_merkle_path` to return
`Err(RekorError::MalformedProof("tree_size is zero"))`.  The actual problem
("treeSize field missing from inclusionProof") is obscured.

When `logIndex` is absent, `log_index == 0` silently uses position 0, which is
a valid log index for the first ever Rekor entry.  If a bundle is structurally
broken (missing `logIndex`), the parser should say so rather than proceeding
with a potentially wrong index.

## Behavior

### Option A — preferred: return `Option<TlogEntry>` from inner parsing logic

Replace the single-function loop body with an inner function that returns
`Option<TlogEntry>` and `continue`s on `None`, emitting an `eprintln!` diagnostic:

```rust
fn parse_single_entry(entry: &serde_json::Value) -> Result<TlogEntry, String> {
    let log_index = entry["logIndex"].as_u64()
        .or_else(|| entry["logIndex"].as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| "missing required field: logIndex".to_string())?;

    let ip = &entry["inclusionProof"];
    let tree_size = ip["treeSize"].as_u64()
        .or_else(|| ip["treeSize"].as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| "missing required field: inclusionProof.treeSize".to_string())?;

    // ... rest of the fields (already use empty/default correctly)

    Ok(TlogEntry { log_index, .. })
}

pub fn parse_tlog_entries(value: &serde_json::Value) -> Vec<TlogEntry> {
    let arr = match value.as_array() { Some(a) => a, None => return vec![] };
    arr.iter().filter_map(|entry| {
        match parse_single_entry(entry) {
            Ok(e) => Some(e),
            Err(msg) => {
                eprintln!("dep-scan: skipping malformed tlog entry: {msg}");
                None
            }
        }
    }).collect()
}
```

This preserves the existing `Vec<TlogEntry>` return type (no caller changes
required) while surfacing the specific missing field in the error message.

### Option B — Vec<Result<TlogEntry, String>>

Change the return type to `Vec<Result<TlogEntry, String>>` and update callers
to filter and log errors.  This is a larger refactor; choose only if the caller
can benefit from the structured errors directly.

The implementer should choose Option A or B and document the choice in source.

## Requirements

- **REQ-050-01:** An entry missing `logIndex` produces an error message containing
  "logIndex" and "missing", not a silent zero substitution.
- **REQ-050-02:** An entry missing `inclusionProof.treeSize` produces an error
  message containing "treeSize" and "missing" — not `MalformedProof("tree_size is zero")`.
- **REQ-050-03:** An entry with `logIndex: 0` (explicit zero) is accepted as valid.
- **REQ-050-04:** An entry with `treeSize: 1` (minimum valid tree) is accepted as valid.
- **REQ-050-05:** A mixed array (one good entry, one bad entry) produces a vec
  with exactly the good entries; the bad entry is skipped with a diagnostic message.
- **REQ-050-06:** All existing task 032 and task 036 test vectors continue to pass.

## Acceptance criteria

- [ ] Missing `treeSize` produces a field-specific error (REQ-050-02); verified by T-050-03, T-050-11.
- [ ] Missing `logIndex` produces a field-specific error (REQ-050-01); verified by T-050-04, T-050-12.
- [ ] `logIndex: 0` is accepted (REQ-050-03); verified by T-050-06.
- [ ] `treeSize: 1` is accepted (REQ-050-04); verified by T-050-07.
- [ ] Mixed array returns only good entries (REQ-050-05); verified by T-050-08.
- [ ] `unwrap_or(0)` removed for required fields (REQ-050-01, REQ-050-02); verified by T-050-13.
- [ ] Task 032 and 036 regression suites pass (REQ-050-06); verified by T-050-15, T-050-16.
- [ ] Design choice documented in source (T-050-14).
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Validating all fields in a tlog entry — only the fields that currently use
  `unwrap_or(0)` for required fields are in scope.
- Changing the public API of `parse_tlog_entries` beyond the return type
  (if Option B is chosen, update only the internal callers in `npm_attestation.rs`
  and `sigstore_verify.rs`).
- Adding structured error types for tlog parsing — a `String` error is sufficient
  for diagnostic purposes here.

## Risk notes

- Option A is preferred because it does not change the return type, minimizing
  caller impact.
- The `eprintln!` diagnostic on a skipped entry will appear on `stderr` during
  normal scans only when a bundle is malformed.  Well-formed bundles (the vast
  majority) produce no output.
- A future structured-logging layer can replace the `eprintln!` without
  changing the function's logic.

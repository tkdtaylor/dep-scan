# Task 061 — Verbose-gate `parse_tlog_entries` malformed-entry diagnostic (N-L-3)

**Status:** backlog
**Depends on:** 050 (parse_tlog_entries missing-field diagnostics), 053 (error output scrubbing)
**Security finding:** N-L-3 (LOW — policy gap: unconditional user-visible output)
**Touches:** `src/registry/npm_attestation.rs` and callers that pass `verbose`

## Objective

Gate the `eprintln!("dep-scan: skipping malformed tlog entry: …")` diagnostic
on `verbose: bool` so that non-verbose invocations produce no extra output when
a tlog entry is malformed, consistent with the task-053 / L-6 policy.

## Background

Task 050 added field-specific error messages to `parse_tlog_entries`.  The
diagnostic is useful for debugging but was not verbose-gated.  Task 053 (L-6)
established the policy: user-visible error output must be verbose-gated and
outermost-message-only by default.

The current `eprintln!` is technically safe (it contains only hard-coded field
names, no user-controlled or registry-controlled strings), but the policy gap
should be closed before the v1.2.0 re-release.

## Approach

### Option A — thread `verbose: bool` through `parse_tlog_entries`

Change the signature to:

```rust
pub fn parse_tlog_entries(value: &serde_json::Value, verbose: bool) -> Vec<TlogEntry>
```

Inside the `filter_map` closure:

```rust
Err(msg) => {
    if verbose {
        eprintln!("dep-scan: skipping malformed tlog entry: {msg}");
    }
    None
}
```

Update every call site (`parse_attestation_response` and any caller in
`sigstore_verify.rs`) to pass the `verbose` flag through.

### Option B — use the `log` crate

If `log` is already in scope as a dependency, replace `eprintln!` with
`log::debug!("…")` and rely on the logging framework to filter output based on
the log level set by `--verbose`.  Do **not** add `log` as a new dependency
solely for this task.

### Recommended: Option A

`log` is not currently a dep-scan dependency.  Option A is two lines of change
in `parse_tlog_entries` plus threading `verbose` through `parse_attestation_response`
and its callers.  This is consistent with how `format_top_level_error` uses
`verbose` in `main.rs`.

## Requirements

- **REQ-061-01:** With `verbose = false`, `parse_tlog_entries` writes nothing to
  stderr when a malformed entry is skipped.
- **REQ-061-02:** With `verbose = true`, `parse_tlog_entries` writes the
  existing field-specific diagnostic (from task 050) to stderr.
- **REQ-061-03:** Well-formed entries produce no stderr output regardless of
  `verbose`.
- **REQ-061-04:** The `verbose` flag is threaded through `parse_attestation_response`
  (or equivalent) to every call site that reaches `parse_tlog_entries`.
- **REQ-061-05:** No new crate dependency is introduced.
- **REQ-061-06:** All task 050 and 032 tests continue to pass.

## Acceptance criteria

- [ ] Malformed entry + `verbose: false` produces empty stderr (REQ-061-01);
  T-061-01, T-061-05, T-061-10.
- [ ] Malformed entry + `verbose: true` produces the diagnostic (REQ-061-02);
  T-061-02, T-061-06, T-061-11.
- [ ] Well-formed entry + either verbose produces no extra stderr (REQ-061-03);
  T-061-03, T-061-04.
- [ ] `parse_attestation_response` passes `verbose` through (REQ-061-04);
  T-061-08.
- [ ] `sigstore_verify` call site passes `verbose` through (REQ-061-04);
  T-061-09.
- [ ] No new `Cargo.toml` dependency (REQ-061-05); verifiable by `cargo tree`.
- [ ] `verify_merkle_path` `tree_size == 0` rejection not disrupted (REQ-061-06);
  T-061-07.
- [ ] Task 050 and 032 regression suites pass; T-061-12, T-061-13.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` pass.

## Out of scope

- Verbose-gating other `eprintln!` calls elsewhere in the codebase — each is
  a separate finding if applicable.
- Switching to a structured logging framework (`log`, `tracing`) — a distinct
  architectural change that deserves its own task and ADR.
- Applying this change to the `parse_single_tlog_entry` helper, which is private
  and does not emit output directly.

## Risk notes

- Threading `verbose` into `parse_attestation_response` means its callers in
  `sigstore_verify.rs` (and ultimately `main.rs`) need an updated signature.
  This touches two modules; it remains within the one-task-two-module guideline.
- Test isolation: asserting "stderr is empty" in a multi-threaded test run may
  require capturing stderr via a pipe or test-local writer rather than reading
  the global stderr handle.  The implementer should use `assert_cmd` or a
  test-local `Vec<u8>` writer pattern rather than reading from
  `std::io::stderr()`.

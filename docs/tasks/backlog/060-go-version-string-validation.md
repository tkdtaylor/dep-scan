# Task 060 — Validate Go version strings before URL composition (N-L-2)

**Status:** backlog
**Depends on:** 019 (Go module proxy client), 041 (Go module path validation)
**Security finding:** N-L-2 (LOW — unsanitised version string in proxy URL)
**Touches:** `src/registry/go.rs`, `src/registry/mod.rs`

## Objective

Add `validate_go_version(version: &str) -> Result<(), GoVersionError>` and call
it inside `fetch_version_info` before the version string is interpolated into the
proxy URL.  Wire the error through a new `RegistryError::InvalidVersion` variant
so the existing fail-closed mapping in `main.rs` applies.

## Background

Task 041 validated the Go _module path_ before URL composition.  The _version_
string received from `@v/list` responses or the CLI was left unvalidated.  A
compromised proxy can serve arbitrary bytes as a version string; if those bytes
contain `/`, `?`, `#`, `%`, whitespace, or CRLF sequences, the constructed URL
may be malformed or interpreted as multiple requests by an HTTP/1.1 server.

## Behavior

### `validate_go_version`

Accepts printable ASCII only.  At minimum rejects:

- Empty string.
- Any string not starting with `v`.
- Characters `/`, `?`, `#`, `%`, `@`, space, tab, `\r`, `\n`, NUL, or any
  non-ASCII byte.
- Any segment equal to `..` after splitting on `/` (version strings should not
  contain `/` at all, so this is a belt-and-suspenders check).
- Percent-encoded sequences (`%XX`) — the `%` character itself is forbidden.

Does **not** attempt to enforce full SemVer grammar or Go pseudo-version grammar
beyond the constraints above.  The goal is to reject characters that would be
dangerous in a URL, not to validate the Go release pipeline.

### `GoVersionError`

A typed error enum analogous to `GoPathError`:

```rust
#[derive(Debug, PartialEq)]
pub enum GoVersionError {
    Empty,
    MissingVPrefix,
    PathTraversal,          // ".." segment
    ForbiddenCharacter { char: char },
}
```

Implements `std::fmt::Display` with human-readable messages.

### `RegistryError::InvalidVersion`

Add a new variant to `registry/mod.rs`:

```rust
/// A Go version string failed validation before URL composition.
#[error("invalid Go version string: {0}")]
InvalidVersion(String),
```

### Call site

Inside `fetch_version_info`, validate immediately after receiving the version
parameter, before `encode_module_path` or URL formatting:

```rust
validate_go_version(version).map_err(|e| RegistryError::InvalidVersion(e.to_string()))?;
```

Also validate at any other call site that sources a version from external input
(e.g. the version-list response path in `get_metadata`).

## Requirements

- **REQ-060-01:** `validate_go_version` returns `Ok(())` for valid semver and
  pseudo-version strings (see T-060-01 through T-060-07).
- **REQ-060-02:** `validate_go_version` returns `Err` for any string containing
  `/`, `?`, `#`, `%`, `@`, space, tab, `\r`, `\n`, NUL, or any non-ASCII
  character (see T-060-08 through T-060-21).
- **REQ-060-03:** `validate_go_version` rejects strings not starting with `v`
  (REQ-060-03 catches bare `1.2.3` forms).
- **REQ-060-04:** `fetch_version_info` returns `Err(RegistryError::InvalidVersion)`
  without making an HTTP request when given a crafted version.
- **REQ-060-05:** `RegistryError::InvalidVersion` exists as a distinct variant
  with a display message that mentions "version".
- **REQ-060-06:** All task 041 Go path validation tests and task 019 Go registry
  tests continue to pass.

## Acceptance criteria

- [ ] `validate_go_version("v1.2.3")` returns `Ok(())` (REQ-060-01); T-060-01.
- [ ] `validate_go_version("..")` returns `Err(_)` (REQ-060-02); T-060-08.
- [ ] `validate_go_version("v1.0\r\nHost: evil")` returns `Err(_)` (REQ-060-02);
  T-060-17.
- [ ] `validate_go_version("v1.0%2F1")` returns `Err(_)` (REQ-060-02); T-060-12.
- [ ] `validate_go_version("1.2.3")` returns `Err(_)` (REQ-060-03); T-060-22.
- [ ] `fetch_version_info` with `".."` returns `InvalidVersion` without HTTP call
  (REQ-060-04); T-060-24.
- [ ] `RegistryError::InvalidVersion` variant exists (REQ-060-05); T-060-27.
- [ ] `GoVersionError::Display` is human-readable (REQ-060-05); T-060-28.
- [ ] Task 041 and 019 regressions pass; T-060-29, T-060-30.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` pass.

## Out of scope

- Full Go pseudo-version grammar validation (complex; overkill for a LOW finding).
- Validating version strings sourced from `go.sum` / lockfile parsing (task 023
  context — a separate task if needed).
- Percent-decoding and re-validating the decoded form — the `%` character itself
  is forbidden, so no decoding is necessary.

## Risk notes

- The version list from `@v/list` can contain multiple entries.  After this
  change, a crafted list entry will cause `fetch_version_info` to return
  `InvalidVersion` for that entry rather than silently constructing a bad URL.
  The caller (`get_metadata`) should propagate this error to the user.
- The `v` prefix requirement may be too strict for some private or non-standard
  Go module proxies.  If this proves problematic in practice, the check can be
  softened to "must not start with a path separator" — document the decision in
  an ADR if changed.

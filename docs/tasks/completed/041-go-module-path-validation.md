# Task 041 — Go module path validation before URL composition

**Status:** backlog
**Depends on:** 019 (Go module registry client), 034 (Go sumdb cross-check)
**Security finding:** H-5 (HIGH)
**Touches:** `src/registry/go.rs` only

## Objective

Validate Go module paths against the Go module path grammar before they are used in URL composition. Currently `encode_module_path` applies only the uppercase-to-`!lc` encoding; characters like `..`, `?`, `#`, spaces, and percent-encoded sequences pass through unvalidated. Combined with a hostile mirror (or a user-supplied module name from an untrusted source), this is a request-smuggling and path-confusion primitive — `?` and `#` can alter which resource the proxy returns; `..` can traverse to a different path on the server.

## Background

`encode_module_path` in `src/registry/go.rs` performs:

```rust
module.chars().map(|c| {
    if c.is_ascii_uppercase() { format!("!{}", c.to_ascii_lowercase()) }
    else { c.to_string() }
}).collect()
```

This leaves `..`, `/`, `?`, `#`, `%`, newlines, and all other non-uppercase characters untouched. These characters are then interpolated directly into URL strings like `"{base_url}/{encoded}/{version}.info"`.

The Go module path grammar (from the Go specification and `cmd/go/internal/module/module.go`) allows:
- Alphanumerics, hyphen (`-`), underscore (`_`), and dot (`.`) within path elements.
- Forward slash (`/`) as a path element separator.
- Uppercase letters (handled by the `!lc` encoding).
- Specifically disallows: `..` segments, `.` segments, leading/trailing slashes, empty segments, and all non-ASCII characters.

The validator in this task enforces a safe subset of this grammar. Characters with special URL significance (`?`, `#`, `%`, space, `@`, `\n`, `\r`) are explicitly forbidden even if the Go spec would permit them (none of them appear in legitimate module paths).

## Behavior

### New function

Add `validate_go_module_path(path: &str) -> Result<(), GoPathError>` in `src/registry/go.rs`.

The function must reject:

1. Empty input — `GoPathError::Empty`.
2. Leading slash — `GoPathError::LeadingSlash`.
3. Trailing slash — `GoPathError::TrailingSlash`.
4. Any path segment that is exactly `..` — `GoPathError::DotDotSegment`.
5. Any path segment that is exactly `.` — `GoPathError::DotSegment`.
6. Any empty path segment (two consecutive slashes) — `GoPathError::EmptySegment`.
7. Any character in the forbidden set: `?`, `#`, `%`, space, `@`, `\n`, `\r`, and any non-ASCII character — `GoPathError::ForbiddenCharacter { char }`.

Characters that are explicitly allowed: ASCII alphanumerics, `-`, `_`, `.` (within a segment), `/` (as separator), all ASCII uppercase letters.

Map `GoPathError` to `RegistryError::InvalidModulePath(reason)` (add this variant if it does not exist).

### Integration

Call `validate_go_module_path(module)` at the start of `encode_module_path` (or just before it is called from URL-building methods in `GoRegistry`). The validation must happen before any URL is constructed or any HTTP call is made.

Also call the validator in the `run_check` dispatch path in `src/main.rs` (for the same reason as task 037: the module path comes from user-supplied CLI input). A bad module path must exit with code 2 before any network call.

## Requirements

- **REQ-041-01:** `validate_go_module_path` rejects `..` segments.
- **REQ-041-02:** `validate_go_module_path` rejects characters with URL special meaning: `?`, `#`, `%`, space, `@`, `\n`, `\r`.
- **REQ-041-03:** `validate_go_module_path` rejects leading slashes, trailing slashes, and empty segments.
- **REQ-041-04:** `validate_go_module_path` rejects empty input.
- **REQ-041-05:** Validation runs before any URL is constructed or any HTTP call is made.
- **REQ-041-06:** Valid module paths (including uppercase, hyphens, underscores, dots within segments, and version suffixes like `/v2`) are accepted without modification.
- **REQ-041-07:** `RegistryError::InvalidModulePath` is returned on validation failure; exit code 2 at the CLI layer.

## Acceptance criteria

- [ ] `validate_go_module_path` implemented (REQ-041-01 through REQ-041-04); verified by T-041-05 through T-041-17.
- [ ] Valid paths accepted (REQ-041-06); verified by T-041-01 through T-041-04, T-041-15.
- [ ] Validation fires before any HTTP call (REQ-041-05); verified by T-041-19, T-041-20.
- [ ] CLI exits with code 2 and names the bad path on validation failure (REQ-041-07); verified by T-041-21, T-041-22, T-041-24.
- [ ] `encode_module_path` still produces correct `!lc` encoding for valid uppercase paths (T-041-18).
- [ ] Task 019 Go registry tests pass unchanged (T-041-25).
- [ ] Task 034 sumdb tests pass unchanged (T-041-26).
- [ ] `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Full Go module path grammar compliance (e.g., the restriction that module path elements cannot begin with a dot, case-folding uniqueness requirements). The forbidden-character + dot-segment checks are the security-relevant subset.
- Validating Go module version strings (e.g., `v1.0.0`, `v2.0.0+incompatible`). Version strings appear in a separate parameter and are not interpolated into paths the same way.
- DNS validation or IP-range checks for the Go proxy base URL (that is a separate concern orthogonal to the module path grammar).

## Risk notes

- The `.` restriction (single-dot segments) is conservative — the Go spec also forbids them in module paths. Some local-replace `go.mod` entries use relative paths like `./local/module`, but these are not user-supplied CLI arguments in dep-scan's `check` or `install` flow; they come from lockfile parsing which is a separate code path.
- The `@` character is explicitly forbidden even though some `go get` invocations use `module@version` syntax. dep-scan receives the module path and version separately; the `@` character appearing in the module-path argument indicates a malformed input or an attempt to confuse the version-parsing logic.

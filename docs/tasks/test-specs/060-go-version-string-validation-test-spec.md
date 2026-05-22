# Test Spec — Task 060: Validate Go version strings before URL composition (N-L-2)

## Context

`fetch_version_info` in `src/registry/go.rs` interpolates the `version` parameter
directly into a proxy URL (`{base_url}/{module}/@v/{version}.info`) without
validating it.  The module path is validated by `validate_go_module_path` (task
041), but the version string is not.  A compromised proxy serving a `@v/list`
response with a crafted version string (`..`, `?`, `\r\n`, `%2F`, etc.) could:

- Redirect the `.info` fetch to an unexpected path.
- Smuggle query parameters into the URL.
- Attempt HTTP request splitting via embedded `\r\n`.

The fix adds `validate_go_version(version: &str) -> Result<(), GoVersionError>`,
called inside `fetch_version_info` (and at any other call site that produces a
version string from external input).  Invalid versions are surfaced as
`RegistryError::InvalidVersion`.

---

## Unit tests — `validate_go_version` acceptance

### T-060-01: Canonical semver tag is accepted
- Input: `"v1.2.3"`
- Expected: `Ok(())`.

### T-060-02: Zero-patch semver tag is accepted
- Input: `"v1.0.0"`
- Expected: `Ok(())`.

### T-060-03: Major-only tag is accepted
- Input: `"v2"`
- Expected: `Ok(())`.

### T-060-04: Major.minor tag is accepted
- Input: `"v0.9"`
- Expected: `Ok(())`.

### T-060-05: Pseudo-version (timestamp + commit hash) is accepted
- Input: `"v0.0.0-20210101120000-abcdef0123456"`
- Expected: `Ok(())`.

### T-060-06: Build-metadata suffix is accepted
- Input: `"v1.2.3+incompatible"`
- Expected: `Ok(())`.

### T-060-07: Pre-release suffix with alphanumeric label is accepted
- Input: `"v1.0.0-beta.1"`
- Expected: `Ok(())`.

---

## Unit tests — `validate_go_version` rejection

### T-060-08: Path traversal segment `..` is rejected
- Input: `".."`
- Expected: `Err(GoVersionError::PathTraversal)` or equivalent named variant.

### T-060-09: Embedded `..` within a longer string is rejected
- Input: `"v1.0.0/../etc"`
- Expected: `Err(_)` — the `..` segment makes this unsafe regardless of context.

### T-060-10: Query separator `?` is rejected
- Input: `"v1.0.0?foo=bar"`
- Expected: `Err(_)`.

### T-060-11: Fragment separator `#` is rejected
- Input: `"v1.0.0#section"`
- Expected: `Err(_)`.

### T-060-12: Percent-encoded slash `%2F` is rejected
- Input: `"v1.0%2F0"`
- Expected: `Err(_)` — the `%` character is forbidden.

### T-060-13: Percent-encoded newline `%0A` is rejected
- Input: `"v1.0%0A.0"`
- Expected: `Err(_)`.

### T-060-14: Bare `@` is rejected
- Input: `"v1.0.0@evil.com"`
- Expected: `Err(_)`.

### T-060-15: Embedded space is rejected
- Input: `"v1.0 .0"`
- Expected: `Err(_)`.

### T-060-16: Tab character is rejected
- Input: `"v1.0\t0"`
- Expected: `Err(_)`.

### T-060-17: Carriage return `\r` is rejected
- Input: `"v1.0\r\n0"`
- Expected: `Err(_)` — HTTP request splitting vector.

### T-060-18: Newline `\n` is rejected
- Input: `"v1.0\n0"`
- Expected: `Err(_)`.

### T-060-19: NUL byte is rejected
- Input: `"v1.0\x000"`
- Expected: `Err(_)`.

### T-060-20: Forward slash `/` inside the version string is rejected
- Input: `"v1.0/0"`
- Expected: `Err(_)` — slashes are path separators and must not appear in a
  version segment.

### T-060-21: Empty string is rejected
- Input: `""`
- Expected: `Err(GoVersionError::Empty)` or equivalent.

### T-060-22: Version not starting with `v` is rejected
- Input: `"1.2.3"` (missing `v` prefix)
- Expected: `Err(_)` — Go version strings must begin with a literal `v`.

---

## Unit tests — `fetch_version_info` integration

### T-060-23: `fetch_version_info` with a valid version contacts the proxy
- wiremock serves a valid `.info` JSON at the expected URL.
- Call `GoRegistry::get_metadata("github.com/foo/bar", Some("v1.2.3"))`.
- Expected: returns `Ok(metadata)` and the mock was contacted exactly once.

### T-060-24: `fetch_version_info` with a crafted version `..` does not contact the proxy
- Call `GoRegistry::get_metadata("github.com/foo/bar", Some(".."))`.
- Expected: returns `Err(RegistryError::InvalidVersion(_))` without making any
  network request (wiremock mock receives zero calls).

### T-060-25: `fetch_version_info` with version `"v1.0\r\nHost: evil.com"` does not contact the proxy
- Call `GoRegistry::get_metadata("github.com/foo/bar", Some("v1.0\r\nHost: evil.com"))`.
- Expected: returns `Err(RegistryError::InvalidVersion(_))` without any HTTP request.

### T-060-26: `fetch_version_info` with a version containing `%2F` does not contact the proxy
- Call `GoRegistry::get_metadata("github.com/foo/bar", Some("v1.0%2F1"))`.
- Expected: `Err(RegistryError::InvalidVersion(_))`.

---

## Unit tests — `RegistryError::InvalidVersion` variant

### T-060-27: `RegistryError::InvalidVersion` exists as a named variant in `registry/mod.rs`
- Code review assertion: `RegistryError` gains an `InvalidVersion(String)` variant
  (or reuses `InvalidModulePath` with a different payload — implementer's choice,
  but the display message must mention "version", not "module path").
- Verifiable by reading the enum definition.

### T-060-28: `GoVersionError` implements `std::fmt::Display` with a human-readable message
- For each variant, the display message must describe the violation clearly enough
  that a user can understand why their version string was rejected.
- Spot check: `GoVersionError::PathTraversal` (or equivalent) displays something
  containing `".."` or `"path traversal"`.

---

## Regression tests

### T-060-29: All task 041 Go module path validation tests still pass
- Run `cargo test go_module` or equivalent.
- Expected: 0 failures — the new version validator is a sibling to the path
  validator, not a replacement.

### T-060-30: All task 019 Go registry client tests still pass
- Run `cargo test go_registry` or equivalent.
- Expected: 0 failures — valid version strings continue to work normally.

### T-060-31: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` all pass.

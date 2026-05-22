# Test Spec — Task 042: Harden TempReqFile against predictable filename / symlink attack

## Unit tests (TempReqFile::create)

### T-042-01: Created temp file has mode 0o600 (owner read/write only)
- Call `TempReqFile::create("name==1.0.0 --hash=sha256:aaaa\n")`
- Stat the returned path
- Expected: permissions are `0o600` on Unix; on Windows this is a no-op and the test is marked `#[cfg(unix)]`

### T-042-02: Created temp file is in the system temp directory
- Call `TempReqFile::create("contents")`
- Expected: the path's parent equals `std::env::temp_dir()`

### T-042-03: Two successive calls to `TempReqFile::create` produce different paths
- Call `TempReqFile::create("a")` and `TempReqFile::create("b")` in rapid succession
- Expected: the two paths differ — the filename suffix is not predictable from the timestamp alone

### T-042-04: `TempReqFile::create` fails atomically if the path already exists as a symlink (TOCTOU defense)
- `#[cfg(unix)]` only
- Pre-create a symlink at the path dep-scan would use (this requires knowing the suffix — which should be impossible with a CSPRNG, but we can test this by injecting a mock that returns a fixed suffix, then pre-creating the symlink)
- Alternative approach: patch the file creation to use `O_CREAT | O_EXCL` semantics (which `tempfile::NamedTempFile` provides); verify that if the NamedTempFile API is used, it inherits the `O_EXCL` guarantee without additional testing surface
- **Implementer note:** if `tempfile::NamedTempFile` is used (recommended), T-042-04 is satisfied by the crate's documented behavior. Add a static check that `TempReqFile::create` calls `tempfile::NamedTempFile::new()` or `Builder::new().tempfile_in()`, NOT `std::fs::write` with a hand-crafted path

### T-042-05: Dropping `TempReqFile` deletes the file
- Call `TempReqFile::create("contents")`, capture the path
- Drop the struct
- Expected: `std::fs::metadata(path)` returns `Err` (file no longer exists)

### T-042-06: Dropping `TempReqFile` when the file was already deleted does not panic
- Call `TempReqFile::create("contents")`, capture the path
- Manually delete the file
- Drop the struct
- Expected: no panic — `Drop::drop` ignores the removal error

### T-042-07: Created file contents match the input string exactly
- Call `TempReqFile::create("express==4.18.0 --hash=sha256:deadbeef\n")`
- Read back the file contents
- Expected: contents equal `"express==4.18.0 --hash=sha256:deadbeef\n"` byte-for-byte

### T-042-08: File is not readable by other users (Unix mode 0o600 — only owner bits set)
- Same as T-042-01 but verifying group and other bits are zero
- `#[cfg(unix)]`
- Expected: `mode & 0o077 == 0` (no group or world permissions)

## Unit tests (static / structural checks)

### T-042-09: `SystemTime::now()` is not used as a sole entropy source for the filename
- Static check: `src/main.rs` (or wherever `TempReqFile::create` is defined) does not contain `SystemTime::now()` used to derive a filename suffix without mixing in a CSPRNG source
- Expected: the implementation uses `tempfile::NamedTempFile` or an equivalent CSPRNG-based approach

### T-042-10: `tempfile` crate is listed in `Cargo.toml` as a regular (non-dev) dependency
- The security audit found `tempfile` was a dev-dependency; it must be promoted to a full dependency so it is available in production builds
- Expected: `Cargo.toml` lists `tempfile` under `[dependencies]`, not only `[dev-dependencies]`

## Integration tests (assert_cmd)

### T-042-11: `dep-scan install flask --registry pypi` creates and then cleans up a temp file
- wiremock serves valid PyPI metadata with a sha256 hash
- Run `dep-scan install flask --registry pypi`
- Check that no `dep-scan-*.txt` files remain in `std::env::temp_dir()` after the process exits (regardless of whether pip succeeded)
- Expected: zero matching files in temp dir after process exit

### T-042-12: `dep-scan install flask --registry pypi` temp file has permissions 0o600 during the window it exists
- `#[cfg(unix)]`
- Patch the code to pause before deleting the temp file (or use a SIGINT during the run), stat the file
- Alternative: use a filesystem observer or check the file during the pip invocation
- **Implementer note:** this test is difficult to assert deterministically in a CI environment. If the `tempfile::NamedTempFile` approach is used, its security properties (O_EXCL + mode 0600 on Unix) are documented and this test case can be satisfied by a code review assertion rather than a runtime assertion. Document the decision here.

### T-042-13: If pip is not available, the temp file is still cleaned up
- wiremock serves valid PyPI metadata
- `pip` is not in PATH (or PATH is cleared)
- Run `dep-scan install flask --registry pypi`
- Expected: pip invocation fails; no temp file remains in `std::env::temp_dir()`

## Regression tests

### T-042-14: All task 031 pip require-hashes tests still pass
- Run `cargo test pip_require_hashes` (or equivalent)
- Expected: 0 failures — the temp file change is internal; the pip invocation behavior is unchanged

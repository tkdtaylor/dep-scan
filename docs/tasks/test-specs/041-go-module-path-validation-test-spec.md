# Test Spec — Task 041: Go module path validation before URL composition

## Unit tests (validate_go_module_path)

These cover a standalone `validate_go_module_path(path: &str) -> Result<(), GoPathError>` function that enforces the Go module path grammar before `encode_module_path` is called.

### T-041-01: Simple valid module path accepted
- Input: `"github.com/gin-gonic/gin"`
- Expected: `Ok(())`

### T-041-02: Standard library-style path accepted
- Input: `"golang.org/x/net"`
- Expected: `Ok(())`

### T-041-03: Module path with version suffix accepted
- Input: `"github.com/foo/bar/v2"`
- Expected: `Ok(())`

### T-041-04: Uppercase-containing path accepted (encode_module_path handles the transform)
- Input: `"github.com/Azure/go-autorest"`
- Expected: `Ok(())` — the validator approves uppercase letters; `encode_module_path` performs the `!lc` encoding

### T-041-05: Path with `..` segment is rejected
- Input: `"github.com/../etc/passwd"`
- Expected: `Err(GoPathError::DotDotSegment)` with a message naming the `..` segment

### T-041-06: Path with `.` segment (single dot) is rejected
- Input: `"github.com/./foo"`
- Expected: `Err(GoPathError::DotSegment)`

### T-041-07: Path containing `?` is rejected (query string confusion)
- Input: `"github.com/foo?bar"`
- Expected: `Err(GoPathError::ForbiddenCharacter { char: '?' })`

### T-041-08: Path containing `#` is rejected (fragment confusion)
- Input: `"github.com/foo#bar"`
- Expected: `Err(GoPathError::ForbiddenCharacter { char: '#' })`

### T-041-09: Path containing a space is rejected
- Input: `"github.com/foo bar"`
- Expected: `Err(GoPathError::ForbiddenCharacter { char: ' ' })`

### T-041-10: Path containing `%` encoding is rejected
- Input: `"github.com/foo%2Fbar"` (URL-encoded slash)
- Expected: `Err(GoPathError::ForbiddenCharacter { char: '%' })`

### T-041-11: Path with leading slash is rejected
- Input: `"/github.com/foo/bar"`
- Expected: `Err(GoPathError::LeadingSlash)`

### T-041-12: Path with trailing slash is rejected
- Input: `"github.com/foo/bar/"`
- Expected: `Err(GoPathError::TrailingSlash)`

### T-041-13: Empty path is rejected
- Input: `""`
- Expected: `Err(GoPathError::Empty)`

### T-041-14: Path with empty segment (double slash) is rejected
- Input: `"github.com//foo"`
- Expected: `Err(GoPathError::EmptySegment)`

### T-041-15: Path with allowed special characters (hyphen, underscore, dot within segment) accepted
- Inputs: `"github.com/foo-bar"`, `"github.com/foo_bar"`, `"gopkg.in/yaml.v3"`
- Expected: `Ok(())` for each

### T-041-16: Newline character in path is rejected
- Input: `"github.com/foo\nbar"` (URL smuggling via CRLF)
- Expected: `Err(GoPathError::ForbiddenCharacter { char: '\n' })`

### T-041-17: `@` character in path is rejected (version confusion)
- Input: `"github.com/foo@v1.0.0"`
- Expected: `Err(GoPathError::ForbiddenCharacter { char: '@' })` — version specifiers belong in the version parameter, not the module path

## Unit tests (encode_module_path is only called after validation passes)

### T-041-18: `encode_module_path` produces correct output for a valid path
- Input: `"github.com/Azure/go-autorest"`
- Expected: `"github.com/!azure/go-autorest"` — uppercase `A` becomes `!a`

### T-041-19: `fetch_version_list` rejects a `..` segment before making any HTTP request
- Arrange: no network mock active
- Call `GoRegistry::fetch_version_list("github.com/../etc/passwd")` (or equivalent internal path)
- Expected: returns `Err(RegistryError::InvalidModulePath(_))`; zero HTTP calls issued

### T-041-20: `GoRegistry::get_metadata` rejects invalid path before any network call
- Call `get_metadata("github.com/foo?injected=1", None)` without any network mock
- Expected: `Err(RegistryError::InvalidModulePath(_))`; zero HTTP calls

## Integration tests (assert_cmd + wiremock)

### T-041-21: `dep-scan check 'github.com/../etc/passwd' --registry go` exits with error code 2
- Expected: exit 2, stderr contains "invalid Go module path" and the bad token; wiremock observes zero calls

### T-041-22: `dep-scan check 'github.com/foo?registry=evil' --registry go` exits with error code 2
- Expected: exit 2, error names the `?` character; wiremock observes zero calls

### T-041-23: `dep-scan check 'github.com/gin-gonic/gin' --registry go` succeeds normally
- wiremock serves valid Go proxy metadata for the module
- Expected: scan runs; no path validation error

### T-041-24: Error message includes the bad module path verbatim
- Input: any path with a forbidden character
- Expected: the stderr message contains the full module path string so the user can identify the problem

## Regression tests

### T-041-25: All task 019 Go module registry tests still pass
- Run `cargo test go_module_registry` (or equivalent)
- Expected: 0 failures — existing valid paths remain valid

### T-041-26: All task 034 Go sumdb tests still pass
- Run `cargo test go_sumdb`
- Expected: 0 failures — the validator is additive; sumdb uses the same module paths and they are all valid

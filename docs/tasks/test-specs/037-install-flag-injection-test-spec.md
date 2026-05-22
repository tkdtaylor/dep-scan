# Test Spec — Task 037: Install command CLI flag injection hardening

## Unit tests (package name validator)

These cover a standalone `validate_package_name(name: &str, registry: RegistryType) -> Result<(), ValidationError>` function that enforces the allowed name grammar per registry before any scan or exec.

### T-037-01: Leading dash rejected for all registries
- Input: `"--registry=http://evil"`, any registry
- Expected: `Err(ValidationError::FlagLike { token: "--registry=http://evil" })` with a message containing "package name must not start with '-'"

### T-037-02: Single-dash prefix rejected
- Input: `"-i"`, any registry
- Expected: `Err(ValidationError::FlagLike { token: "-i" })`

### T-037-03: Legitimate npm package accepted
- Input: `"express"`, `RegistryType::Npm`
- Expected: `Ok(())`

### T-037-04: Scoped npm package accepted
- Input: `"@babel/core"`, `RegistryType::Npm`
- Expected: `Ok(())`

### T-037-05: Legitimate crates name accepted
- Input: `"serde_json"`, `RegistryType::Crates`
- Expected: `Ok(())`

### T-037-06: Legitimate Go module path accepted
- Input: `"github.com/gin-gonic/gin"`, `RegistryType::Go`
- Expected: `Ok(())`

### T-037-07: Empty string rejected
- Input: `""`, any registry
- Expected: `Err(ValidationError::Empty)`

### T-037-08: Package name with only whitespace rejected
- Input: `"   "`, any registry
- Expected: `Err(ValidationError::Empty)` or `Err(ValidationError::FlagLike)` — either is acceptable; the important property is that it is rejected, not passed to the exec call

### T-037-09: Multiple packages — one bad token rejects the entire batch
- Input: `["express", "--global", "lodash"]`, `RegistryType::Npm`
- Expected: validation returns an error naming `"--global"` before any scan or exec begins

## Integration tests (assert_cmd)

These run the real binary against a mocked registry and verify the behavior end-to-end.

### T-037-10: `dep-scan install '--registry=http://attacker' express --registry npm` exits with error code 2 and rejects before scanning
- The exploit from H-1: the first positional token looks like a flag
- Expected: exit code 2 (bad input, not a policy block), stderr contains "package name must not start with '-'", wiremock observes zero metadata calls (validation happens before network)

### T-037-11: `dep-scan install '-i' pkg --registry npm` is rejected before exec
- Input: flag-like token as first package argument
- Expected: exit code 2, stderr names the bad token, wiremock observes zero metadata calls

### T-037-12: `dep-scan install '--global' pkg --registry npm` is rejected before exec
- Same shape as T-037-11; `--global` is a real npm flag that would elevate privileges
- Expected: exit code 2 with the bad token named in the error

### T-037-13: `dep-scan check '--registry=http://evil' express --registry npm` is also rejected
- The same validator must apply in the `check` subcommand, not just `install`
- Expected: exit code 2, error names the bad token

### T-037-14: Legitimate multi-package install proceeds normally
- Input: `dep-scan install express lodash --registry npm` with wiremock serving clean metadata for both
- Expected: scan runs for both packages; if both pass, exec proceeds (npm not available in test environment — exit code reflects "npm not found", not a validation error); no "must not start with '-'" error appears in stderr

### T-037-15: `dep-scan install '@babel/core' --registry npm` with scoped package proceeds normally
- Scoped npm packages begin with `@`; they must NOT be rejected by the validator
- Expected: same shape as T-037-14 — validation passes, scan runs

### T-037-16: Error message includes the bad token verbatim
- Input: any flag-like token, e.g. `"--config-settings=build_backend=foo"`
- Expected: stderr contains the full token `"--config-settings=build_backend=foo"` so the user can identify which argument triggered the error

## Regression tests

### T-037-17: All task 024 integration tests still pass
- Run `cargo test install_subcommand` (or equivalent) after this task lands
- Expected: 0 failures — none of the existing install tests use flag-like package names, so behavior is unchanged

### T-037-18: `dep-scan install` with no packages produces a usage error, not a panic
- Input: `dep-scan install --registry npm` (no package arguments)
- Expected: exit code 2 with a usage message; not a panic or empty validation result

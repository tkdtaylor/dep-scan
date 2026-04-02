# Test Spec — Task 009: check subcommand integration

## Integration tests (assert_cmd + wiremock)

### T-009-01: Check passing package exits 0
- Setup: wiremock returns npm JSON for package published 72h ago
- Run: `dep-scan check old-package --registry npm`
- Expected: exit code 0, output shows "pass"

### T-009-02: Check failing package exits 1
- Setup: wiremock returns npm JSON for package published 1h ago
- Run: `dep-scan check new-package --registry npm`
- Expected: exit code 1, output shows "block" with age reason

### T-009-03: Check with --json outputs valid JSON
- Setup: wiremock returns npm JSON
- Run: `dep-scan check some-package --registry npm --json`
- Expected: exit code 0 or 1, output is valid JSON with expected fields

### T-009-04: Multiple packages checked in one invocation
- Setup: wiremock returns JSON for two packages (one old, one new)
- Run: `dep-scan check old-pkg new-pkg --registry npm`
- Expected: exit code 1 (at least one failure), output shows results for both

### T-009-05: Cache hit skips registry query
- Setup: pre-populate cache with result for "cached-pkg"
- Run: `dep-scan check cached-pkg --registry npm`
- Expected: no HTTP request made to wiremock, result from cache used

### T-009-06: New results are cached
- Setup: wiremock returns npm JSON, empty cache
- Run: `dep-scan check new-pkg --registry npm` twice
- Expected: second run uses cache (verify wiremock received only 1 request)

### T-009-07: Registry error exits 2
- Setup: wiremock returns 500
- Run: `dep-scan check broken-pkg --registry npm`
- Expected: exit code 2, error message shown

### T-009-08: Human-readable output format
- Setup: wiremock returns npm JSON
- Run: `dep-scan check some-package --registry npm`
- Expected: output contains package name, version, age, and policy result in readable format

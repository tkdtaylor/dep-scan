# Test Spec — Task 015: Dependency confusion heuristics

## Unit tests

### T-015-01: Internal prefix match warns
- Package name "internal-utils", default prefixes
- Expected: Warn mentioning "internal namespace pattern"

### T-015-02: Private prefix match warns
- Package name "private-api-client"
- Expected: Warn

### T-015-03: Normal package passes
- Package name "lodash"
- Expected: Pass

### T-015-04: Custom prefix config
- Config with internal_prefixes = ["acme-", "myco-"]
- Package "acme-auth"
- Expected: Warn

### T-015-05: Custom prefix — non-match passes
- Config with internal_prefixes = ["acme-"]
- Package "lodash"
- Expected: Pass

### T-015-06: Scoped package pattern
- Package name "@internal/utils"
- Expected: Warn (@ prefix indicates potential private scope)

### T-015-07: Empty prefix list disables check
- Config with internal_prefixes = []
- Any package name
- Expected: Pass

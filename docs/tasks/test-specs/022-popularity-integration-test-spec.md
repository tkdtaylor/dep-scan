# Test Spec — Task 022: Popularity + v0.3 integration tests

## Unit tests (PopularityPolicy)

### T-022-01: High download count passes
- metadata.downloads = Some(1000000), min_downloads = 1000
- Expected: Pass

### T-022-02: Low download count warns
- metadata.downloads = Some(42), min_downloads = 1000
- Expected: Warn mentioning download count

### T-022-03: No download data passes
- metadata.downloads = None
- Expected: Pass

### T-022-04: Configurable threshold
- min_downloads = 50, downloads = Some(42)
- Expected: Warn

## Integration tests

### T-022-05: crates.io package check e2e
- wiremock serves crates.io JSON for a crate
- dep-scan check test-crate --registry crates
- Expected: exit 0 or 1, output shows policy results

### T-022-06: Go module check e2e
- wiremock serves Go proxy responses
- dep-scan check test-module --registry go
- Expected: exit 0 or 1, output shows policy results

### T-022-07: Low-popularity warning in output
- wiremock returns crate with downloads: 5
- Expected: output contains popularity warning

### T-022-08: JSON output includes all registries
- Run with --json against wiremock crates.io
- Expected: valid JSON with policies array

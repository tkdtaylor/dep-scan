# Test Spec — Task 010: ScanContext + multi-policy pipeline refactor

## Unit tests

### T-010-01: ScanContext construction with minimal data
- Create ScanContext with PackageMetadata and empty enrichment fields
- Expected: all fields accessible, vulnerabilities/install_scripts empty

### T-010-02: ScanContext construction with full enrichment
- Create ScanContext with all fields populated
- Expected: all enrichment data accessible

### T-010-03: AgePolicy works with ScanContext
- Create ScanContext wrapping metadata with published_at 72h ago, min_age 48h
- Expected: PolicyResult::Pass (backwards compatible)

### T-010-04: AgePolicy blocks via ScanContext
- Create ScanContext wrapping metadata with published_at 1h ago, min_age 48h
- Expected: PolicyResult::Block

### T-010-05: PolicyDetail captures policy name and result
- Evaluate AgePolicy, wrap result in PolicyDetail
- Expected: policy_name = "age", result and reason populated

### T-010-06: Aggregate results — all pass returns Pass
- Input: [Pass, Pass, Pass]
- Expected: aggregated result = "pass"

### T-010-07: Aggregate results — any block returns Block
- Input: [Pass, Block("reason"), Pass]
- Expected: aggregated result = "block"

### T-010-08: Aggregate results — warn without block returns Warn
- Input: [Pass, Warn("reason"), Pass]
- Expected: aggregated result = "warn"

## Integration tests

### T-010-09: Check with only age policy (backwards compatible)
- Setup: wiremock npm JSON, only age policy enabled
- Run: `dep-scan check old-package --registry npm`
- Expected: same behavior as v0.1 — exit 0, pass result

### T-010-10: JSON output includes policy details array
- Setup: wiremock npm JSON
- Run: `dep-scan check package --registry npm --json`
- Expected: JSON has "policies" array with at least age policy entry

### T-010-11: Multiple policies in output
- Setup: wiremock npm JSON, age policy enabled (package passes age check)
- Expected: output shows individual policy results

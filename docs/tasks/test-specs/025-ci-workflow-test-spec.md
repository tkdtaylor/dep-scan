# Test Spec — Task 025: GitHub Actions CI workflow

## Validation (not automated tests)

### T-025-01: Valid YAML
- .github/workflows/ci.yml parses without errors

### T-025-02: Triggers on push to main
- on.push.branches includes "main"

### T-025-03: Triggers on pull requests
- on.pull_request exists

### T-025-04: Runs cargo test
- steps include `cargo test`

### T-025-05: Runs cargo clippy
- steps include `cargo clippy -- -D warnings`

### T-025-06: Runs cargo fmt --check
- steps include `cargo fmt --check`

### T-025-07: Caches cargo artifacts
- uses actions/cache or similar for ~/.cargo and target/

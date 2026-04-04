# Test Spec — Task 026: GitHub Actions release workflow

## Validation

### T-026-01: Valid YAML
- .github/workflows/release.yml parses without errors

### T-026-02: Triggers on tag push
- on.push.tags includes "v*"

### T-026-03: Matrix includes all 5 targets
- Linux x86_64, Linux ARM64, macOS x86_64, macOS ARM64, Windows x86_64

### T-026-04: Creates GitHub release
- uses softprops/action-gh-release or similar

### T-026-05: Uploads binary artifacts
- Each matrix job uploads its binary

### T-026-06: Generates checksums
- SHA256 checksum file included in release

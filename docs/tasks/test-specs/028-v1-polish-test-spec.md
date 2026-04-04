# Test Spec — Task 028: v1.0 polish and release

## Validation

### T-028-01: Version is 1.0.0
- Cargo.toml version = "1.0.0"
- dep-scan --version shows "dep-scan 1.0.0"

### T-028-02: All tests pass
- cargo test — zero failures

### T-028-03: Clippy clean
- cargo clippy -- -D warnings — no warnings

### T-028-04: README is accurate
- Registry status table reflects current state
- Install instructions include install script
- Test count matches reality

### T-028-05: Roadmap reflects completed milestones
- v0.1, v0.2, v0.3 marked as completed with dates

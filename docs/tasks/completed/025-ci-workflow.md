# Task 025 — GitHub Actions CI workflow

**Status:** backlog
**Depends on:** none

## Objective

Add automated testing CI that runs on every push and PR.

## Acceptance criteria

- [x] .github/workflows/ci.yml exists
- [x] Triggers on push to main and pull requests
- [x] Runs cargo test, cargo clippy, cargo fmt --check
- [x] Caches cargo registry and target directory
- [x] All tests pass, workflow is valid YAML

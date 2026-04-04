# Task 025 — GitHub Actions CI workflow

**Status:** backlog
**Depends on:** none

## Objective

Add automated testing CI that runs on every push and PR.

## Acceptance criteria

- [ ] .github/workflows/ci.yml exists
- [ ] Triggers on push to main and pull requests
- [ ] Runs cargo test, cargo clippy, cargo fmt --check
- [ ] Caches cargo registry and target directory
- [ ] All tests pass, workflow is valid YAML

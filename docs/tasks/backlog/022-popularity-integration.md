# Task 022 — Popularity/download threshold + v0.3 integration tests

**Status:** backlog
**Depends on:** 018, 019, 020, 021

## Objective

Add download popularity warnings and end-to-end integration tests for all v0.3 features.

## Acceptance criteria

- [ ] src/policy/popularity.rs: PopularityPolicy implements Policy
- [ ] Warn if downloads < configurable min_downloads (default 1000)
- [ ] Pass if downloads is None or above threshold
- [ ] Config: [popularity] section with min_downloads
- [ ] Wired into main.rs
- [ ] Integration tests: crates.io e2e, Go module e2e, obfuscation detection, low popularity, --json output
- [ ] All tests pass, clippy clean, fmt clean

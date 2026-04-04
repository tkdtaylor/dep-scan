# Task 022 — Popularity/download threshold + v0.3 integration tests

**Status:** done
**Depends on:** 018, 019, 020, 021

## Objective

Add download popularity warnings and end-to-end integration tests for all v0.3 features.

## Acceptance criteria

- [x] src/policy/popularity.rs: PopularityPolicy implements Policy
- [x] Warn if downloads < configurable min_downloads (default 1000)
- [x] Pass if downloads is None or above threshold
- [x] Config: [popularity] section with min_downloads
- [x] Wired into main.rs
- [x] Integration tests: crates.io e2e, Go module e2e, low popularity, --json output
- [x] All tests pass, clippy clean, fmt clean

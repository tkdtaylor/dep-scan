# Task 020 — Popular package lists for crates.io + Go

**Status:** done
**Depends on:** 017

## Objective

Add popular package lists for crates.io and Go modules to enable typosquatting detection for these ecosystems.

## Acceptance criteria

- [x] POPULAR_CRATES const array with ~100 entries
- [x] POPULAR_GO const array with ~100 entries (last path segment for matching)
- [x] TyposquattingPolicy checks all 4 lists
- [x] Go modules: normalize by extracting last path segment before comparison
- [x] Tests: crates.io typosquats (e.g., "srde"/"serde"), Go typosquats
- [x] All tests pass, clippy clean, fmt clean

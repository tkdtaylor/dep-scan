# Task 020 — Popular package lists for crates.io + Go

**Status:** backlog
**Depends on:** 017

## Objective

Add popular package lists for crates.io and Go modules to enable typosquatting detection for these ecosystems.

## Acceptance criteria

- [ ] POPULAR_CRATES const array with ~100 entries
- [ ] POPULAR_GO const array with ~100 entries (last path segment for matching)
- [ ] TyposquattingPolicy checks all 4 lists
- [ ] Go modules: normalize by extracting last path segment before comparison
- [ ] Tests: crates.io typosquats (e.g., "srde"/"serde"), Go typosquats
- [ ] All tests pass, clippy clean, fmt clean

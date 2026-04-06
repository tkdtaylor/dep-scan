# Task 008 — Minimum package age policy

**Status:** backlog
**Depends on:** 004

## Objective

Implement the minimum package age policy check that blocks packages published too recently.

## Acceptance criteria

- [x] src/policy/mod.rs: `Policy` trait with `fn evaluate(&self, metadata: &PackageMetadata) -> PolicyResult`
- [x] `PolicyResult` enum: `Pass`, `Warn(String)`, `Block(String)`
- [x] src/policy/age.rs: `AgePolicy` struct with configurable `min_age: chrono::Duration`
- [x] Blocks if `published_at` is less than `min_age` ago
- [x] Passes if package is old enough
- [x] Handles missing `published_at` (warn or block, configurable)
- [x] Tests: 1h old package (block), 72h old package (pass), exactly at threshold, missing date
- [x] All tests pass, clippy clean, fmt clean

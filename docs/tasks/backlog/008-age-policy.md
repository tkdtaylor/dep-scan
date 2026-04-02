# Task 008 — Minimum package age policy

**Status:** backlog
**Depends on:** 004

## Objective

Implement the minimum package age policy check that blocks packages published too recently.

## Acceptance criteria

- [ ] src/policy/mod.rs: `Policy` trait with `fn evaluate(&self, metadata: &PackageMetadata) -> PolicyResult`
- [ ] `PolicyResult` enum: `Pass`, `Warn(String)`, `Block(String)`
- [ ] src/policy/age.rs: `AgePolicy` struct with configurable `min_age: chrono::Duration`
- [ ] Blocks if `published_at` is less than `min_age` ago
- [ ] Passes if package is old enough
- [ ] Handles missing `published_at` (warn or block, configurable)
- [ ] Tests: 1h old package (block), 72h old package (pass), exactly at threshold, missing date
- [ ] All tests pass, clippy clean, fmt clean

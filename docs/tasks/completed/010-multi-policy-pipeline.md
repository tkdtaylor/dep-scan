# Task 010 — ScanContext + multi-policy pipeline refactor

**Status:** completed
**Depends on:** v0.1 complete

## Objective

Refactor the check pipeline from single-policy to multi-policy evaluation. Introduce ScanContext as the enriched data container that all policies evaluate against.

## Acceptance criteria

- [x] src/types.rs: `ScanContext`, `VulnerabilityInfo`, `InstallScript` structs added
- [x] src/policy/mod.rs: `Policy` trait updated to `fn evaluate(&self, ctx: &ScanContext) -> PolicyResult`
- [x] src/policy/mod.rs: `PolicyDetail` struct added (policy_name, result, reason)
- [x] src/policy/age.rs: Updated to use `ctx.metadata.published_at`
- [x] src/main.rs: `run_check` builds `Vec<Box<dyn Policy>>` from config toggles
- [x] src/main.rs: Evaluates all enabled policies per package, collects results
- [x] src/main.rs: Aggregates results — worst wins (Block > Warn > Pass)
- [x] CheckResult updated to include per-policy details
- [x] Human-readable output shows per-policy results
- [x] JSON output includes array of policy results per package
- [x] All existing v0.1 tests still pass
- [x] All tests pass, clippy clean, fmt clean

# Task 010 — ScanContext + multi-policy pipeline refactor

**Status:** backlog
**Depends on:** v0.1 complete

## Objective

Refactor the check pipeline from single-policy to multi-policy evaluation. Introduce ScanContext as the enriched data container that all policies evaluate against.

## Acceptance criteria

- [ ] src/types.rs: `ScanContext`, `VulnerabilityInfo`, `InstallScript` structs added
- [ ] src/policy/mod.rs: `Policy` trait updated to `fn evaluate(&self, ctx: &ScanContext) -> PolicyResult`
- [ ] src/policy/mod.rs: `PolicyDetail` struct added (policy_name, result, reason)
- [ ] src/policy/age.rs: Updated to use `ctx.metadata.published_at`
- [ ] src/main.rs: `run_check` builds `Vec<Box<dyn Policy>>` from config toggles
- [ ] src/main.rs: Evaluates all enabled policies per package, collects results
- [ ] src/main.rs: Aggregates results — worst wins (Block > Warn > Pass)
- [ ] CheckResult updated to include per-policy details
- [ ] Human-readable output shows per-policy results
- [ ] JSON output includes array of policy results per package
- [ ] All existing v0.1 tests still pass
- [ ] All tests pass, clippy clean, fmt clean

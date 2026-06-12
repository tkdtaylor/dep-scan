# Task 108 — Transitive scan path wiring (capstone)

**Status:** backlog
**Depends on:** 104 (verdict rollup), 105 (fetch pool + node budget),
               106 (subtree_digest cache column), 107 (config + CLI flag)
**ADR:** 009 (capstone — wires all transitive pieces into the real CLI entry point)
**Scope:** medium
**Touches:** `src/main.rs` (scan arm wiring, gate on `[transitive].enabled`,
            render diagnostics), `src/transitive/mod.rs` (entry-point fn)

## Objective

Wire the transitive walker (task 103), rollup (task 104), fetch pool (task 105),
subtree-digest cache (task 106), and config (task 107) into the `src/main.rs`
check/install scan arm, gated behind `[transitive].enabled`. Render the final
aggregated transitive verdict and all diagnostics (`DepthLimitReached`,
`CycleDetected`, `NodeBudgetExceeded`, `UnresolvedRange`) in both native and
machine formats, reusing `render_native` from task 098.

All integration tests use local fixtures or a local git daemon — **zero external
network**.

## Background

This is the capstone task of the transitive resolution epic (ADR 009). It is the
only task that modifies `src/main.rs`'s scan entry points. Everything else is
callable in isolation; this task assembles them into the live CLI path.

## Requirements

### REQ-108-01: Gate on [transitive].enabled
When `[transitive].enabled = false` (or `--no-transitive`), the scan arm
produces output **byte-for-byte identical** to the pre-transitive flat scan.
The DFS walker, fetch pool, and subtree-digest code paths are never entered.

### REQ-108-02: Core malicious-transitive-child scenario (primary acceptance test)
When `[transitive].enabled = true` and a clean direct dep pulls in a malicious
transitive git sub-tree, the final exit code is 1 (Block) and the output names
the malicious sub-tree as the source of the Block verdict.

### REQ-108-03: All diagnostics surfaced in both output formats
`DepthLimitReached`, `CycleDetected`, `NodeBudgetExceeded`, and
`UnresolvedRange` diagnostics appear in `--format json` and `--format native`
output.

### REQ-108-04: render_native is reused, not reimplemented
The table formatter from task 098 is called directly. No duplicate
table-rendering logic is written.

### REQ-108-05: Fetch pool and node budget are active in the wired path
`fetch_concurrency` and `max_total_nodes` from the config (task 107) are
passed to the fetch pool (task 105). `NodeBudgetExceeded` → exit code ≥ 1.

### REQ-108-06: subtree_digest invalidation works end-to-end
Warm cache: second scan of an unchanged tree → all cache hits, no git fetches.
Changed child: second scan after child changes → parent's subtree_digest
mismatches → parent re-scanned → new verdict propagated to root.

### REQ-108-07: CLI flag wired in scan arm
`--transitive` and `--no-transitive` reach the scan arm; they override config.

### REQ-108-08: Zero external network in integration tests
All integration tests (T-108-04 through T-108-18) use local fixtures or a
local git daemon.

## Acceptance criteria

- [ ] enabled=false output byte-for-byte identical to flat scan (T-108-02..03)
- [ ] Clean direct dep + malicious transitive child → root Block (T-108-04)
- [ ] All-clean transitive tree → root Pass (T-108-05)
- [ ] DepthLimitReached diagnostic in JSON output (T-108-06)
- [ ] DepthLimitReached diagnostic in native output (T-108-07)
- [ ] NodeBudgetExceeded diagnostic in both formats (T-108-08)
- [ ] CycleDetected diagnostic in both formats (T-108-09)
- [ ] render_native reused (T-108-10)
- [ ] JSON output is valid (T-108-11)
- [ ] Native output includes transitive verdict rows (T-108-12)
- [ ] --transitive CLI flag triggers transitive scan (T-108-13)
- [ ] --no-transitive CLI flag suppresses transitive scan (T-108-14)
- [ ] fetch_concurrency respected in wired path (T-108-15)
- [ ] max_total_nodes exceeded → scan fails closed (T-108-16)
- [ ] Warm cache → no git fetches on second run (T-108-17)
- [ ] Changed child → parent re-scanned (T-108-18)
- [ ] Zero external network in all integration tests (T-108-01)
- [ ] All T-108-01 through T-108-19 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/108-transitive-scan-path-wiring-test-spec.md`

## Out of scope

- Manifest range resolution for lockfile-less repos (task 109, deferred)
- New policies specific to transitive scanning (future work)
- UI changes beyond the existing `render_native` table format

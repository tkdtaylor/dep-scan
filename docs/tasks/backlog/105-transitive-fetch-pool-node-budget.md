# Task 105 — Transitive fetch pool + node budget

**Status:** backlog
**Depends on:** 103 (walker integration — fetch pool wraps the git fetch path
               already wired in 103)
**ADR:** 009 (piece 5 — Decision 3b mitigations 4 and 5)
**Scope:** medium
**Touches:** `src/transitive/pool.rs` (new — bounded fetch pool),
            `src/transitive/budget.rs` (new — node budget counter),
            `src/transitive/` (integration with the DFS engine)

## Objective

Introduce a **bounded worker pool** for git sub-tree fetches (`fetch_concurrency`
config key, small default like 4) and a **`max_total_nodes` safety ceiling** that
fails the scan closed with a `NodeBudgetExceeded` diagnostic when exceeded.

Both mitigations compose with `vcs.fetch_timeout_secs` from task 096 and the
pack-size caps already in the fetch client, bounding total work to:
`(vcs.fetch_timeout_secs × ceil(distinct_git_nodes / fetch_concurrency))`.

**No specific thread-pool or async-runtime crate is prescribed.** The algorithm
(bounded concurrency, queue, semaphore / permit model) is specified here; crate
selection is an implementation decision.

## Background

ADR 009 Decision 3b mitigations 4 and 5:
- Without a fetch pool, a wide dependency tree would open unbounded connections.
- Without a node budget, a pathological graph could blow past the dedup bound.
- The node budget is a second line of defence; it is not optional (silent
  truncation to Pass is prohibited).

## Requirements

### REQ-105-01: Bounded fetch pool — `fetch_concurrency` config key
The pool limits the number of simultaneously in-flight git sub-tree fetches.
Default: 4 (configurable via task 107). At no time may more than
`fetch_concurrency` fetches be executing concurrently.

### REQ-105-02: Pool does not deadlock with fetch_concurrency = 1
Serial execution (all fetches queued) must complete without deadlock.

### REQ-105-03: `max_total_nodes` safety ceiling — fail-closed
When the number of distinct nodes enqueued for scanning exceeds
`max_total_nodes`, the scan fails with a `NodeBudgetExceeded` diagnostic.
The scan result is ≥ Warn (never Pass). Silent truncation to Pass is
**prohibited** (fail-closed callout in T-105-05).

### REQ-105-04: `NodeBudgetExceeded` diagnostic is emitted and surfaced in both output formats
The diagnostic message includes the node count and the limit.

### REQ-105-05: Dedup prevents double-counting in node budget
The budget counter increments at most once per distinct `NodeId` (visited-set
dedup from task 102). A diamond dep D reachable from two paths counts as 1 node.

### REQ-105-06: Compose with vcs.fetch_timeout_secs
Each fetch task in the pool respects the per-fetch timeout from task 096.
A timed-out fetch is treated as unfetchable (≥ Warn to parent) and does not
hang the entire scan.

### REQ-105-07: No specific crate prescribed
The implementation uses any bounded-concurrency primitive available in the Rust
ecosystem (channel + semaphore, rayon, tokio, etc.). This task does not mandate
a choice.

## Acceptance criteria

- [ ] `fetch_concurrency = 2` caps peak concurrency at 2 (T-105-01)
- [ ] `fetch_concurrency = 1` serialises all fetches (T-105-02)
- [ ] All queued fetches complete without deadlock (T-105-03)
- [ ] No unbounded socket fan-out (T-105-04)
- [ ] Exceeding `max_total_nodes` fails closed with diagnostic (T-105-05..06)
- [ ] `max_total_nodes = 0` fails immediately (T-105-07)
- [ ] Diamond dedup means D counted once in budget (T-105-08)
- [ ] Per-fetch timeout respected in pool (T-105-09)
- [ ] Concurrency actually reduces wall-clock time (T-105-10)
- [ ] No crate name hard-coded in task contract (T-105-11)
- [ ] All T-105-01 through T-105-12 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/105-transitive-fetch-pool-node-budget-test-spec.md`

## Out of scope

- subtree_digest cache column (task 106)
- Config parsing (task 107 provides the config values; this task reads them)
- Main.rs wiring (task 108)

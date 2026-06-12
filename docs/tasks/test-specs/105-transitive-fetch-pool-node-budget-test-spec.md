# Test Spec — Task 105: Transitive fetch pool + node budget

## Context

ADR 009 piece 5 (Decision 3b mitigations 4 and 5). Introduces a bounded worker
pool for git sub-tree fetches (`fetch_concurrency`, configurable, small default
like 4) and a `max_total_nodes` safety ceiling that fails the scan closed with a
diagnostic when exceeded. Composes with `vcs.fetch_timeout_secs` from task 096.
No specific thread-pool or async-runtime crate is named — the model and contract
are specified here; crate selection is deferred to implementation.

---

## Bounded concurrency

### T-105-01: fetch_concurrency limits simultaneous in-flight git fetches
- Configure `fetch_concurrency = 2`.
- Enqueue 6 git sub-tree fetch tasks (mocked with a controlled delay).
- At no point are more than 2 fetch tasks executing concurrently.
- Assert via a concurrency counter (atomic increment on start, decrement on
  finish) that the peak concurrent count never exceeds 2.

### T-105-02: fetch_concurrency = 1 serialises all fetches
- Same setup; `fetch_concurrency = 1`.
- Peak concurrent count equals 1 throughout the scan.

### T-105-03: All queued fetches complete when pool size < task count
- Configure `fetch_concurrency = 2`; 5 fetch tasks.
- All 5 tasks eventually complete (pool does not deadlock or drop tasks).

### T-105-04: No unbounded socket fan-out — pool exhausts bounded resources
- Simulate a tree with 100 distinct git sub-tree nodes.
- The pool opens at most `fetch_concurrency` connections simultaneously.
- Assert no unbounded-socket-fan-out diagnostic is emitted from the pool itself.

---

## max_total_nodes ceiling — fail-closed

### T-105-05: Exceeding max_total_nodes fails the scan closed with a diagnostic
- Configure `max_total_nodes = 10`.
- Walk a graph with 15 distinct nodes.
- When the 11th node is enqueued, the scan fails with a `NodeBudgetExceeded`
  diagnostic.
- The scan result is Warn or Block (fail-closed); it is NOT silently truncated to
  Pass with the first 10 nodes passing.
- (Fail-closed callout: silent truncation to Pass would allow an attacker to
  hide a malicious node past the budget; the budget must fail closed, not silent.)

### T-105-06: NodeBudgetExceeded diagnostic is emitted and visible in output
- Same setup as T-105-05.
- The diagnostic message includes the node count and the configured
  `max_total_nodes` limit.
- Diagnostic appears in `--format json` output and `--format native` output.

### T-105-07: max_total_nodes = 0 fails immediately for any non-empty graph
- Configure `max_total_nodes = 0`.
- Any graph with at least one node triggers `NodeBudgetExceeded` immediately.
- Scan result is ≥ Warn.

### T-105-08: max_total_nodes budget is not exhausted by the dedup visited set
- Configure `max_total_nodes = 100`.
- Walk a diamond graph: A → {B, C}; B → {D}; C → {D} (4 distinct nodes).
- D is counted once in the budget (visited-set dedup), not twice.
- Budget consumption is 4, not 5.

---

## Composition with vcs.fetch_timeout_secs

### T-105-09: Per-fetch timeout from vcs.fetch_timeout_secs is respected in the pool
- Configure `vcs.fetch_timeout_secs = 1`.
- One of the pool's mock fetch tasks hangs beyond 1 second.
- The hanging fetch is cancelled/timed-out and returns an error.
- The scan continues (or fails closed) rather than hanging indefinitely.
- (Fail-closed callout: a timed-out fetch is treated as unfetchable, contributing
  ≥ Warn to the parent's verdict.)

### T-105-10: Total wall-clock time for N fetches is bounded by ceil(N / fetch_concurrency) * timeout
- Configure `fetch_concurrency = 2`, `vcs.fetch_timeout_secs = 2`, 4 tasks each
  taking 1 second.
- Total time is approximately 2 seconds (two rounds of 2 parallel tasks), not
  4 seconds (sequential).
- Confirm the concurrency actually helps: time < 1.9 * (N/concurrency) * per_fetch.

---

## No premature crate choice

### T-105-11: Pool implementation uses no specific thread-pool or async-runtime crate name in the task contract
- This assertion is a design review: the task file and spec name the algorithm
  (bounded worker pool, queue, semaphore or permit model) without mandating
  a specific Rust crate.
- Confirmed: neither the spec nor the task file contains a hard `extern crate`
  requirement for the concurrency primitive.

---

## Tooling gate

### T-105-12: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

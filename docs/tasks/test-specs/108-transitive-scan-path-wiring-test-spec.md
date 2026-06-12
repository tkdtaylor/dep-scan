# Test Spec — Task 108: Transitive scan path wiring (capstone)

## Context

ADR 009 capstone task. Wires the transitive walker (task 103), rollup (task 104),
fetch pool (task 105), cache (task 106), and config (task 107) into the
`src/main.rs` scan arm, gated behind `[transitive].enabled`. Renders the final
aggregated verdict and diagnostics in both native and machine output formats
(reusing `render_native` from task 098). All integration tests use local fixtures
or a local git daemon — zero external network.

---

## Zero-external-network integration

### T-108-01: End-to-end transitive scan uses only local fixtures or local git daemon
- All assertions in this spec run against pre-staged local repositories and
  fixture lockfiles.
- No call to a public internet endpoint.
- Assert: tests pass in a network-isolated environment.

---

## Gate: enabled=false produces no change (non-regression)

### T-108-02: enabled=false output is identical to today's flat scan (byte-for-byte)
- Use a fixture `package-lock.json` with a known dep tree.
- Run with `[transitive] enabled = false`.
- Captured output (stdout, stderr, exit code) is byte-for-byte identical to the
  same run before task 108 was applied.
- (Non-regression: the capstone wiring must not alter flat-scan behaviour when
  the feature is disabled.)

### T-108-03: enabled=false means the DFS walker code path is never entered
- With `enabled = false`, no call to `dfs_walk` or the fetch pool is made.
- Assert via a spy that the transitive entry point is not invoked.

---

## Core malicious-transitive-child scenario

### T-108-04: Clean direct dep with malicious transitive child → root Block
- Fixture: `package-lock.json` declaring dep A (clean); dep A depends on dep B
  (a git sub-tree with a malicious `postinstall.js`).
- Dep B fixture is a local git repo with the install script.
- Run with `[transitive] enabled = true`.
- Exit code: 1 (Block).
- Output (native or JSON) shows dep B as Block and the root as Block (or dep A
  as Block via rollup).
- (Fail-closed callout: this is the primary scenario ADR 008 motivates — a
  malicious transitive node cannot hide behind a clean direct dep.)

### T-108-05: All-clean transitive tree → root Pass
- Fixture lockfile with a two-level tree; all nodes are clean.
- Exit code: 0 (Pass).

---

## Diagnostics rendered in output

### T-108-06: DepthLimitReached diagnostic appears in --format json output
- Fixture tree deeper than `max_depth`.
- JSON output contains a `DepthLimitReached` entry with the node ID and depth.

### T-108-07: DepthLimitReached diagnostic appears in --format native output
- Same fixture.
- Native table shows the cut node with a Warn indicator and a depth-limit note.

### T-108-08: NodeBudgetExceeded diagnostic appears in output when max_total_nodes hit
- Fixture tree with more distinct nodes than `max_total_nodes`.
- Both JSON and native outputs contain the `NodeBudgetExceeded` diagnostic.
- Exit code is ≥ 1 (Warn or Block — not 0).

### T-108-09: CycleDetected diagnostic appears in output
- Fixture lockfile with a known cyclic dep (A→B→A, constructed manually).
- Both JSON and native outputs contain the `CycleDetected` diagnostic naming
  the back-edge.

---

## Output format compliance

### T-108-10: render_native is reused from task 098 (not reimplemented)
- The wiring calls `render_native` (or the shared render helper from task 098)
  rather than writing a new table formatter.
- Confirmed by code inspection: no duplicate table-rendering logic.

### T-108-11: --format json output for transitive scan is valid JSON
- Run transitive scan with `--format json` on a fixture.
- Output is parseable JSON with no trailing garbage.

### T-108-12: --format native output for transitive scan includes transitive verdict rows
- Run transitive scan with `--format native` on a fixture.
- The table includes rows for transitive deps (not only direct deps).
- Each row shows the node name, depth, and verdict.

---

## CLI flag wiring

### T-108-13: --transitive CLI flag triggers transitive scan even when config has enabled=false
- Config: `[transitive] enabled = false`.
- Invocation: `dep-scan check --transitive`.
- Transitive walker is entered; output differs from flat scan.

### T-108-14: --no-transitive CLI flag suppresses transitive scan even when config has enabled=true
- Config: `[transitive] enabled = true`.
- Invocation: `dep-scan check --no-transitive`.
- Output is identical to the flat scan.

---

## Fetch pool and budget in wired path

### T-108-15: fetch_concurrency is respected in the wired scan arm
- Configure `fetch_concurrency = 1`.
- Fixture tree has 3 git sub-tree nodes (local daemon).
- Assert: the three fetches occur serially (peak concurrency ≤ 1), the scan
  completes, and all three nodes are scanned.

### T-108-16: max_total_nodes exceeded in the wired path fails scan closed
- Configure `max_total_nodes = 2`.
- Fixture lockfile has 5 nodes.
- Scan exits with code ≥ 1 and emits `NodeBudgetExceeded`.

---

## Cache integration in wired path

### T-108-17: Warm cache serves transitive hit (subtree_digest valid)
- First scan: populate cache with all transitive results.
- Second scan (same fixture, same deps): all nodes are cache hits; no git
  fetches occur.
- Assert: `VcsFetcher::fetch` is not called on the second run.

### T-108-18: Changed child verdict invalidates parent cache entry
- Prime cache; then simulate one child's verdict changing (e.g. re-stage
  fixture with a malicious file).
- Second scan: parent's subtree_digest mismatch → parent re-scanned →
  new Block verdict propagated to root.
- Root is Block, not the stale Pass from the first scan.

---

## Tooling gate

### T-108-19: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

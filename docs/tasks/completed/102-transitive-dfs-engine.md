# Task 102 — Transitive DFS engine (pure algorithmic core)

**Status:** backlog
**Depends on:** 100 (NodeId type must exist)
**ADR:** 009 (piece 3a — Decisions 2a, 2b; the pure DFS core)
**Scope:** large (split from ADR 009 item 3 — this is the unit-testable core)
**Touches:** `src/transitive/` (new module), `src/transitive/engine.rs`
            (or equivalent path)

## Objective

Implement the algorithmic core of the transitive walker as a fully unit-testable
component operating over **abstract traits** (`EdgeProvider` and `NodeScanner`).
No real lockfile, no real manifest, no real git fetch. The engine must be
exhaustively tested in isolation.

This task does **not** wire any concrete I/O. Wiring happens in task 103.

## Background

ADR 009 Decision 2a/2b: visited-set DFS, `path` stack for cycle detection,
`max_depth` config, `on_depth_limit` action, `DepthLimitReached` /
`CycleDetected` / `UnresolvedRange` diagnostics.

Key invariants:
- `visited: HashSet<NodeId>` — every already-scanned (or in-flight) node.
- `path: Vec<NodeId>` — active DFS root-to-current path.
- Child on `visited` but not on `path` → diamond/re-visit: reuse verdict,
  do NOT re-scan.
- Child on `path` → cycle: emit `CycleDetected`, do not recurse.
- Edge crossing `max_depth + 1` → emit `DepthLimitReached`, parent gets ≥ Warn.

## Requirements

### REQ-102-01: Define `EdgeProvider` trait
```
trait EdgeProvider {
    fn edges_for(&self, node: &NodeId) -> Result<Vec<NodeId>, EdgeError>;
}
```
Where `EdgeError` carries enough information for the engine to emit a diagnostic.

### REQ-102-02: Define `NodeScanner` trait
```
trait NodeScanner {
    fn scan(&self, node: &NodeId) -> Verdict;
}
```
Returns a `Verdict` (Pass / Warn / Block equivalent) for the given node.

### REQ-102-03: DFS traversal with visited-set dedup
- `visited: HashSet<NodeId>` prevents re-scanning the same node.
- Diamond graphs are handled: D reachable via two paths is scanned once.

### REQ-102-04: Path-stack cycle detection
- A `path` (or path-as-set) tracks the current root-to-node branch.
- "Child already on path?" → `CycleDetected`; do not recurse.
- Covers both A→A and A→B→A with the same membership test.

### REQ-102-05: Depth-limit enforcement, fail-closed
- When an edge would cross depth `max_depth + 1`, emit `DepthLimitReached`.
- The parent's verdict for that edge is ≥ Warn (or Block if
  `on_depth_limit = Block`).
- Never silently pass a depth-limited node.

### REQ-102-06: Depth parameter is a function argument
- `max_depth` is passed into `dfs_walk` as a parameter (not a hardcoded
  constant). Default `5` lives in config (task 107).

### REQ-102-07: UnresolvedRange edges emit diagnostic and contribute ≥ Warn
- An `EdgeProvider` returning `EdgeError::UnresolvedRange` causes the engine
  to emit a diagnostic and assign ≥ Warn to the parent.

### REQ-102-08: Zero I/O with mocked providers
- All tests in this task use in-memory mock providers.
- The engine itself has no I/O calls; asserted by T-102-01.

## Acceptance criteria

- [ ] `EdgeProvider` and `NodeScanner` traits defined
- [ ] Depth-0 returns only root (T-102-02)
- [ ] Each hop increments depth by 1 (T-102-03)
- [ ] Full traversal at sufficient depth visits all nodes (T-102-04)
- [ ] Depth-limit cut emits DepthLimitReached and ≥ Warn (T-102-05..07)
- [ ] Diamond dedup: node scanned exactly once (T-102-08..09)
- [ ] Direct cycle detected without infinite loop (T-102-10)
- [ ] Indirect cycle detected without infinite loop (T-102-11)
- [ ] Clean cycle rolls up Pass (T-102-12)
- [ ] Cycle through Warn node carries Warn (T-102-13)
- [ ] Back-edge never re-traversed (T-102-14)
- [ ] UnresolvedRange → diagnostic + ≥ Warn (T-102-15)
- [ ] Visited set keyed on NodeId, not name alone (T-102-16)
- [ ] Path-stack test covers both cycle types (T-102-17)
- [ ] All T-102-01 through T-102-18 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/102-transitive-dfs-engine-test-spec.md`

## Out of scope

- Concrete `EdgeProvider` impls (task 103)
- Concrete `NodeScanner` impls (task 103)
- Verdict rollup propagation (task 104 — previewed in T-102-06 but not
  the full rollup logic)
- Fetch pool (task 105)
- Config parsing (task 107)

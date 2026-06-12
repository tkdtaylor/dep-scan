# Test Spec — Task 102: Transitive DFS engine (pure algorithmic core)

## Context

ADR 009 piece 3a. The pure algorithmic core of the transitive walker: a
visited-set DFS over abstract `EdgeProvider` and `NodeScanner` traits with
depth-limit enforcement, cycle detection, and diagnostic production. All tests
use mocked/in-memory providers — zero network I/O, zero real lockfile or
manifest parsing. This is the component that can be exhaustively unit-tested
in isolation.

---

## Zero-network / zero-I/O contract

### T-102-01: DFS engine performs zero I/O with mocked providers
- Construct the engine with a mock `EdgeProvider` and mock `NodeScanner`
  (in-memory maps, no file or network access).
- Run `dfs_walk(root, max_depth, ...)`. The test must complete without any file
  read, network call, or system call beyond memory allocation.
- (Fail-closed callout: the engine itself never fetches anything; fetching is
  the responsibility of the concrete `NodeScanner` injected by task 103.)

---

## Basic traversal correctness

### T-102-02: Depth 0 returns only the root node (direct entries only)
- Edge graph: A → {B, C}; B → {D}; C → {}; D → {}.
- `dfs_walk(root=A, max_depth=0)` scans only A.
- B, C, D are NOT visited.

### T-102-03: Each hop increments depth by exactly 1
- Same graph as T-102-02; `max_depth = 1`.
- A (depth 0) and B, C (depth 1) are scanned.
- D (depth 2) is NOT scanned.

### T-102-04: Full traversal at sufficient depth visits all reachable nodes
- Graph: A → {B, C}; B → {D}; C → {D}; D → {}.
- `max_depth = 5` (more than enough).
- All four nodes A, B, C, D are scanned exactly once (diamond dedup — see T-102-08).

---

## Depth-limit enforcement — fail-closed

### T-102-05: An edge crossing max_depth+1 is cut and emits DepthLimitReached
- Graph: A → B → C → D → E → F → G (linear chain, depth 6 from A).
- `max_depth = 5`.
- Node at depth 6 (G) is NOT scanned.
- A `DepthLimitReached { node: G_id, depth: 6 }` diagnostic is emitted.
- (Fail-closed callout: the cut node must never receive Pass. The parent at
  depth 5 rolls up at least Warn for this unscanned child. Attacker cannot
  hide a malicious node by burying it past the depth limit.)

### T-102-06: Depth-limited node contributes at least Warn to parent verdict
- Same setup as T-102-05. Mock `NodeScanner` returns Pass for every scanned node.
- The rolled-up verdict for the depth-5 node (F) must be ≥ Warn because its
  child G was cut.
- The root verdict is ≥ Warn even though every explicitly scanned node passed.

### T-102-07: on_depth_limit="block" escalates cut nodes to Block
- Same setup; engine configured with `on_depth_limit = Block`.
- The depth-5 node (F) receives Block (not merely Warn) for its unscanned child.
- Root verdict is Block.

---

## Diamond / re-visit deduplication

### T-102-08: A node reached by two paths is scanned exactly once
- Graph: A → {B, C}; B → {D}; C → {D}. (D reachable via A→B→D and A→C→D.)
- `dfs_walk` with `max_depth = 5`.
- `NodeScanner::scan(D)` is called exactly once (not twice).
- Assert the mock scanner's call count for D equals 1.

### T-102-09: Re-visited node's verdict is reused, not re-scanned
- Same graph; mock scanner returns Warn for D.
- Both B's rollup and C's rollup incorporate D's Warn without re-invoking
  `scan(D)`.

---

## Cycle detection — fail-closed

### T-102-10: Direct self-cycle A → A is detected; CycleDetected diagnostic emitted
- Graph: A → {A} (self-loop).
- `dfs_walk` terminates without infinite recursion.
- `CycleDetected { back_edge: (A→A) }` diagnostic emitted.
- A's verdict is computed from its own scan result (not from the back-edge).

### T-102-11: Indirect cycle A → B → A is detected; no infinite loop
- Graph: A → {B}; B → {A}.
- Walk terminates; `CycleDetected` diagnostic emitted naming the A→B→A back-edge.

### T-102-12: Cycle through a clean node rolls up Pass
- Graph: A → {B}; B → {A}. Mock scanner returns Pass for both A and B.
- After cycle detection, the root verdict is Pass (cycle itself is not a failure).

### T-102-13: Cycle through a Warn node carries that verdict upward
- Graph: A → {B}; B → {A}. Mock scanner returns Pass for A, Warn for B.
- Root verdict is Warn (worst-verdict-wins; the back-edge does not suppress B's
  Warn).
- (Fail-closed callout: a cycle cannot be used to hide a Warn/Block — the node
  on the path has already been scanned and its verdict participates in rollup.)

### T-102-14: Back-edge is never re-traversed (no double-scan of on-path node)
- Same graph as T-102-11; mock scanner tracks call counts.
- A and B are each scanned exactly once despite the cycle.

---

## UnresolvedRange diagnostic

### T-102-15: An UnresolvedRange edge emits a diagnostic and contributes at least Warn
- `EdgeProvider` returns an edge to a `NodeId::UnresolvedRange { range: "^1.0" }`
  (or equivalent sentinel).
- The engine emits `UnresolvedRange` diagnostic for that edge.
- The parent's verdict is ≥ Warn (fail-closed: unresolvable range = unscanned).
- (Fail-closed callout: an attacker cannot supply a range that cannot be pinned
  and have it silently pass.)

---

## Visited set and NodeId identity

### T-102-16: Visited set is keyed on NodeId, not on name alone
- Graph contains two nodes with the same package name but different versions:
  `NodeId::Registry { name:"foo", version:"1.0", registry:"npm" }` and
  `NodeId::Registry { name:"foo", version:"2.0", registry:"npm" }`.
- Both are scanned independently (they are different NodeIds).

### T-102-17: Path stack and visited set agree — on-path membership test covers both cycle types
- Run through T-102-10 (direct) and T-102-11 (indirect) scenarios with a
  single code path: the "is child already on the current path?" check.
- Confirm no special-casing: the same code that catches A→A also catches A→B→A.

---

## Tooling gate

### T-102-18: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

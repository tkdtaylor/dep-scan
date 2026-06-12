# Test Spec — Task 104: Transitive verdict rollup

## Context

ADR 009 piece 4 (Decision 2c). Propagates each scanned node's verdict upward
through the DFS post-order via worst-verdict-wins, using `aggregate_results`
from `src/main.rs`. Unscannable nodes (unfetchable, depth-limited,
`UnresolvedRange`) contribute ≥ Warn to their parent's verdict — never Pass.
Reuses the `aggregate_results` function already present in the codebase.

---

## Worst-verdict-wins propagation

### T-104-01: All-Pass subtree rolls up to Pass at root
- Tree: root → A → B (linear).
- Scanner returns Pass for A, Pass for B.
- Root verdict after rollup: Pass.

### T-104-02: A single Block anywhere in the subtree makes the root Block
- Tree: root → A → B; B scans Block, A scans Pass.
- Root verdict: Block.
- (Fail-closed callout: Block cannot be suppressed by a passing ancestor.)

### T-104-03: A single Warn propagates upward unless something worse exists
- Tree: root → A → B; B scans Warn, A scans Pass, root scans Pass.
- Root verdict: Warn.

### T-104-04: Block is worse than Warn — Block wins over Warn
- Tree: root → {A, B}; A scans Block, B scans Warn.
- Root verdict: Block.

### T-104-05: Rollup is monotonically upward — child can only raise, never lower, an ancestor
- Tree: root scans Block; its only child scans Pass.
- Root verdict stays Block (child Pass does not lower it).

### T-104-06: aggregate_results is reused, not reimplemented
- The rollup function calls the existing `aggregate_results` from `src/main.rs`
  rather than containing its own worst-verdict comparison logic.
- Confirmed by code inspection (no duplicate worst-verdict comparison).

---

## Unscannable node floor — fail-closed assertions

### T-104-07: Unfetchable child contributes at least Warn to parent verdict
- Tree: root → A; A's git fetch fails.
- A is marked as unscannable (unfetchable).
- Root verdict: ≥ Warn (never Pass).
- (Fail-closed callout: an attacker cannot hide a malicious node by making it
  unfetchable — the unfetchable node floors the parent at Warn/Block.)

### T-104-08: Depth-limit cut node contributes at least Warn to parent verdict
- Tree: root → A at depth 5; A has a child at depth 6 (cut by DepthLimitReached).
- A's rollup is ≥ Warn even if A's own scan returned Pass.
- Root verdict: ≥ Warn.
- (Fail-closed callout: a node buried past the depth limit cannot silently pass.)

### T-104-09: UnresolvedRange edge contributes at least Warn to parent verdict
- Tree: root → A; A's edge to B is an UnresolvedRange.
- A's rollup is ≥ Warn (B is effectively unscanned).
- Root verdict: ≥ Warn.
- (Fail-closed callout: an unresolvable version range = an unscanned dep.)

### T-104-10: on_depth_limit="block" escalates depth-limited child to Block
- Same scenario as T-104-08, with `on_depth_limit = Block` config.
- A's rollup from the cut child is Block (not merely Warn).
- Root verdict: Block.

---

## Attacker-cannot-hide assertions

### T-104-11: Attacker cannot hide a Block node by making it unfetchable
- Tree: root → A → B. B would scan Block if reachable.
- Simulate B as unfetchable (e.g. `NodeScanner` returns fetch error for B).
- A's verdict is ≥ Warn (unfetchable floor).
- Root verdict is ≥ Warn.
- The attacker's malicious node never silently produces Pass at the root.

### T-104-12: Attacker cannot hide a Block node by burying it past the depth limit
- Tree: root at depth 0, B at depth 6. B would scan Block if reachable.
- B is cut by DepthLimitReached.
- Root verdict is ≥ Warn (depth-limit floor propagates up).

### T-104-13: Attacker cannot hide a Block node inside a cycle
- Tree: A → B → A (cycle). B scans Block.
- CycleDetected is emitted; B's Block verdict is used in rollup (not suppressed).
- Root verdict is Block.

---

## Rollup composition with aggregate_results

### T-104-14: Rollup composable with single-node fail-closed rule from main.rs
- Simulate the existing single-node git-dep fail-closed path
  (`src/main.rs:1081-1094`): a single unfetchable node returns Warn.
- The transitive rollup of a parent with one unfetchable child also returns
  ≥ Warn, consistent with the single-node rule (generalisation, not a new rule).

---

## Tooling gate

### T-104-15: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

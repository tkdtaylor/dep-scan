# Task 104 — Transitive verdict rollup

**Status:** backlog
**Depends on:** 103 (walker integration — the rollup receives verdicts from
               the wired walker)
**ADR:** 009 (piece 4 — Decision 2c, partial-failure rollup)
**Scope:** medium
**Touches:** `src/transitive/rollup.rs` (new — rollup logic), `src/main.rs`
            (reuse `aggregate_results` — no duplication)

## Objective

Propagate each scanned node's verdict upward through the DFS post-order via
**worst-verdict-wins**, applying the ≥ Warn floor for every unscannable node
(unfetchable, depth-limited, `UnresolvedRange`). Reuses `aggregate_results` from
`src/main.rs` — no new worst-verdict comparison logic is written.

## Background

ADR 009 Decision 2c: the transitive verdict for a parent is the worst verdict
across the parent itself and every node in its scanned subtree. This is a strict
generalisation of the existing single-node fail-closed rule to the tree.

Unscannable nodes — unfetchable, depth-limited, unresolved-range — contribute
**at least Warn** (or Block under `on_depth_limit = Block`). An attacker
therefore cannot hide a malicious node by making it unfetchable, burying it
past the depth limit, or hiding it in a cycle.

Propagation is monotonically upward: a child verdict can only **raise** (never
lower) an ancestor's verdict.

## Requirements

### REQ-104-01: Reuse `aggregate_results` from `src/main.rs`
The rollup function calls the existing `aggregate_results` (worst-verdict-wins).
No duplicate comparison logic is introduced.

### REQ-104-02: Post-order rollup — children before parents
Verdict computation follows DFS post-order: a parent's verdict incorporates all
of its children's (already-computed) verdicts before the parent's own scan
result is folded in.

### REQ-104-03: Unscannable node floor — ≥ Warn
Any node that is unfetchable, depth-limited (DepthLimitReached), or has an
UnresolvedRange edge must contribute **at least Warn** to its parent's rollup.
Never Pass.

### REQ-104-04: on_depth_limit = Block escalates depth-limited nodes to Block
When `on_depth_limit = Block`, depth-limited nodes contribute Block (not merely
Warn) to their parent.

### REQ-104-05: Monotonic upward propagation
A child verdict can only raise an ancestor's verdict. A Block subtree makes the
root Block. A passing root is not lowered by a passing child (it stays Pass).

### REQ-104-06: Fail-closed attacker scenarios
All three "cannot hide" scenarios are explicitly asserted:
1. Unfetchable child → parent ≥ Warn (T-104-07, T-104-11).
2. Depth-limited node → parent ≥ Warn (T-104-08, T-104-12).
3. Cycle through Block/Warn → verdict carries up (T-104-13).

## Acceptance criteria

- [ ] All-Pass subtree → root Pass (T-104-01)
- [ ] Single Block anywhere → root Block (T-104-02)
- [ ] Single Warn propagates upward (T-104-03)
- [ ] Block beats Warn (T-104-04)
- [ ] Propagation is monotonically upward (T-104-05)
- [ ] `aggregate_results` is reused, not reimplemented (T-104-06)
- [ ] Unfetchable child → ≥ Warn, never Pass (T-104-07, T-104-11)
- [ ] Depth-limited node → ≥ Warn (T-104-08, T-104-12)
- [ ] UnresolvedRange → ≥ Warn (T-104-09)
- [ ] on_depth_limit=block → Block (T-104-10)
- [ ] Cycle through Block/Warn carries verdict (T-104-13)
- [ ] Consistent with single-node fail-closed rule (T-104-14)
- [ ] All T-104-01 through T-104-15 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/104-transitive-verdict-rollup-test-spec.md`

## Out of scope

- Fetch pool / node budget (task 105)
- subtree_digest cache column (task 106)
- Config and CLI (task 107)
- Main.rs wiring (task 108)

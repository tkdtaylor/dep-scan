# Test Spec — Task 014: Maintainer change detection

## Unit tests (cache)

### T-014-01: Record and retrieve maintainers
- Record ["alice", "bob"] for "lodash"/"npm"
- get_previous_maintainers → Some(["alice", "bob"])

### T-014-02: No history returns None
- get_previous_maintainers for unrecorded package
- Expected: None

### T-014-03: Record updates existing
- Record ["alice"], then record ["alice", "bob"]
- Expected: latest retrieved is ["alice", "bob"]

## Unit tests (MaintainerChangePolicy)

### T-014-04: First scan (no history) passes
- ScanContext with previous_maintainers = None
- Expected: Pass

### T-014-05: No change passes
- previous_maintainers = Some(["alice", "bob"]), current = ["alice", "bob"]
- Expected: Pass

### T-014-06: Maintainer added warns
- previous = ["alice"], current = ["alice", "bob"]
- Expected: Warn mentioning "bob" added

### T-014-07: Maintainer removed warns
- previous = ["alice", "bob"], current = ["alice"]
- Expected: Warn mentioning "bob" removed

### T-014-08: Complete changeover blocks
- previous = ["alice", "bob"], current = ["charlie", "dave"]
- Expected: Block (all maintainers replaced)

### T-014-09: Order doesn't matter
- previous = ["bob", "alice"], current = ["alice", "bob"]
- Expected: Pass (same set, different order)

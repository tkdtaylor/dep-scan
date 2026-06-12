# Test Spec — Task 109: Manifest range resolution (deferred stub)

## Context

ADR 009 piece 8. This task is a **backlog stub only** — the lowest-priority item
in the transitive epic, explicitly deferred pending a crate-choice ADR for semver
resolution. The spec records the deferred status, the blocking prerequisite, and
the minimal contract for when implementation eventually starts. No implementation
is expected from this task; the test cases here are completeness checks on the
stub task file, not behavioral assertions.

---

## Stub completeness

### T-109-01: Task file records deferred status explicitly
- The task file `docs/tasks/backlog/109-manifest-range-resolution-deferred.md`
  contains the text "DEFERRED" or "deferred" in its status or objective section.
- The file is present and committed.

### T-109-02: Task file names the blocking ADR prerequisite
- The task file explicitly states that a semver-resolution crate-choice ADR must
  be written and accepted before implementation begins.
- The blocking prerequisite is not buried — it is in the Requirements or
  Acceptance criteria section.

### T-109-03: Task file records lowest-priority ranking
- The task file explicitly states this is the lowest-priority task in the
  transitive epic.
- The priority field or equivalent section says "lowest" or "deferred."

### T-109-04: Task file does not name a specific semver-resolution crate
- The task file discusses the resolution approach at the algorithm level.
- No specific Rust crate name is prescribed (consistent with T-099-09 and the
  ADR 009 no-premature-crate-choice constraint).

### T-109-05: Task file references ADR 009 as the design contract
- The task file references `docs/architecture/decisions/009-transitive-resolution.md`
  explicitly.
- The scope is limited to "manifest-only repos with unpinned ranges" (not the
  lockfile-first case which is already handled by task 100).

---

## When-implemented behavioral contract (future assertions)

The following assertions are placeholders for when this task is eventually
implemented. They do not need to pass now; they define the contract for the
implementor.

### T-109-06: (FUTURE) UnresolvedRange edge emits diagnostic rather than silently passing
- A manifest-only repo with `"foo": "^1.0"` and no lockfile.
- Without this task implemented: `UnresolvedRange` diagnostic is emitted and
  the edge contributes ≥ Warn (existing behavior from task 102).
- With this task implemented: the range is optionally resolved to a specific
  version using the chosen semver crate; if resolution succeeds, the version
  is scanned; if it fails, ≥ Warn still applies.

### T-109-07: (FUTURE) Resolution does not contradict the installed version
- If a lockfile is present, lockfile-first (task 100) takes precedence.
- This task only activates for manifest-only repos where no lockfile exists.
- Assert: if a lockfile is present, this task's resolver is not invoked.

### T-109-08: (FUTURE) Resolved version is scanned, not the range string
- After resolution, the scanned NodeId is `NodeId::Registry { version: "1.2.3" }`
  (a pinned version), not an UnresolvedRange sentinel.

---

## Tooling gate (for the stub task itself)

### T-109-09: No regressions introduced by creating the stub files
- `cargo test` (full suite) exits 0 (no src/ changes for this task).
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

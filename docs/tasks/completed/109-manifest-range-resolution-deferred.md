# Task 109 — Manifest range resolution (deferred stub)

**Status:** DEFERRED — backlog stub only
**Depends on:** 103 (walker integration — UnresolvedRange diagnostics already
               emitted there; this task optionally resolves them)
**ADR:** 009 — [`docs/architecture/decisions/009-transitive-resolution.md`](../../architecture/decisions/009-transitive-resolution.md) (piece 8 — explicitly deferred, lowest priority)
**Scope:** large (estimated); lowest priority in the transitive epic
**Priority:** LOWEST — do not start without completing a semver-crate-choice ADR

## Objective

Optionally resolve unpinned version ranges in manifest-only (lockfile-less)
repos instead of emitting `UnresolvedRange` diagnostics and rolling up ≥ Warn.

**This task is a BACKLOG STUB only.** No implementation is expected until:

1. A new ADR is written choosing a specific semver-resolution crate.
2. That ADR is accepted.

## Why deferred

ADR 009 (T-099-09) explicitly prohibits choosing a semver-resolution crate at
the design-spike stage. Choosing the wrong crate (or discovering the existing
options are all unsuitable) would require rework. The current approach —
emit `UnresolvedRange`, roll up ≥ Warn — is already safe (fail-closed) and
handles the vast majority of real projects (which have lockfiles). The deferred
case covers only manifest-only repos with unpinned ranges.

## Blocking prerequisite

**A semver-crate-choice ADR must be written and accepted before this task
proceeds.** The ADR must:
- Compare at least two candidate crates.
- Evaluate each against the single-binary constraint (no subprocess, no runtime
  deps).
- Choose one crate and document the rationale.

This task file must be updated with the ADR reference before implementation
starts.

## Scope when eventually implemented

When this task is implemented, it provides **optional** resolution of unpinned
ranges in manifest-only repos:
- Activation: a new config field (e.g. `[transitive] resolve_ranges = true`,
  default false) — non-regressive.
- Scope: manifest-only repos only. If a lockfile is present, lockfile-first
  (task 100) takes precedence; this task's resolver is NOT invoked.
- Resolution: use the chosen semver crate to resolve `^1.0` → `1.2.3`
  (pinned). The resolved version is then scanned as a normal `NodeId::Registry`.
- Fallback: if resolution fails → `UnresolvedRange` diagnostic + ≥ Warn (same
  as today). Resolution failure must not silently produce Pass.

## Requirements (deferred — for when implementation begins)

### REQ-109-01: Semver-crate-choice ADR must precede implementation
This requirement cannot be satisfied without the blocking prerequisite above.

### REQ-109-02: Lockfile-first takes precedence — resolver not invoked when lockfile present
When a lockfile exists, task 100's lockfile graph reader is used exclusively.
This resolver activates only for manifest-only repos.

### REQ-109-03: Resolution failure is fail-closed
If resolution fails for any range → `UnresolvedRange` diagnostic + ≥ Warn.
Never silently pass an unresolved range.

### REQ-109-04: Resolution is opt-in, default false
`resolve_ranges = false` by default; no behaviour change for existing users.

## Acceptance criteria (deferred)

- [ ] Blocking ADR written and accepted (REQ-109-01)
- [ ] Resolver not invoked when lockfile present (T-109-07)
- [ ] Resolution failure → UnresolvedRange + ≥ Warn (T-109-06)
- [ ] Resolved version is scanned as pinned NodeId (T-109-08)
- [ ] No regressions (T-109-09)

## Current acceptance criteria (stub — verifiable now)

- [ ] Task file records deferred status (T-109-01)
- [ ] Blocking ADR prerequisite is named (T-109-02)
- [ ] Lowest-priority ranking is stated (T-109-03)
- [ ] No specific semver crate is prescribed (T-109-04)
- [ ] ADR 009 is referenced (T-109-05)

## Test spec

`docs/tasks/test-specs/109-manifest-range-resolution-deferred-test-spec.md`

## Out of scope (now and until the blocking ADR is written)

- Any implementation of range resolution
- Any changes to `src/` beyond what the stub stub verification requires
- Choosing a semver crate (that belongs in the ADR, not here)

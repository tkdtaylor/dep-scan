# Task 099 — Transitive resolution design spike

**Status:** backlog
**Depends on:** 096 (VCS fetch client — transitive deps of git sources are part
               of the scope), 098 (policy pipeline on fetched trees — the
               transitive walk feeds the same policy pipeline)
**ADR:** 008 (piece 4 — transitive resolution; the ADR explicitly does NOT commit
         to an algorithm and identifies this as a separable epic)
**Touches:** `docs/architecture/decisions/009-transitive-resolution.md` (new ADR
            or design doc; no `src/` files)

## Objective

Produce a design document (ADR 009 or equivalent) that resolves all open design
questions from ADR 008 piece 4, enabling the transitive resolution epic to begin
with concrete implementation tasks. This is a documentation-only task: no `src/`
files are modified.

## Background

ADR 008 piece 4 is framed as a "separable epic" with genuine open design
questions. The ADR explicitly does not commit to a single resolution algorithm
because the pieces 1–3 cache and source-kind changes may reshape the design.
Rushing to implement before the questions are answered would likely result in
wasted work or a design that fights the cache model.

The open questions from ADR 008:

1. **Source of truth:** Lockfile (already-resolved, complete) vs. each package's
   own manifest (authoritative for edges but requires re-resolution and
   re-introduces version-range ambiguity)?
2. **Depth limit and cycle detection:** Default max depth? Cycle handling?
   Performance budget when one scan fans out into hundreds of transitive nodes?
3. **Partial failure rollup:** If one transitive dep is unfetchable, what is
   the top-level verdict under fail-closed posture?
4. **Cache key impact:** The current `(name, version, registry)` model has no
   representation for "this verdict depended on these transitive children."

## Requirements

### REQ-099-01: Produce `docs/architecture/decisions/009-transitive-resolution.md`
The document must address all four open questions above with a concrete answer
and rationale for each.

### REQ-099-02: Source-of-truth answer
Pick one approach (lockfile-first, manifest-first, or hybrid) and explain why.
Document the trade-offs against version-range ambiguity and the cost of
re-resolution.

### REQ-099-03: Depth limit, cycle detection, partial-failure rollup
Specify: default max depth (concrete integer), cycle detection algorithm
(e.g. visited-set DFS), and verdict rollup when a subtree node is unfetchable.
All must be consistent with fail-closed posture.

### REQ-099-04: Performance estimate and mitigations
Include a rough estimate of worst-case node count and fetch time at the chosen
depth limit. Propose mitigations (concurrency, caching, depth limit enforcement)
with enough specificity to scope implementation tasks.

### REQ-099-05: Follow-up task list
The document includes a list of the concrete implementation tasks the spike
enables (task titles and rough scope; not full task files).

### REQ-099-06: No `src/` changes
The diff for this task touches only `docs/`. `cargo test` exits 0 unchanged.

## Acceptance criteria

- [ ] ADR 009 (or equivalent) committed to `docs/architecture/decisions/`
- [ ] All four ADR 008 open questions answered with concrete, non-"TBD" answers
- [ ] Source-of-truth question answered with rationale
- [ ] Depth limit is a specific integer; cycle detection algorithm named
- [ ] Partial failure rollup is specified and consistent with fail-closed
- [ ] Cache key impact is addressed
- [ ] Performance estimate and mitigations included
- [ ] Follow-up implementation task list included
- [ ] No `src/` files modified
- [ ] All T-099-01 through T-099-14 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/099-transitive-resolution-design-spike-test-spec.md`

## Out of scope

- Any implementation of transitive walking (follow-up tasks defined in the
  design document)
- Changes to the policy pipeline, cache schema, or scan loop
- Choosing specific Rust crates for manifest parsing or semver resolution

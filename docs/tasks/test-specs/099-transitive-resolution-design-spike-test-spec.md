# Test Spec — Task 099: Transitive resolution — design spike

## Context

ADR 008 piece 4 — the transitive resolution epic. ADR 008 explicitly does NOT
commit to a resolution algorithm and lists genuine open design questions. This
task's deliverable is a design document (or follow-up ADR) that resolves those
questions, not a working implementation. The document becomes the entry point
and contract for the implementation tasks that follow.

Because this is a design/documentation deliverable rather than a code deliverable,
the "test cases" here are completeness and quality checks on the document itself.
Every open question from ADR 008 must be answered in the document; ambiguous or
unresolved items fail the spec.

---

## Document completeness

### T-099-01: Design document exists at `docs/architecture/decisions/009-transitive-resolution.md`
  (or an equivalent named file if the reviewer agrees on a different path)
- The document is committed and present.
- It references ADR 008 explicitly.

### T-099-02: Source-of-truth question is answered
ADR 008 open question: "Lockfile (already-resolved, complete) vs. each package's
own manifest (authoritative for edges but requires re-resolution)?"
- The document picks one and explains the rationale.
- If the answer is "lockfile for registry deps, manifest for git deps", the
  document explains how those two sources are reconciled.

### T-099-03: Depth limit is specified with a default value
- The document specifies the default maximum traversal depth.
- The default is a concrete integer (e.g. 5 or 10), not "TBD".
- The document explains what happens when the limit is reached (warn? block?
  configurable?).

### T-099-04: Cycle detection algorithm is specified
- The document describes the cycle detection approach (e.g. visited-set,
  depth-first with path tracking).
- It covers direct cycles (A → A) and indirect cycles (A → B → A).
- It specifies the verdict when a cycle is detected (warn? block? configurable?).

### T-099-05: Partial failure rollup is specified
ADR 008 open question: "how partial failures (one unfetchable node) roll up into
the top-level verdict under fail-closed."
- The document specifies: if one transitive dep cannot be fetched or scanned,
  does the top-level dep's verdict become `Block`, `Warn`, or inherit the
  subtree verdict?
- The answer must be consistent with the fail-closed posture (ADR 003/008).

### T-099-06: Cache key impact is addressed
ADR 008 open question: cache model has no representation for "this verdict
depended on these transitive children."
- The document describes how the cache key or cache invalidation changes when
  transitive scanning is enabled.
- If the answer is "transitive results are not cached at the top level," the
  document explains the performance implication.

### T-099-07: Performance budget is estimated
ADR 008 concern: "one scan fans out into hundreds of transitive nodes."
- The document includes a rough estimate or bound: e.g., "with depth = 5 and
  a typical npm package having ~10 direct deps per level, worst case is N nodes;
  at Y ms per fetch this is Z seconds."
- It proposes mitigations (depth limit, concurrency, caching) with enough
  specificity to write implementation tasks from.

### T-099-08: Follow-up implementation tasks are listed
- The document includes a section listing the concrete implementation tasks
  that the design spike enables (with rough scope estimates).
- These are task-file stubs or a numbered list; they are NOT backlog task files
  yet (that comes after the document is reviewed and accepted).

---

## No premature implementation decisions

### T-099-09: Document does not prescribe a specific Rust library or crate
- The design document discusses the resolution approach at the algorithm level,
  not in terms of specific crate names.
- Choosing a specific `semver` resolution crate, a manifest-parsing crate, etc.
  is left to the implementation tasks.

### T-099-10: Document does not include any `src/` file changes
- This task produces only a documentation artifact; no `src/` files are modified.
- Confirmed: `git diff HEAD --name-only` shows only files in `docs/`.

---

## Consistency with ADR 008 constraints

### T-099-11: Design is consistent with the single-binary constraint
- The proposed resolution approach does not require an external binary (e.g.
  `npm ls --json`). If it does, the document must explain how the single-binary
  constraint is met.

### T-099-12: Design is consistent with the fail-closed posture
- The document does not propose any path where an unresolvable transitive dep
  silently passes.

### T-099-13: Design is consistent with network-only-on-explicit-scan
- The resolution approach does not fetch manifests or packages during lockfile
  parse or config load.

---

## Tooling gate

### T-099-14: No regressions
- `cargo test` (full suite) exits 0 (no code was changed; this confirms the
  document-only nature of the task).
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

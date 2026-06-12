# Task 106 — subtree_digest cache column

**Status:** backlog
**Depends on:** 103 (walker integration — produces the child verdicts that the
               digest is computed over), 104 (rollup — supplies the per-node
               verdict that goes into the digest)
**ADR:** 009 (piece 6 — Decision 4, cache key impact)
**Scope:** medium
**Touches:** `src/cache.rs` (additive migration + extend `insert`/`insert_git`,
            update `lookup`/`lookup_git` validity check)

## Objective

Extend the `scanned_packages` cache table with a nullable `subtree_digest TEXT`
column using the same additive-idempotent `ALTER TABLE … ADD COLUMN` migration
pattern as tasks 029, 032, and 097 (add only when absent, no backfill, legacy
rows read NULL).

`subtree_digest` fingerprints the set of (child `NodeId`, child verdict) pairs
that the parent's verdict depended on. A cached transitive verdict is a Hit only
if **both** the existing content-hash gate (task 030) **and** the recomputed
`subtree_digest` match the stored values. A mismatch on either → re-scan.

## Background

ADR 009 Decision 4: without a subtree-digest binding, a parent's cached Pass
verdict could be served even after a child's verdict has changed (e.g. a
mutable-ref child flips, or a child's cache entry is invalidated). The
`subtree_digest` column adds a second fingerprint checked alongside the content
hash. Invalid subtree digest → re-scan; invalidation propagates upward by
construction (DFS post-order).

Mutable-ref children are never cached (task 097) → a parent depending on one
cannot form a stable digest → effectively re-scanned each time.

## Requirements

### REQ-106-01: Additive idempotent migration
Add `subtree_digest TEXT` only when absent. Running the migration twice must
not error. Legacy/registry rows carry NULL (no backfill). Mirrors tasks
029/032/097 exactly.

### REQ-106-02: subtree_digest computation
`sha256` over the sorted, length-framed set of `(child_NodeId_string, child_verdict_string)` pairs.
Sort is deterministic (lexicographic on the NodeId string representation).
Length framing reuses the `git_tree_content_hash` discipline from
`src/main.rs:152`.

### REQ-106-03: Two-gate validity rule — fail-closed
A cached transitive row is a Hit iff:
1. content-hash gate (task 030) passes, AND
2. recomputed `subtree_digest` == stored `subtree_digest`.

If either gate fails → Miss → re-scan. Never serve a stale Pass.

### REQ-106-04: Extend `insert` and `insert_git` with optional `subtree_digest`
New signatures accept `subtree_digest: Option<&str>`. Existing callers that
pass `None` write NULL (backwards-compatible).

### REQ-106-05: NULL subtree_digest preserves flat-scan behaviour
Rows with `subtree_digest = NULL` are treated as flat-scan entries. The
content-hash gate applies; the subtree-digest gate is skipped (no transitive
context). Non-regression: all pre-existing cache tests continue to pass.

### REQ-106-06: Mutable-ref child prevents stable parent digest
A parent depending on a mutable-ref child can never produce a stale Pass
from cache, because the mutable-ref child is never cached → parent's
subtree_digest cannot be validated → parent is re-scanned.

## Acceptance criteria

- [ ] Migration adds column when absent (T-106-01)
- [ ] Migration is idempotent (T-106-02)
- [ ] Legacy registry rows read NULL (T-106-03)
- [ ] Legacy git rows read NULL (T-106-04)
- [ ] Digest computation: sorted, length-framed, sha256 (T-106-05)
- [ ] Digest is order-independent (T-106-06)
- [ ] Empty child set produces deterministic digest (T-106-07)
- [ ] Hit requires both gates (T-106-08)
- [ ] Changed child verdict → digest mismatch → re-scan (T-106-09)
- [ ] Content-hash mismatch alone forces re-scan (T-106-10)
- [ ] subtree_digest mismatch alone forces re-scan (T-106-11)
- [ ] insert writes subtree_digest (T-106-12)
- [ ] insert_git writes subtree_digest (T-106-13)
- [ ] insert with None writes NULL (T-106-14)
- [ ] Mutable-ref parent not served as stale Hit (T-106-15)
- [ ] All pre-existing cache tests pass (non-regression)
- [ ] All T-106-01 through T-106-16 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/106-subtree-digest-cache-column-test-spec.md`

## Out of scope

- Config parsing (task 107)
- Main.rs wiring (task 108)
- Fetch pool (task 105)

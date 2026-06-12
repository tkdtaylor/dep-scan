# Test Spec — Task 106: subtree_digest cache column

## Context

ADR 009 piece 6 (Decision 4). Extends the `scanned_packages` cache table with a
nullable `subtree_digest TEXT` column using the same additive-idempotent
`ALTER TABLE … ADD COLUMN` migration pattern as tasks 029, 032, and 097. The
digest fingerprints the set of (child NodeId, child verdict) pairs the parent's
verdict depended on. Cache hit requires both the existing content-hash gate (task
030) AND the recomputed subtree digest matching the stored one. Mutable-ref
children are never cached (task 097), so a parent depending on one can never
form a stable digest.

---

## Schema migration — additive and idempotent

### T-106-01: Migration adds subtree_digest column when absent
- Open a fresh in-memory cache (no pre-existing `subtree_digest` column).
- `Cache::new(...)` completes without error.
- `PRAGMA table_info(scanned_packages)` shows `subtree_digest TEXT` column present.

### T-106-02: Migration is idempotent — running twice does not error
- Open a cache, close it, open it again (simulating a second run against the
  same DB file).
- No `duplicate column` error or panic.
- The column appears exactly once in `PRAGMA table_info`.

### T-106-03: Legacy registry rows read NULL for subtree_digest
- Insert a registry row using the pre-106 `insert` function (no `subtree_digest`
  argument).
- `lookup(name, version, registry)` returns a `CacheEntry` with
  `subtree_digest == None`.
- (Fail-closed callout: NULL subtree_digest means "flat-scan / no transitive
  children recorded." The flat-scan behaviour is preserved exactly — no
  regressions for non-transitive rows.)

### T-106-04: Legacy git rows (task 097) read NULL for subtree_digest
- Insert a git row using the existing `insert_git` function.
- `lookup_git(name, commit_sha)` returns `subtree_digest == None`.
- Flat-scan behaviour for git rows is preserved.

---

## subtree_digest computation

### T-106-05: Digest is sha256 over sorted, length-framed (child_NodeId, child_verdict) pairs
- Children: `[("foo@1.0.0@npm", "pass"), ("bar@abc123@git", "warn")]`.
- Sort deterministically (by NodeId string representation).
- Length-frame each pair (mirrors `git_tree_content_hash` in `src/main.rs:152`).
- Compute `sha256:…` over the framed bytes.
- Assert the resulting digest matches a pre-computed expected value (golden test).

### T-106-06: Digest is order-independent — same children in different insertion order yield same digest
- Same children as T-106-05, inserted in reversed order.
- Recomputed digest equals the digest from T-106-05.

### T-106-07: Empty child set produces a deterministic digest (not NULL)
- A leaf node with no transitive children but scanned transitively.
- `subtree_digest` is computed (a sha256 of an empty input) and written, not NULL.
- Two empty-child nodes produce the same digest.

---

## Cache hit validity — two-gate rule

### T-106-08: Hit requires content-hash gate AND subtree_digest match
- Insert a transitive cache row with `content_hash = "sha256:aaa"` and
  `subtree_digest = "sha256:bbb"`.
- Lookup with matching content hash and recomputed subtree digest that matches
  stored → Hit.
- Lookup with matching content hash but a recomputed subtree digest that differs
  → Miss (fail-closed: stale parent verdict not served).

### T-106-09: Changed child verdict → recomputed digest differs → parent re-scanned
- Prime cache: parent A with subtree_digest computed when child B had Pass.
- Simulate child B changing to Warn.
- Recomputed subtree_digest for A now differs from the stored one.
- Cache lookup for A returns a Miss.
- Parent A is re-scanned (not served a stale Pass).
- (Fail-closed callout: this is the central correctness invariant — a stale Pass
  cannot be served when a child's verdict has changed.)

### T-106-10: content-hash mismatch alone forces re-scan (existing gate unchanged)
- Correct subtree_digest but tampered content_hash.
- Lookup returns Miss (task-030 gate still applies; both gates must pass).

### T-106-11: subtree_digest mismatch alone forces re-scan even if content-hash matches
- Correct content_hash but subtree_digest differs (child verdict changed).
- Lookup returns Miss.

---

## insert / insert_git extension

### T-106-12: insert writes subtree_digest when provided
- Call `insert(name, version, registry, result, content_hash, provenance_identity, Some(subtree_digest))`.
- Lookup returns a row where `subtree_digest` equals the written value.

### T-106-13: insert_git writes subtree_digest when provided
- Call `insert_git(name, commit_sha, result, content_hash, Some(subtree_digest))`.
- Lookup returns a row where `subtree_digest` equals the written value.

### T-106-14: insert with None subtree_digest writes NULL
- Call `insert(... , None)`.
- Lookup returns `subtree_digest == None`.

---

## Mutable-ref children cannot form a stable digest

### T-106-15: Parent depending on a mutable-ref child has no cached subtree_digest
- A parent's children include a mutable-ref git dep.
- Mutable-ref child is never written to cache (task 097 invariant).
- The parent's `subtree_digest` computation includes the mutable-ref child's
  current verdict, but because the child's cache row does not exist (or is
  invalidated on every scan), the parent's subtree_digest cannot be validated
  on the next lookup → parent is effectively re-scanned.
- Assert the parent's cached row is not served as a Hit on the second run.

---

## Tooling gate

### T-106-16: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.
- All pre-existing cache tests (tasks 029, 030, 047, 097) still pass
  (non-regression: the migration is additive).

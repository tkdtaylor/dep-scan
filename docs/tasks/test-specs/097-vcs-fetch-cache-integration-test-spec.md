# Test Spec — Task 097: VCS fetch cache integration

## Context

ADR 008 piece 2 (VCS client) — cache integration for git-sourced dependencies.
The existing cache in `src/cache.rs` is keyed `(name, version, registry)` where
`version` is a SemVer string and `registry` is a `RegistryType` string. This
model does not represent git sources: there is no registry, and the "version"
is a commit SHA or mutable ref name.

ADR 008's cache open question: "Does the key become `(name, commit_sha, source)`?
Are mutable-ref results cacheable at all?"

This task resolves that question (the executor documents the decision in ADR 008
or a follow-up note) and implements the cache behaviour:
- Pinned commit SHA deps: cached by `(name, commit_sha, "git")`. A re-scan of
  the same SHA is a cache hit.
- Mutable ref deps: NOT cached. Every scan re-fetches and re-checks, because the
  ref's content can change between scans. Attempting to cache a mutable-ref result
  is silently skipped (no error, no stale cache write).

This task depends on 090 (source model), 096 (fetch client exists), and 007
(SQLite cache schema).

---

## Cache key for git sources

### T-097-01: Pinned commit SHA dep produces cache key `(name, sha, "git")`
- Fetch and scan a git dep with `ref_ = "a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b5"`.
- After scan, `cache.lookup("pkg-name", "a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b5", "git")` returns a cache hit.

### T-097-02: Second scan of the same pinned SHA is a cache hit (no re-fetch)
- Scan a pinned SHA dep once (primes the cache).
- Scan again with the same dep.
- The VCS fetch client's `fetch` method is called exactly once across both scans.
  (Confirmed via a spy/stub on the fetcher.)

### T-097-03: Mutable ref dep is NOT written to cache
- Scan a git dep with `ref_ = "main"` (mutable).
- After scan, `cache.lookup("pkg-name", "main", "git")` returns a cache miss.

### T-097-04: Mutable ref dep always re-fetches on second scan
- Scan a mutable ref dep twice.
- The fetcher is called twice (cache never intervenes).

### T-097-05: Cache key `"git"` string does not collide with existing `RegistryType` strings
- Verify that `"git"` is not equal to any existing registry key strings used by
  the npm, PyPI, crates, or Go cache entries (i.e. checking that a crate named
  `foo` at version `abc123` from crates.io cannot collide with a git dep named
  `foo` at commit `abc123`).

---

## Cache schema migration (additive, idempotent)

### T-097-06: Existing cache DB with no git entries is not corrupted
- Open an existing cache DB (from earlier tasks that have no git entries).
- Run any required schema migration.
- All pre-existing registry entries are still readable after migration.

### T-097-07: Schema migration is idempotent
- Apply the migration twice to the same DB.
- No error. Existing entries unchanged.

### T-097-08: Migration adds no new required columns to existing rows
- The migration is additive: it may add new columns or tables but must not
  invalidate or require backfill of existing rows.

---

## Cache content for git hits

### T-097-09: A pinned-SHA cache hit returns the stored `CheckResult`
- Prime the cache with a `Pass` result for a pinned SHA dep.
- On cache hit, the scan loop uses the stored verdict without calling the fetcher.
- `CheckResult.verdict == Pass` as stored.

### T-097-10: Content hash integrity check applies to git cache entries
- The existing content-hash integrity check (task 030) must also apply when
  reading a git-source cache entry. A tampered cache entry is rejected and the
  dep is re-fetched.
  (Exact mechanism matches the existing ADR 003 hash-verify pattern.)

---

## Fail-closed on cache error

### T-097-11: Cache lookup error for git dep is surfaced to stderr (warn-only)
- Corrupt the cache DB such that a lookup returns `Err`.
- The scan loop logs the error to stderr and proceeds with a full re-fetch.
- The dep verdict is determined by the fetch result, not the cache error.
- Consistent with REQ-047-01/02 behaviour for registry deps.

---

## Tooling gate

### T-097-12: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

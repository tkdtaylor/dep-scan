# Task 097 — VCS fetch cache integration

**Status:** completed
**Depends on:** 090 (source model), 096 (VCS fetch client), 007 (SQLite cache)
**ADR:** 008 (piece 2 — cache open question: key for git sources, mutable-ref
         cacheability)
**Touches:** `src/cache.rs` (schema migration + git key support), `src/main.rs`
            (cache lookup/store in git-dep scan arm)

## Objective

Integrate git-sourced dependency results with the SQLite cache: cache pinned
commit SHA results by `(name, commit_sha, "git")` so re-scans of immutable SHAs
are cache hits; never cache mutable-ref results because the ref's content can
change between scans.

## Design decision (must document before implementing)

ADR 008 explicitly lists the cache key for git sources as an open question.
Before implementation, the executor must record the resolution in ADR 008 (or
a follow-up note): the chosen key scheme is `(name, commit_sha, "git")` for
pinned SHAs; mutable refs are not cached. The rationale is that an immutable
SHA uniquely identifies the fetched tree, whereas a mutable branch name does not.

## Requirements

### REQ-097-01: Cache key for pinned SHA git deps
Store and look up git-source results with key `(name, commit_sha, "git")`.
`"git"` as the registry-slot string must not collide with any existing
`RegistryType` to_string value.

### REQ-097-02: Mutable ref results are never written to cache
When the git ref is classified as mutable (see task 094's `classify_ref`), skip
the cache store step silently. No error is returned; the result is just not
persisted.

### REQ-097-03: Additive, idempotent schema migration
If the existing cache schema requires extension (e.g. a new `source_kind` column
or new table), the migration must be additive (no column drops, no data loss) and
idempotent (safe to run twice). Existing registry entries must be readable after
migration.

### REQ-097-04: Content-hash integrity applies to git entries
The existing hash-verify step from task 030 must cover git-source cache entries.
A tampered entry triggers a re-fetch, consistent with the ADR 003 fail-closed
posture.

### REQ-097-05: Cache lookup errors for git deps surface as warnings
A DB error on git dep cache lookup is logged to stderr and causes the scan to
proceed with a full re-fetch (not a silent pass or a hard abort), consistent
with REQ-047-01/02.

## Acceptance criteria

- [ ] Pinned SHA dep: second scan is a cache hit; fetcher called exactly once
- [ ] Mutable ref dep: cache never stores; fetcher called on every scan
- [ ] `"git"` key string does not collide with existing registry key strings
- [ ] Schema migration is additive and idempotent
- [ ] Pre-existing registry cache entries survive migration
- [ ] Content-hash integrity check covers git cache entries
- [ ] Cache lookup error → stderr warning + re-fetch (not pass, not abort)
- [ ] All T-097-01 through T-097-12 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/097-vcs-fetch-cache-integration-test-spec.md`

## Out of scope

- Running the policy pipeline against fetched trees (task 098)
- Transitive resolution (task 099)
- Cache eviction / TTL for git entries (future)
- Cache invalidation when a pinned SHA is later found malicious (future)

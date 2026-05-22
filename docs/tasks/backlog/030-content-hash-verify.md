# Task 030 — Verify content hash on cache hit

**Status:** backlog
**Depends on:** 029

## Objective

Close the cache-poisoning gap identified in [ADR 003](../../architecture/decisions/003-content-hash-cache-integrity.md): when a cached verdict is found, verify the registry's currently-published content digest still matches the stored `content_hash` before honoring the cached result. Mismatch ⇒ invalidate the row and fall through to a full re-scan.

This is especially load-bearing because today's cache key uses the literal string `"latest"` for the version ([src/main.rs:220](../../../src/main.rs#L220)). A republish under the same tag would otherwise produce a permanent false-positive cache hit. Hash verification breaks that.

## Behavior

In `run_check`'s cache-hit branch ([src/main.rs:218-240](../../../src/main.rs#L218-L240)):

1. Fetch package metadata from the registry (same call we'd make on a cache miss).
2. Compare `metadata.content_hash` against `cache_entry.content_hash`.
3. **Match** ⇒ return the cached verdict as today.
4. **Mismatch** ⇒ `cache.invalidate(name, "latest", registry)`, log a clear message (`"cache hash mismatch for <pkg>; re-scanning"`), and fall through to the full scan pipeline.
5. **Cached hash is NULL** (legacy row from before task 029) ⇒ treat as mismatch: invalidate and re-scan. This upgrades pre-029 cache rows organically.
6. **Registry-fetched hash is None but cached is Some** ⇒ treat as mismatch (registry stopped publishing a digest is itself suspicious).
7. **Both None** ⇒ honor the cached verdict (best-effort — nothing to verify against; logged at verbose level).
8. **Registry fetch fails during verification** ⇒ fall through to the full scan path (which will surface the error consistently with the no-cache flow).

`--force` on `install` continues to bypass *verdicts* but not the verification step itself — a hash mismatch always triggers a re-scan; the user can then `--force` past the resulting verdict if they choose.

## Acceptance criteria

- [ ] `run_check` cache-hit branch fetches metadata and compares `content_hash` before returning the cached result
- [ ] Mismatch invalidates the cache row via `Cache::invalidate` and continues into the full scan
- [ ] NULL cached hash (legacy row) is treated as mismatch — triggers re-scan; new scan populates the hash
- [ ] When the full scan succeeds after a mismatch, the resulting cache row contains the *new* hash (closes the verify loop)
- [ ] Verbose output distinguishes: `cache hit (verified)`, `cache hit (no hash to verify)`, `cache hash mismatch — re-scanning`
- [ ] Non-verbose output stays quiet on the happy path; mismatch always prints a one-line notice to stderr
- [ ] `--force` on install does not bypass the verification step (only verdicts)
- [ ] Integration test: cache populated with hash A, registry returns hash B, `dep-scan check` re-scans and produces a fresh verdict
- [ ] Integration test: cache populated with hash A, registry returns hash A, `dep-scan check` returns cached result and does NOT execute policy logic
- [ ] No new public API surface; no schema change (all schema work was in 029)
- [ ] All tests pass, `cargo clippy` clean, `cargo fmt --check` clean

## Out of scope

- Downloading and locally re-hashing the tarball — deferred `--paranoid` mode
- Row-level HMAC against local cache tampering — out of scope for v1.1
- Skipping verification for performance (a future `--skip-cache-verify` flag is not part of this task)

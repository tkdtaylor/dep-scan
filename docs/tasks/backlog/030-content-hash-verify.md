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

**Verification is always on, fail-closed, no opt-out.** The decision table (verbatim from [ADR 003](../../architecture/decisions/003-content-hash-cache-integrity.md)):

| Cached hash | Registry hash | Action |
|-------------|---------------|--------|
| `Some(a)`   | `Some(a)`     | Honor cache |
| `Some(a)`   | `Some(b)`     | Invalidate row, re-scan |
| `Some(a)`   | `None`        | Invalidate row, re-scan |
| `None`      | `Some(b)`     | Invalidate row, re-scan (legacy pre-029 row upgrades in place) |
| `None`      | `None`        | Invalidate row, re-scan (**fail-closed** — an attacker who controls the registry can engineer this state) |
| `Some(a)`   | fetch fails / parse error / version-not-found / malformed digest | Invalidate row, re-scan |

On any `Reverify` outcome: `cache.invalidate(name, "latest", registry)`, log a one-line message to stderr (`"cache hash mismatch for <pkg>; re-scanning"`), and fall through to the full scan pipeline. After a successful re-scan, the new cache row stores the freshly-observed hash, closing the verify loop.

`--force` on `install` bypasses *verdicts* but not the verification step itself — a hash mismatch always triggers a re-scan; the user can then `--force` past the resulting verdict if they choose. This prevents `--force` from silently honoring a stale `pass`.

## Acceptance criteria

- [ ] `run_check` cache-hit branch fetches metadata and compares `content_hash` before returning the cached result
- [ ] All `Reverify` cases from the decision table invalidate the cache row via `Cache::invalidate` and fall through to the full scan
- [ ] **Both-None is fail-closed:** when cached hash and registry hash are both `None`, the cache is *not* honored — a re-scan runs
- [ ] After a successful re-scan, the resulting cache row contains the *new* hash (closes the verify loop)
- [ ] Verification has no opt-out flag (no `--skip-cache-verify` or equivalent in this task)
- [ ] Verbose output distinguishes: `cache hit (verified)`, `cache hash mismatch — re-scanning`
- [ ] Non-verbose output stays quiet on the happy path; mismatch always prints a one-line notice to stderr
- [ ] `--force` on install does not bypass the verification step (only verdicts)
- [ ] Registry fetch errors during verification surface identically to the cache-miss path (no new failure modes; consistent fail-closed)
- [ ] Integration test: cache populated with hash A, registry returns hash B, `dep-scan check` re-scans and produces a fresh verdict
- [ ] Integration test: cache populated with hash A, registry returns hash A, `dep-scan check` returns cached result and does NOT execute policy logic
- [ ] No new public API surface; no schema change (all schema work was in 029)
- [ ] All tests pass, `cargo clippy` clean, `cargo fmt --check` clean

## Out of scope

- Downloading and locally re-hashing the tarball — deferred `--paranoid` mode
- Row-level HMAC against local cache tampering — out of scope for v1.1
- Skipping verification for performance — explicitly *not* added; secure default is no opt-out
- Closing the TOCTOU window between dep-scan's verification and the package manager's own fetch — task 031 handles the pip case via `--require-hashes` passthrough

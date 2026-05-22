# Task 038 — Use resolved version as cache key instead of "latest"

**Status:** backlog
**Depends on:** 007 (SQLite cache), 029 (content hash capture), 030 (content hash verify)
**Security finding:** H-2 (HIGH)

## Objective

Replace the hard-coded `"latest"` string used as the cache key version in `cache.lookup` and `cache.insert` with the concrete version string resolved from the registry (`metadata.version`). This closes two gaps: (1) a cross-version aliasing window where a `pass` verdict cached under `"latest"` could apply to a future different tarball at the same name, and (2) the current absence of any short-circuit value for unpinned packages (since every resolved version is a different `"latest"` alias, cache hits never fire for packages queried without a pinned version).

## Background

`src/main.rs` currently calls `cache.lookup(pkg_name, "latest", &reg_str)` before the scan and `cache.insert(pkg_name, "latest", ...)` after it. This means every version of a package (including republished versions at the same floating tag) shares a single cache row.

The content-hash verify logic from task 030 provides defense-in-depth against serving the wrong tarball, but using `"latest"` as the key creates an unnecessary aliasing surface: if a CDN briefly serves the old `dist.integrity` for a newly-published package at the same name+version string, a stale `pass` verdict could be honored. More practically, the cache provides zero benefit for the common case of scanning an unpinned package twice in the same project because the resolved version changes between scans.

The fix is straightforward: fetch metadata first, read `metadata.version`, use that as the key in both the lookup and the insert. The content-hash verify layer (task 030) remains the primary runtime guard; this change makes the cache key content-stable so that the verify step is comparing apples to apples.

## Behavior

In `src/main.rs`, in the `run_check` loop:

1. **Fetch metadata first.** Move the registry `get_metadata` call before the cache lookup. (Currently the lookup is attempted before the metadata fetch, using `"latest"` as a speculative key. Reverse this: fetch first, then look up by resolved version.)
2. **Look up by resolved version.** Call `cache.lookup(pkg_name, &metadata.version, &reg_str)`.
3. **Insert by resolved version.** Call `cache.insert(pkg_name, &metadata.version, ...)`.
4. **Invalidate by resolved version.** Call `cache.invalidate(pkg_name, &metadata.version, ...)` on hash mismatch.

The `PackageMetadata.version` field is always populated by every registry client (it is a required field). No fallback to `"latest"` is acceptable.

## Requirements

- **REQ-038-01:** `cache.lookup` is called with `metadata.version`, never with the literal string `"latest"`.
- **REQ-038-02:** `cache.insert` is called with `metadata.version`, never with the literal string `"latest"`.
- **REQ-038-03:** `cache.invalidate` is called with `metadata.version` on hash mismatch.
- **REQ-038-04:** The string literal `"latest"` does not appear as an argument to any cache method call in `src/main.rs`.
- **REQ-038-05:** A cache hit for version `"X.Y.Z"` is not returned when the registry resolves the package to version `"A.B.C"` (no cross-version aliasing).
- **REQ-038-06:** Registry fetch errors produce no cache entry (no version to key on).

## Acceptance criteria

- [ ] `cache.lookup` uses `metadata.version` (REQ-038-01); verified by T-038-02, T-038-08.
- [ ] `cache.insert` uses `metadata.version` (REQ-038-02); verified by T-038-01.
- [ ] `cache.invalidate` uses `metadata.version` (REQ-038-03); verified by T-038-07.
- [ ] Literal `"latest"` absent from cache call sites in `src/main.rs` (REQ-038-04); verified by T-038-06 (static grep).
- [ ] Old `"latest"` rows are not hit after the change (REQ-038-05); verified by T-038-03.
- [ ] Registry fetch errors produce no cache entry (REQ-038-06); verified by T-038-11.
- [ ] Two different resolved versions coexist independently in cache (T-038-04).
- [ ] Cross-version aliasing attack still triggers hash mismatch via task 030 logic (T-038-09).
- [ ] Go and crates.io cache keys also use resolved version (T-038-10).
- [ ] Task 030 hash-verify tests pass unchanged (T-038-12).
- [ ] Task 014 maintainer-history table unaffected (T-038-13).
- [ ] `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Pruning old `"latest"` rows from existing user databases. Migration is not needed — old rows simply won't be hit under the new lookup key and will expire naturally (or can be cleared by the user). A future "cache prune" task can handle housekeeping.
- Pinning a specific version in the `dep-scan check` or `dep-scan install` CLI. This task changes only the internal cache key; the user-facing behavior of scanning "the latest available version" is unchanged.
- Caching behavior when the user supplies a specific version (e.g. `dep-scan check express@4.18.0`). That path already uses the specific version; this task does not touch it.

## Risk notes

- Moving the metadata fetch before the cache lookup changes the order of network calls. The code previously short-circuited on a cache hit before fetching metadata. The new order always fetches first. This is an intentional trade-off: the cache hit rate improves (correct version key), but there is now always one network call per package. The performance impact is acceptable and consistent with what task 030 already requires (it fetches metadata to compare content hashes even on a cache hit).
- The `metadata.version` field must be validated non-empty before use as a cache key. A registry client that returns an empty version string should surface a `RegistryError` rather than silently inserting an empty-version row.

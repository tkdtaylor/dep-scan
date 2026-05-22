# Task 029 — Capture content hash in scan cache

**Status:** completed
**Depends on:** 007, 017

## Objective

Capture the registry-published content digest for every scanned package and persist it on `scanned_packages.content_hash`. This is the foundational change for hash-based cache invalidation on install (task 030) — see [ADR 003](../../architecture/decisions/003-content-hash-cache-integrity.md).

## Acceptance criteria

- [x] `PackageMetadata` (`src/types.rs`) gains a `content_hash: Option<String>` field formatted as `<algo>:<hex>`
- [x] npm registry client (`src/registry/npm.rs`): populate from `dist.integrity` (preferred) or `dist.shasum` fallback, normalized to `sha512:<hex>` or `sha1:<hex>`
- [x] PyPI registry client (`src/registry/pypi.rs`): populate from `digests.sha256` of the sdist if present, else first wheel — formatted `sha256:<hex>`
- [x] crates.io registry client (`src/registry/crates.rs`): populate from `cksum` — `sha256:<hex>`
- [x] Go module registry client (`src/registry/go.rs`): populate from sum DB `h1:` hash — `h1:<base64>`
- [x] `scanned_packages` schema: add nullable `content_hash TEXT` column
- [x] `Cache::new` upgrades a legacy DB in place via column-exists check + `ALTER TABLE ... ADD COLUMN content_hash TEXT` (idempotent, safe to re-run)
- [x] `Cache::insert` extends to accept `content_hash: Option<&str>`
- [x] `Cache::lookup` returns the stored hash as part of `CacheEntry`
- [x] Hash-less rows (NULL) deserialize to `content_hash = None` — never an error, never a mismatch
- [x] Existing test suites for tasks 002–028 still pass unchanged (this is an additive change)
- [x] All tests pass, `cargo clippy` clean, `cargo fmt --check` clean

## Out of scope

- Verification of the stored hash at install time — task 030
- Downloading and locally re-hashing the tarball — deferred to a future `--paranoid` flag
- Row-level HMAC against local cache tampering — out of scope for v1.1

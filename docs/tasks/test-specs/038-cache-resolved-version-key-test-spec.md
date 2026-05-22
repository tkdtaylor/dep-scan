# Test Spec — Task 038: Use resolved version as cache key instead of "latest"

## Unit tests (cache key selection logic)

These cover the change to use `metadata.version` (the concrete version string returned by the registry, e.g. `"1.2.3"`) as the cache key instead of the literal string `"latest"`.

### T-038-01: Cache insert uses resolved version, not "latest"
- Arrange: a `PackageMetadata` with `version = "1.2.3"` for package `"express"`
- After `run_check` completes for this metadata, inspect the SQLite cache
- Expected: one row exists with `(name="express", version="1.2.3", registry="npm")`; no row exists with `version="latest"`

### T-038-02: Cache lookup uses resolved version, not "latest"
- Pre-populate cache with `(name="express", version="1.2.3", registry="npm", result="pass", content_hash="sha512:aaaa")`
- wiremock returns metadata with `version="1.2.3"` and `dist.integrity = "sha512:aaaa"`
- Run `dep-scan check express --registry npm --verbose`
- Expected: output contains "cache hit (verified)"; the lookup key used is `"1.2.3"`, not `"latest"`

### T-038-03: Old "latest" row in cache is NOT hit after this change (version isolation)
- Pre-populate cache with the old schema: `(name="express", version="latest", registry="npm", result="pass", content_hash="sha512:aaaa")`
- wiremock returns metadata with `version="1.2.3"` and `dist.integrity = "sha512:aaaa"`
- Run `dep-scan check express --registry npm --verbose`
- Expected: cache miss — the old `"latest"` row does not match the new lookup key `"1.2.3"`; full scan runs; a new row `(express, "1.2.3", npm, ...)` is inserted

### T-038-04: Two different resolved versions of the same package coexist in cache independently
- Pre-populate `(express, "1.2.3", npm, pass, sha512:aaaa)` and `(express, "1.3.0", npm, pass, sha512:bbbb)`
- wiremock returns version `"1.2.3"` with `dist.integrity = "sha512:aaaa"`
- Run `dep-scan check express --registry npm --verbose`
- Expected: the `"1.2.3"` row is hit and honored; the `"1.3.0"` row is not touched

### T-038-05: Registry returns a different resolved version — cache miss, re-scan
- Pre-populate `(express, "1.2.3", npm, pass, sha512:aaaa)`
- wiremock now returns `version="1.3.0"` with `dist.integrity = "sha512:bbbb"` (new release)
- Run `dep-scan check express --registry npm`
- Expected: cache miss (no `"1.3.0"` row yet); full scan runs; new row `(express, "1.3.0", npm, ...)` is inserted; the `"1.2.3"` row is left untouched

### T-038-06: "latest" is NOT used as a cache lookup key in any code path (static check)
- Grep `src/` for string literals `"latest"` in any cache `lookup(` or `insert(` call site
- Expected: zero occurrences — the resolved version string from `PackageMetadata.version` is always used

### T-038-07: invalidate also targets the resolved version key
- Pre-populate `(express, "1.2.3", npm, pass, sha512:aaaa)`
- Trigger a hash mismatch during verify (wiremock returns `dist.integrity = "sha512:xxxx"`)
- Run `dep-scan check express --registry npm`
- Expected: the `"1.2.3"` row is invalidated (removed or updated), not a phantom `"latest"` row

## Integration tests (assert_cmd + wiremock)

### T-038-08: Second scan within the same session uses the cache hit (resolved version)
- wiremock serves `express` with `version="4.18.0"`, `dist.integrity = "sha512:cccc"`, clean metadata
- Run `dep-scan check express --registry npm` — first scan, populates cache with key `"4.18.0"`
- Run `dep-scan check express --registry npm --verbose` — second scan, same wiremock
- Expected: second run output contains "cache hit (verified)"; wiremock observes exactly 2 metadata calls total (one per run — no extra calls for cache verification)

### T-038-09: Cross-version aliasing attack does not yield a cache hit
- Scenario: attacker republishes `express` at the same version string `"4.18.0"` but with a different tarball (CDN replay window)
- Pre-populate `(express, "4.18.0", npm, pass, sha512:old-hash)`
- wiremock now returns `version="4.18.0"` but with a different `dist.integrity = "sha512:new-hash"` (simulating a republished tarball)
- Run `dep-scan check express --registry npm`
- Expected: hash mismatch detected (the content-hash verify logic from task 030 fires), cache invalidated, full re-scan triggered; the stale `pass` verdict is NOT honored

### T-038-10: Go and crates.io also use resolved version as cache key
- wiremock serves `serde` at `version="1.0.193"` (crates.io) and `github.com/gin-gonic/gin` at version `"v1.9.1"` (Go proxy)
- Run `dep-scan check serde --registry crates` then `dep-scan check github.com/gin-gonic/gin --registry go`
- Inspect cache after each run
- Expected: rows have the concrete version strings `"1.0.193"` and `"v1.9.1"` respectively, not `"latest"`

### T-038-11: Version fetch failure produces no cache entry (not a "latest" fallback)
- wiremock returns 500 for the metadata endpoint
- Run `dep-scan check express --registry npm`
- Expected: scan fails with an error; no cache row is inserted (there is no version to key on); the error exit code matches the pre-existing behavior for registry errors

## Regression tests

### T-038-12: Task 030 hash-verify behavior is preserved with the new key
- All T-030-06 through T-030-13 scenarios still apply — just with version `"X.Y.Z"` as the cache key instead of `"latest"`
- Run `cargo test content_hash_verify` (or equivalent)
- Expected: 0 failures after substituting the resolved version key

### T-038-13: Maintainer history table is unaffected
- The `maintainer_history` table uses `(name, registry)` as its key, not a version — it must not be touched by this change
- Static check: `cache.record_maintainers` call sites still use `(pkg_name, reg_str)`; no version argument is introduced
- Expected: task 014 tests pass unchanged

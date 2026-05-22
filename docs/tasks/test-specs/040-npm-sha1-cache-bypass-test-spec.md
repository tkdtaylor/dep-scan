# Test Spec — Task 040: Reject SHA-1 content hashes as cache trust gates for npm

## Unit tests (extract_npm_content_hash behavior)

### T-040-01: Package with SRI `integrity` field returns sha512 hash (unchanged)
- Input: `NpmDist { integrity: Some("sha512-abc..."), shasum: Some("deadbeef") }`
- Expected: `extract_npm_content_hash(...)` returns `Some("sha512:<hex>")`; `shasum` is not used

### T-040-02: Package with only `shasum` (no `integrity`) returns `sha1:`-prefixed hash
- Input: `NpmDist { integrity: None, shasum: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709") }`
- Expected: `extract_npm_content_hash(...)` returns `Some("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709")`
- Note: this is the existing behavior and must remain unchanged — the function still extracts the sha1 for informational purposes

### T-040-03: Package with neither `integrity` nor `shasum` returns `None`
- Input: `NpmDist { integrity: None, shasum: None }`
- Expected: `extract_npm_content_hash(...)` returns `None`

## Unit tests (cache insertion policy — sha1 must not be stored as a pass verdict cache key)

### T-040-04: `pass` verdict with a `sha1:` content hash is NOT inserted into the cache as a trusted entry
- Arrange: npm package metadata with only `shasum` (no SRI `integrity`), policy pipeline returns `pass`
- After `run_check` completes, inspect the SQLite cache
- Expected: either (a) no row exists for this package (the sha1-only pass is not cached), OR (b) a row exists with `result = "pass"` but `content_hash = NULL` (so the hash verify step from task 030 will always reverify on next lookup, never short-circuit)
- The implementer must choose (a) or (b) and document the decision; the spec accepts either

### T-040-05: `block` verdict with a `sha1:` content hash IS cached normally
- Arrange: npm package metadata with only `shasum`, policy pipeline returns `block`
- Expected: a cache row exists with `result = "block"` — caching a `block` verdict is safe regardless of hash quality because the next scan would re-block, not silently pass

### T-040-06: `warn` verdict with a `sha1:` content hash follows the same policy as `pass` (not trusted)
- Arrange: npm package metadata with only `shasum`, pipeline returns `warn`
- Expected: same as T-040-04 — the `warn` is not cached with the sha1 hash as the trust gate (or is cached with `content_hash = NULL`)

## Unit tests (cache lookup policy — sha1 hits always reverify)

### T-040-07: Cache hit with a `sha1:` stored hash always triggers reverify, never honors the cached verdict
- Pre-populate cache with `(pkg, "1.0.0", npm, "pass", content_hash="sha1:deadbeef")`
- wiremock returns metadata with `shasum = "deadbeef"` and no `integrity` field (hashes match)
- Run `dep-scan check pkg --registry npm --verbose`
- Expected: the matching sha1 hash does NOT produce a cache hit that is honored; instead `HonorCache` is not returned for sha1 hashes — the full scan pipeline runs again

### T-040-08: Cache hit with a `sha1:` stored hash where the registry returns a sha512 does NOT produce a match
- Pre-populate cache with `(pkg, "1.0.0", npm, "pass", content_hash="sha1:deadbeef")`
- wiremock returns metadata with `integrity = "sha512-abcd..."` (package now has SRI)
- Run `dep-scan check pkg --registry npm --verbose`
- Expected: `Reverify` (hash algorithms differ — `sha1:` vs `sha512:` — no match regardless of the sha1 value)

### T-040-09: Cache hit with a `sha512:` hash still short-circuits as before (no regression)
- Pre-populate cache with `(pkg, "4.18.0", npm, "pass", content_hash="sha512:aaaa")`
- wiremock returns metadata with `dist.integrity = "sha512:aaaa"` (matching)
- Run `dep-scan check pkg --registry npm --verbose`
- Expected: "cache hit (verified)" — sha512 short-circuit is unaffected by this change

## Integration tests (assert_cmd + wiremock)

### T-040-10: Scanning a sha1-only npm package runs the full pipeline every time (no stale cache short-circuit)
- wiremock serves a package with `shasum` only (no `integrity`), returning clean metadata
- Run `dep-scan check legacypkg --registry npm` twice
- Expected: both runs execute the full policy pipeline; wiremock observes 2 metadata calls (no cache short-circuit for sha1)

### T-040-11: stderr or verbose output indicates why the cache was bypassed for a sha1-only package
- Run `dep-scan check legacypkg --registry npm --verbose`
- Expected: verbose output contains a message indicating the sha1 hash was not used as a cache trust gate (e.g. "sha1 hash not accepted for cache short-circuit; re-scanning")

### T-040-12: Chosen-prefix SHA-1 collision scenario — old sha1 hash in cache, new tarball with same shasum
- Pre-populate cache with `(legacypkg, "1.0.0", npm, "pass", content_hash="sha1:colliding-hash")`
- wiremock returns metadata with `shasum = "colliding-hash"` (attacker republished with collision)
- Run `dep-scan check legacypkg --registry npm`
- Expected: the full scan pipeline runs regardless of the sha1 match; the stale `pass` is NOT honored

## Regression tests

### T-040-13: All task 030 hash-verify tests that use sha512 are unaffected
- Run `cargo test content_hash_verify` (or equivalent)
- Expected: 0 failures — only sha1 behavior changes

### T-040-14: All task 032 npm provenance tests are unaffected
- Run `cargo test npm_provenance`
- Expected: 0 failures — npm provenance works at the sigstore layer, not the shasum layer

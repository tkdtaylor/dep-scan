# Test Spec — Task 030: Verify content hash on cache hit

## Unit tests (verification decision logic)

These cover the decision table in the task — given `cached_hash` and `registry_hash`, decide one of: `HonorCache`, `Reverify`, `Skip` (best-effort honor).

### T-030-01: Matching hashes ⇒ honor cache
- cached = `Some("sha256:aaaa")`, registry = `Some("sha256:aaaa")`
- Expected: `HonorCache`

### T-030-02: Mismatched hashes ⇒ reverify
- cached = `Some("sha256:aaaa")`, registry = `Some("sha256:bbbb")`
- Expected: `Reverify`

### T-030-03: Legacy NULL cached hash ⇒ reverify
- cached = `None`, registry = `Some("sha256:bbbb")`
- Expected: `Reverify` (upgrade path — legacy row gets a hash on the next scan)

### T-030-04: Registry stopped publishing digest ⇒ reverify
- cached = `Some("sha256:aaaa")`, registry = `None`
- Expected: `Reverify`

### T-030-05: Both None ⇒ reverify (fail-closed)
- cached = `None`, registry = `None`
- Expected: `Reverify`
- Rationale: an attacker who controls the registry could engineer this state (serve metadata with no `dist.integrity`, ensure first scan stores NULL, then republish freely). Honoring the cache here would be a permanent verification bypass. Fail closed instead — re-scan and re-populate.

## Integration tests (assert_cmd + wiremock)

### T-030-06: Cache hit with matching hash skips re-scan
- Pre-populate cache with `(pkg, "latest", npm, "pass", content_hash="sha512:aaaa")`
- wiremock npm metadata returns `dist.integrity = "sha512:aaaa"` (matches)
- Run: `dep-scan check pkg --registry npm --verbose`
- Expected: exit 0, output contains `cache hit (verified)`, wiremock observes exactly ONE metadata call (the verification fetch), policy logic does not execute

### T-030-07: Cache hit with mismatched hash invalidates and re-scans
- Pre-populate cache with `(pkg, "latest", npm, "pass", content_hash="sha512:aaaa")`
- wiremock returns `dist.integrity = "sha512:bbbb"` and otherwise clean metadata
- Run: `dep-scan check pkg --registry npm`
- Expected: exit 0, stderr contains `cache hash mismatch for pkg; re-scanning`, the resulting cache row's `content_hash` is now `sha512:bbbb`

### T-030-08: Cache hit with mismatched hash where re-scan blocks
- Pre-populate cache with `(pkg, "latest", npm, "pass", content_hash="sha512:aaaa")`
- wiremock returns `dist.integrity = "sha512:bbbb"` plus a fresh published_at that fails the min-age policy
- Run: `dep-scan check pkg --registry npm`
- Expected: exit 1, output shows a min-age violation (i.e. the cached `pass` was correctly NOT honored)

### T-030-09: Legacy cache row (NULL hash) triggers re-scan
- Manually insert a row with `content_hash = NULL` (simulating a pre-029 DB)
- wiremock returns clean metadata with `dist.integrity = "sha512:abcd"`
- Run: `dep-scan check pkg --registry npm --verbose`
- Expected: exit 0, verbose output shows `cache hash mismatch — re-scanning`, post-run the row has `content_hash = "sha512:abcd"`

### T-030-10: Both hashes None ⇒ re-scan (fail-closed)
- Pre-populate cache with `content_hash = NULL`, result = `pass`
- wiremock returns metadata with no `dist.integrity` and no `dist.shasum` (so registry hash is also `None`)
- Run: `dep-scan check pkg --registry npm --verbose`
- Expected: exit 0, verbose output shows `cache hash mismatch — re-scanning`, the full policy pipeline executes, the resulting cache row reflects the fresh scan (still `content_hash = NULL` since registry has no digest, but verdict and `scanned_at` are refreshed)
- Rationale: secure default — never short-circuit when there's nothing to verify against

### T-030-11: Registry fetch failure during verification falls through to scan path
- Pre-populate cache with hash
- wiremock returns 500 on the metadata endpoint
- Run: `dep-scan check pkg --registry npm`
- Expected: behaves identically to a cache-miss against a 500 — registry error surfaced, exit code matches the existing no-cache error semantics (not a new failure mode)

### T-030-12: `install --force` does not bypass verification
- Pre-populate cache with `(pkg, "latest", npm, "pass", content_hash="sha512:aaaa")`
- wiremock returns `dist.integrity = "sha512:bbbb"` plus fresh published_at that fails min-age
- Run: `dep-scan install pkg --registry npm --force`
- Expected: stderr shows the re-scan was triggered (not silently honored), the post-scan verdict (`block` for min-age) is then bypassed by `--force`, package manager is invoked. Critically, the install does NOT proceed using only the stale cached `pass`.

### T-030-13: Verify-loop closes — second run is a clean cache hit
- Run T-030-07 to populate the cache with the new hash
- Run `dep-scan check pkg --registry npm --verbose` a second time (wiremock still returns `sha512:bbbb`)
- Expected: exit 0, output contains `cache hit (verified)`, no re-scan

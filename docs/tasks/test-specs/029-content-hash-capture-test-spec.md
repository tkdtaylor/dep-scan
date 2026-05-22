# Test Spec — Task 029: Capture content hash in scan cache

## Unit tests (PackageMetadata + registry clients)

### T-029-01: PackageMetadata.content_hash defaults to None
- Construct `PackageMetadata` with no `content_hash`
- Expected: field is `None`

### T-029-02: npm client extracts dist.integrity
- Fixture response with `dist.integrity = "sha512-<base64>"`
- Expected: `content_hash = Some("sha512:<hex>")` (decoded and normalized to hex)

### T-029-03: npm client falls back to dist.shasum when integrity missing
- Fixture response with only `dist.shasum = "<hex>"`
- Expected: `content_hash = Some("sha1:<hex>")`

### T-029-04: npm client tolerates missing dist
- Fixture response with neither `dist.integrity` nor `dist.shasum`
- Expected: `content_hash = None`, no error

### T-029-05: PyPI client extracts sdist digest
- Fixture release with an sdist file having `digests.sha256`
- Expected: `content_hash = Some("sha256:<hex>")` taken from the sdist entry

### T-029-06: PyPI client falls back to first wheel when no sdist
- Fixture release with only wheels (no sdist)
- Expected: `content_hash = Some("sha256:<hex>")` from the first wheel's `digests.sha256`

### T-029-07: PyPI client tolerates missing digests
- Fixture release with no `digests` block
- Expected: `content_hash = None`, no error

### T-029-08: crates.io client extracts cksum
- Fixture response with `cksum = "<hex>"`
- Expected: `content_hash = Some("sha256:<cksum>")`

### T-029-09: Go module client extracts h1 hash
- Fixture sum-DB response line: `<module> <version> h1:<base64>`
- Expected: `content_hash = Some("h1:<base64>")`

## Unit tests (Cache schema and migration)

### T-029-10: Cache::new on a fresh DB creates content_hash column
- New `:memory:` cache
- Expected: `PRAGMA table_info(scanned_packages)` lists `content_hash` of type `TEXT`, nullable

### T-029-11: Cache::new on a legacy DB adds the column in place
- Manually create the v1.0 `scanned_packages` schema (no `content_hash`)
- Insert one legacy row
- Open with `Cache::new`
- Expected: column is added, the legacy row is preserved with `content_hash = NULL`, no error

### T-029-12: Cache::new is idempotent across the migration
- Open the same DB twice in sequence
- Expected: no "duplicate column" error on the second open

## Unit tests (Cache insert/lookup round-trip)

### T-029-13: insert + lookup round-trips content_hash
- Insert (`lodash`, `4.17.21`, `npm`, `pass`, `content_hash = Some("sha512:abcd…")`)
- Lookup the same key
- Expected: `CacheEntry.content_hash == Some("sha512:abcd…")`

### T-029-14: insert with None stores NULL
- Insert with `content_hash = None`
- Lookup
- Expected: `CacheEntry.content_hash == None`, no error

### T-029-15: Legacy rows return None for content_hash
- After migration test (T-029-11), `lookup` the legacy row
- Expected: `CacheEntry.content_hash == None` — surfaced as `None`, not an error or mismatch signal

### T-029-16: Re-insert updates content_hash via upsert
- Insert with `content_hash = Some("sha256:aaaa")`
- Re-insert same key with `content_hash = Some("sha256:bbbb")`
- Lookup
- Expected: `CacheEntry.content_hash == Some("sha256:bbbb")`

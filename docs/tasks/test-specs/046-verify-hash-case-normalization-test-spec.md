# Test Spec — Task 046: verify_hash algorithm-prefix case normalization

## Context

`verify_hash(cached, registry)` in `src/main.rs` compares two content-hash
strings of the form `<algo>:<hex>`.  The comparison is currently a plain
byte-equality check.  The algorithm prefix (`sha512`, `sha256`, etc.) originates
from `parse_npm_integrity`, which lowercases the SRI prefix (`sha512-…` →
`sha512:`), but the PyPI and crates.io paths may produce mixed-case prefixes in
future, and a registry could legally return `SHA512-…` as a valid SRI string.

If a registry returns `SHA512-<base64>` once and `sha512-<base64>` for the same
bytes later, `verify_hash` would compare `"SHA512:<hex>"` against `"sha512:<hex>"`
and find them unequal, returning `Reverify` instead of `HonorCache`.  This
causes a spurious re-scan — not a security vulnerability but a correctness defect.

The fix: lowercase the algorithm prefix (the part before the first `:`) on both
sides before comparison.

---

## Unit tests — `verify_hash`

### T-046-01: Matching sha512 hashes (lowercase on both sides) returns HonorCache
- `cached  = Some("sha512:abcdef")`
- `registry = Some("sha512:abcdef")`
- Expected: `HashVerifyDecision::HonorCache`.

### T-046-02: Matching hashes where cached has uppercase prefix — HonorCache
- `cached  = Some("SHA512:abcdef")`
- `registry = Some("sha512:abcdef")`
- Expected: `HashVerifyDecision::HonorCache`.
- This is the primary bug being fixed.

### T-046-03: Matching hashes where registry has uppercase prefix — HonorCache
- `cached  = Some("sha512:abcdef")`
- `registry = Some("SHA512:abcdef")`
- Expected: `HashVerifyDecision::HonorCache`.

### T-046-04: Both sides uppercase, same hex — HonorCache
- `cached  = Some("SHA512:ABCDEF")`
- `registry = Some("SHA512:ABCDEF")`
- Expected: `HashVerifyDecision::HonorCache`.
- Note: only the algorithm prefix is normalized; the hex portion retains its
  original case and comparison proceeds on the normalized strings.  If hex is
  case-sensitive in practice (it should be lowercase), this test ensures the
  prefix normalization alone resolves the issue.

### T-046-05: Algorithm prefix matches but hex differs — Reverify
- `cached  = Some("sha512:aaa")`
- `registry = Some("sha512:bbb")`
- Expected: `HashVerifyDecision::Reverify`.

### T-046-06: Different algorithms (sha256 vs sha512) — Reverify
- `cached  = Some("sha256:abcdef")`
- `registry = Some("sha512:abcdef")`
- Expected: `HashVerifyDecision::Reverify`.

### T-046-07: Mixed-case different algorithms — Reverify
- `cached  = Some("SHA256:abcdef")`
- `registry = Some("sha512:abcdef")`
- Expected: `HashVerifyDecision::Reverify`.

### T-046-08: sha1-prefixed cached hash — Reverify (existing behavior preserved)
- `cached  = Some("sha1:deadbeef")`
- `registry = Some("sha1:deadbeef")`
- Expected: `HashVerifyDecision::Reverify` — sha1 rejection from task 040 is
  checked before the case-normalization comparison and must not be removed.

### T-046-09: SHA1-uppercase cached hash — Reverify (sha1 rejection applies regardless of case)
- `cached  = Some("SHA1:deadbeef")`
- `registry = Some("SHA1:deadbeef")`
- Expected: `HashVerifyDecision::Reverify` — case normalization of the prefix
  must happen after the sha1 guard, or the sha1 guard must also be case-insensitive.
- Implementer note: the sha1 guard uses `c.starts_with("sha1:")`.  After prefix
  normalization, a `"SHA1:…"` string becomes `"sha1:…"`, so the guard correctly
  fires.  Ensure the sha1 check occurs on the normalized prefix, not on the
  original string.

### T-046-10: None on both sides — Reverify (fail-closed, unchanged)
- `cached = None`, `registry = None`
- Expected: `HashVerifyDecision::Reverify`.

### T-046-11: Hash string with no colon separator — treated as no-prefix, compared as-is
- `cached  = Some("nodash")`
- `registry = Some("nodash")`
- Expected: `HashVerifyDecision::HonorCache` — if there is no `:`, treat the
  whole string as the "prefix" (no transformation) and compare directly.
  This is a degenerate case that should not occur with real registry data;
  the test ensures the function does not panic.

### T-046-12: Empty string hash — Reverify (not a valid hash, fail-closed)
- `cached  = Some("")`
- `registry = Some("")`
- Expected: `HashVerifyDecision::Reverify` — an empty hash string is not a
  valid match.

---

## Integration test

### T-046-13: A package whose registry later returns an uppercase algorithm prefix is still recognized from cache
- Pre-populate cache with `(pkg, "1.0.0", npm, "pass", content_hash="sha512:aabbcc")`
- wiremock serves `dist.integrity = "SHA512-qrs…"` (SRI with uppercase, same decoded hex as `aabbcc`)
- After `parse_npm_integrity` normalizes the SRI form to `sha512:<hex>` or `SHA512:<hex>`,
  `verify_hash` must still return `HonorCache`.
- Expected: `dep-scan check pkg --registry npm` reports cache hit; wiremock receives only 1 metadata call.
- Implementer note: this test depends on `parse_npm_integrity` being the place
  that converts `SHA512-<b64>` → `<algo>:<hex>`.  If `parse_npm_integrity`
  already lowercases, this test may trivially pass; it is included to ensure no
  regression if that normalization is ever changed.

---

## Regression tests

### T-046-14: All task 030 hash-verify tests still pass
- Run `cargo test content_hash_verify` (or equivalent).
- Expected: 0 failures.

### T-046-15: All task 040 sha1-rejection tests still pass
- Run `cargo test sha1`.
- Expected: 0 failures — the sha1 rejection path is not affected by prefix normalization.

### T-046-16: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

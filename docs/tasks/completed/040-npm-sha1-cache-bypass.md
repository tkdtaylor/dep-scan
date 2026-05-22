# Task 040 — Reject SHA-1 content hashes as cache trust gates for npm

**Status:** backlog
**Depends on:** 029 (content hash capture), 030 (content hash verify), 005 (npm registry client)
**Security finding:** H-4 (HIGH)
**Touches:** `src/registry/npm.rs`, `src/main.rs` (cache insertion and lookup policy)

## Objective

Stop treating npm `dist.shasum` (a raw SHA-1 hex digest) as a trust-gating cache key. A SHA-1-only package verdict cached as `pass` can be replayed against a tarball with a chosen-prefix collision — SHAttered-class attacks cost approximately $45k in 2020 and are dropping. The fix: when a package's only available content hash is `sha1:`-prefixed, never honor a cached `pass` verdict based on that hash; always re-run the full scan pipeline.

## Background

`extract_npm_content_hash` in `src/registry/npm.rs` prefers `dist.integrity` (SRI format, typically `sha512-…`) but falls back to `dist.shasum` (SHA-1) when `integrity` is absent. The resulting `sha1:<hex>` string is stored in the `content_hash` column and used by the task 030 hash-verify logic to decide whether to honor a cached verdict.

The problem: SHA-1 is cryptographically broken for collision resistance. An attacker who can produce two tarballs with the same SHA-1 digest can republish under a known `shasum`, causing dep-scan to see a "matching" hash and honor the cached `pass` verdict for the new (malicious) tarball. This bypasses the full policy pipeline.

`sha512:` hashes (from `dist.integrity`) are not affected — SHA-512 has no known practical collision attacks. The fix is targeted at the `sha1:` prefix only.

## Behavior

### Cache insertion

In `run_check` in `src/main.rs`, when calling `cache.insert`:

- If `metadata.content_hash` starts with `sha1:` AND the verdict is `pass` or `warn`:
  - Either do not insert (the scan runs fresh every time for sha1-only packages), OR
  - Insert with `content_hash = NULL` (so the task 030 hash-verify always produces `Reverify`, never `HonorCache`).
  - **The implementer must choose one approach and document it here.** Option (b) (insert with NULL hash) is preferred because it preserves the scan timestamp and `provenance_identity` columns for auditing purposes.
- If `metadata.content_hash` starts with `sha1:` AND the verdict is `block`:
  - Insert normally — caching a `block` result is safe; the next scan will re-block, not silently pass.
- If `metadata.content_hash` starts with `sha512:` or any other non-sha1 algorithm: no change to current behavior.

### Cache lookup

In the `verify_hash` function (or equivalent in `src/main.rs`):

- If the cached `content_hash` starts with `sha1:`, always return `Reverify` regardless of whether the registry-served hash matches.
- This closes the window even for old rows already in user databases with sha1 hashes from before this fix.

### Verbose output

When a sha1-only cache entry is bypassed, emit a verbose message: `"sha1 hash not accepted for cache short-circuit; re-scanning"` (or equivalent) so operators can see why the cache was skipped.

## Requirements

- **REQ-040-01:** A cached `pass` verdict backed by a `sha1:` content hash is never honored; the full scan pipeline always runs for sha1-only packages.
- **REQ-040-02:** A cached `block` verdict backed by a `sha1:` content hash may be honored (re-blocking is not a security regression).
- **REQ-040-03:** When inserting a `pass` or `warn` verdict for a sha1-only package, `content_hash` is stored as `NULL` (or the row is omitted), so the next lookup produces `Reverify`.
- **REQ-040-04:** Packages with `sha512:` or other non-sha1 hashes are unaffected — the cache short-circuit continues to work for them.
- **REQ-040-05:** A verbose log message is emitted when a sha1-only cache entry is bypassed.
- **REQ-040-06:** The `extract_npm_content_hash` function continues to return the sha1 hash value for informational purposes (e.g. logging); the policy change lives in the cache layer, not the hash extraction function.

## Acceptance criteria

- [ ] Cache insertion for sha1-only pass/warn stores `content_hash = NULL` (REQ-040-03); verified by T-040-04, T-040-06.
- [ ] Cache lookup for sha1-prefixed hash always returns `Reverify` (REQ-040-01); verified by T-040-07, T-040-08.
- [ ] Cache insertion for sha1-only block stores the row normally (REQ-040-02); verified by T-040-05.
- [ ] sha512 cache behavior unaffected (REQ-040-04); verified by T-040-09, T-040-13.
- [ ] Verbose bypass message emitted (REQ-040-05); verified by T-040-11.
- [ ] `extract_npm_content_hash` still returns sha1 values (REQ-040-06); verified by T-040-01, T-040-02.
- [ ] Chosen-prefix collision scenario does not yield a cache hit (T-040-12).
- [ ] Two runs of a sha1-only package both execute the full pipeline (T-040-10).
- [ ] Task 030 and task 032 tests pass unchanged (T-040-13, T-040-14).
- [ ] `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Rejecting packages that have only SHA-1 hashes (blocking the install entirely). That is a policy decision beyond the scope of this security hardening task; the goal is to prevent the cache from becoming a trust bypass, not to break installs of legacy npm packages.
- Upgrading npm's SHA-1 usage at the registry level. The npm registry serves `dist.shasum` for many packages published before SRI was adopted; dep-scan cannot control this.
- Applying the same sha1 treatment to crates.io or PyPI — those registries use SHA-256 or SHA-512 exclusively. This task is npm-specific.

## Risk notes

- Packages with only `dist.shasum` will now be re-scanned on every `dep-scan check` invocation. For projects with many legacy npm dependencies this may increase scan time noticeably. This is an intentional security vs. performance trade-off; the performance impact can be mitigated by encouraging registry owners to add `dist.integrity` fields (which npm has supported since npm@5).
- Existing user databases may have sha1-backed `pass` rows. The cache lookup change (always reverify sha1 hashes) handles these automatically without a migration.

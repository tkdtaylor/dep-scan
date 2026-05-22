# Test Spec — Task 057: Bump `rusqlite` 0.31 → 0.39

## Context

dep-scan is 8 minor versions behind on `rusqlite`.  The changelog between 0.31
and 0.39 contains breaking changes to the parameter-binding API (`params!` macro
semantics, `Rows` iterator behaviour, and `Connection::prepare` lifetime rules).
`src/cache.rs` is the sole consumer and exercises the full API surface:
`Connection::open`, `execute_batch`, `prepare`, `query_map`, `execute`, and the
`params!` macro.

This is the highest-risk dep bump in this batch because every cache operation
(insert, lookup, invalidate, maintainer history read/write) passes through
rusqlite.  The spec explicitly covers the task 029, 038, and 040 cache behaviors
that are load-bearing for security (content hash storage, resolved-version keying,
SHA-1 rejection).

---

## Compilation tests

### T-057-01: `cargo build --release` succeeds after bumping `rusqlite` to `"0.39"`
- Update `Cargo.toml` to `rusqlite = { version = "0.39", features = ["bundled"] }`.
- Expected: `cargo build --release` exits 0 — all `params!` usages, `query_map`
  calls, and `execute_batch` calls compile without error.

### T-057-02: `cargo audit` is clean after the bump
- Expected: exit 0, no advisories for `rusqlite` or `libsqlite3-sys`.

---

## Cache correctness tests (regression suite — all must pass after the bump)

These tests exercise the exact API surface that rusqlite breaking changes affect.

### T-057-03: `Cache::new` creates the `scanned_packages` table (T-007-01 equivalent)
- Call `Cache::in_memory()`.
- Expected: `Ok(_)` — no error from `execute_batch`.

### T-057-04: Insert and lookup round-trip `result` (T-007-02 equivalent)
- Insert `("pkg", "1.0.0", "npm", "pass", None, None)`.
- Lookup `("pkg", "1.0.0", "npm")`.
- Expected: `Ok(Some(CacheEntry { result: "pass", … }))`.

### T-057-05: Cache upsert updates existing row (T-007-04 equivalent)
- Insert `("pkg", "1.0.0", "npm", "pass", None, None)`.
- Insert `("pkg", "1.0.0", "npm", "block", None, None)`.
- Lookup.
- Expected: `result == "block"`.

### T-057-06: `cache.invalidate` removes the row (T-007-05 equivalent)
- Insert then invalidate `("pkg", "1.0.0", "npm")`.
- Expected: lookup returns `Ok(None)`.

### T-057-07: Content hash round-trips through `params!` (T-029-13 equivalent — task 029)
- Insert with `content_hash = Some("sha512:abcdef1234567890")`.
- Lookup.
- Expected: `content_hash == Some("sha512:abcdef1234567890")`.
- Rationale: task 029 is the primary SHA-512 content-hash path; a rusqlite
  params API change could silently truncate or misplace the hash value.

### T-057-08: `provenance_identity` round-trips (T-032-16 equivalent — task 032)
- Insert with `provenance_identity = Some("https://github.com/…/release.yml@refs/tags/v1")`.
- Lookup.
- Expected: `provenance_identity` matches the inserted value exactly.

### T-057-09: SHA-1 content hash `"sha1:<hex>"` stored as `NULL` (T-040-04
  equivalent — task 040)
- Simulate an npm sha1-only package: insert with `content_hash = None` (SHA-1
  is not cached as a trust gate per task 040).
- Lookup.
- Expected: `content_hash == None`.
- Rationale: the sha1 bypass relies on `None` being stored correctly; a rusqlite
  `params!` change that maps `None` differently could silently re-enable sha1 trust.

### T-057-10: Resolved-version keying is intact (T-038 equivalent — task 038)
- Insert `("lodash", "4.17.21", "npm", "pass", Some("sha512:aaaa"), None)`.
- Insert `("lodash", "4.17.22", "npm", "pass", Some("sha512:bbbb"), None)`.
- Lookup `("lodash", "4.17.21", "npm")`.
- Expected: `content_hash == Some("sha512:aaaa")` — different versions are
  distinct keys; the 0.31 → 0.39 param-binding change must not collapse them.

### T-057-11: Maintainer history insert and retrieve (T-014-01 equivalent — task 014)
- `record_maintainers("lodash", "npm", &["alice", "bob"])`.
- `get_previous_maintainers("lodash", "npm")`.
- Expected: `Ok(Some(["alice", "bob"]))`.

### T-057-12: Additive migration (content_hash column) runs without error on legacy schema
- Construct a pre-029 schema DB (no `content_hash` column).
- Open with `Cache::new`.
- Expected: `Ok(_)` — `ALTER TABLE … ADD COLUMN` executes without error under
  rusqlite 0.39.

### T-057-13: Additive migration (provenance_identity column) runs without error
- Construct a post-029/pre-032 schema DB (has `content_hash`, no
  `provenance_identity`).
- Open with `Cache::new`.
- Expected: `Ok(_)`.

---

## API-surface checks

### T-057-14: `params!` macro in `insert` compiles with 7 parameters
- The `insert` method passes 7 parameters to rusqlite via `params![name, version,
  registry, result, scanned_at, content_hash, provenance_identity]`.
- Expected: compiles cleanly — the `params!` macro limit and syntax must
  accommodate 7 elements under rusqlite 0.39.

### T-057-15: `query_map([], …)` syntax (zero params) compiles for PRAGMA queries
- `cache.conn.prepare("PRAGMA table_info(scanned_packages)")?.query_map([], …)`
- Expected: compiles — zero-parameter `query_map` must remain valid in 0.39.

---

## Regression tests

### T-057-16: Total test count does not drop
- Run `cargo test` before and after the bump.
- Expected: count after >= 635.

### T-057-17: `cargo clippy --all-targets -- -D warnings` passes
### T-057-18: `cargo fmt --check` passes

# Test Spec — Task 047: Cache I/O error surfacing

## Context

`cache.lookup(...)` returns `Result<Option<CacheEntry>, anyhow::Error>`.  The
call site in `src/main.rs` uses `if let Ok(Some(entry)) = cache.lookup(...)`,
which silently discards any `Err(_)` variant.  A corrupted or unreadable SQLite
database causes every lookup to return `Err`, producing 100% cache misses with
no indication to the user that the cache is broken.

The fix has two parts:
1. When `lookup` returns `Err`, write a warning to `stderr` (minimum viable
   surface); do not silently swallow the error.
2. In non-`--force` paths, treat a persistent DB error as fatal (exit with a
   non-zero code and an actionable error message) to prevent the user from
   unknowingly operating on a potentially tampered cache.

---

## Unit tests — `Cache::lookup` error propagation

### T-047-01: `Cache::lookup` on a valid in-memory database returns `Ok`
- Create `Cache::in_memory()`.
- Call `lookup("pkg", "1.0.0", "npm")` on an empty database.
- Expected: `Ok(None)`.

### T-047-02: `Cache::lookup` after inserting an entry returns `Ok(Some(entry))`
- Create `Cache::in_memory()`, insert `("pkg", "1.0.0", "npm", "pass", None, None)`.
- Call `lookup("pkg", "1.0.0", "npm")`.
- Expected: `Ok(Some(CacheEntry { result: "pass", … }))`.

### T-047-03: `Cache` created on a path that is a directory (not a file) returns `Err` from `new`
- Call `Cache::new(Path::new("/tmp"))` (a directory, not a file).
- Expected: `Err(_)` — the cache constructor correctly propagates the SQLite
  connection error.
- This test verifies the error surfaces at construction time, not silently at
  lookup time.

---

## Unit tests — call-site error handling in `run_check`

### T-047-04: A lookup `Err` is written to stderr, not silently dropped
- This cannot be tested against the real SQLite connection in a unit test without
  injecting a broken connection.  Use a mock or wrapper trait for the cache.
- **Implementer note:** if `Cache` implements a `CacheLookup` trait (or if
  `lookup` is extracted behind a trait), inject a mock that always returns
  `Err(anyhow!("simulated I/O error"))`.
- Run the check pipeline with the mock cache.
- Expected: `stderr` contains a message describing the cache error (e.g.
  "cache lookup failed: simulated I/O error — re-scanning").
- The package scan proceeds (fail-open for the lookup error; the scan itself runs).

### T-047-05: A lookup `Err` in non-`--force` mode writes to stderr and the process exits non-zero
- Same mock as T-047-04, but the error is persistent (every lookup fails).
- Expected: the process exits with a non-zero exit code and the error message
  appears on stderr.
- **Implementer note:** "persistent" means the error happens on the first (and
  only) lookup for the package under test.  A single lookup failure is
  sufficient to trigger the fatal path.
- Whether to make this fatal or warn-only is a policy decision documented in the
  task file.  This test asserts the chosen behavior — see REQ-047-02.

### T-047-06: In `--force` mode, a lookup `Err` is logged but does not cause a non-zero exit
- `dep-scan check pkg --registry npm --force` with a broken cache mock.
- Expected: the process exits 0 (or exits based on policy verdict, not cache error);
  stderr contains the cache-error warning.

---

## Integration tests (assert_cmd + broken SQLite file)

### T-047-07: Corrupted cache file produces an actionable error message
- Write garbage bytes to the SQLite cache path.
- Run `dep-scan check pkg --registry npm` (wiremock serves valid metadata).
- Expected: stderr contains a message like "cache database error" or "cache is
  corrupted" with the file path; exit code is non-zero (or the check proceeds
  with a clear warning if warn-only policy was chosen).

### T-047-08: Cache file with wrong permissions (unreadable) produces an error message
- `#[cfg(unix)]`
- Create a valid SQLite file, then `chmod 000` it.
- Run `dep-scan check pkg --registry npm`.
- Expected: stderr contains a permission-related error message; exit code is
  non-zero (or the scan proceeds with a clear warning, consistent with
  REQ-047-02).

### T-047-09: After the cache error is surfaced, the full scan pipeline still runs (no silent skip)
- Use the corrupted cache from T-047-07.
- wiremock serves clean metadata that would result in a `pass` verdict.
- Expected: the scan pipeline runs and produces a verdict (pass/warn/block);
  the cache error does not prevent the scan from completing.

---

## Regression tests

### T-047-10: All task 007 cache tests still pass
- Run `cargo test cache`.
- Expected: 0 failures — the cache module behavior for valid databases is unchanged.

### T-047-11: All task 030 hash-verify tests still pass
- Run `cargo test content_hash_verify`.
- Expected: 0 failures — the cache error path is separate from the hash-verify path.

### T-047-12: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

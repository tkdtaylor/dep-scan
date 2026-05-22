# Test Spec — Task 054: Cache DB privacy hardening (L-7)

## Context

`Cache::new` in `src/cache.rs` opens the SQLite database with no file-permission
hardening.  On Unix systems the file inherits the process umask (typically `0644`),
making it world-readable: any user on the same host can enumerate every package
name and verdict dep-scan has ever recorded.

The fix has two parts:
1. After opening the database file, `chmod 0600` it on Unix
   (`#[cfg(unix)]` only — Windows inherits parent-directory ACLs).
2. Execute `PRAGMA journal_mode = WAL` to improve durability and to ensure
   that the `-wal` and `-shm` companion files SQLite creates are also restricted
   to the same permissions as the main file.

---

## Unit tests — file permission hardening (`#[cfg(unix)]`)

### T-054-01: Cache DB file created on Unix has mode 0600
- `#[cfg(unix)]`
- Create a `Cache::new(path)` at a temp path.
- Stat the file.
- Expected: `mode & 0o777 == 0o600` — owner read/write, no group or world bits.

### T-054-02: No group or world read bits are set on a newly created cache DB
- `#[cfg(unix)]`
- Same setup as T-054-01.
- Expected: `mode & 0o077 == 0` — no group or world permissions of any kind.

### T-054-03: `chmod 0600` is applied even if the file was created with a permissive umask
- `#[cfg(unix)]`
- Temporarily set umask to `0022` (the typical default) before calling `Cache::new`.
- Expected: the file has mode `0600` regardless of umask.
- Implementation note: use `std::os::unix::fs::PermissionsExt` to read back the
  mode after `Cache::new` returns.

### T-054-04: Re-opening an existing cache DB does not widen its permissions
- `#[cfg(unix)]`
- Create a `Cache::new(path)` (mode is now 0600).
- Drop the cache.
- Re-open with a second `Cache::new(path)` call.
- Stat the file after re-open.
- Expected: mode is still `0600` — re-opening must not widen permissions.

### T-054-05: WAL journal mode is set after `Cache::new`
- Create `Cache::new(path)` at a temp path.
- Query `PRAGMA journal_mode`.
- Expected: the returned value is `"wal"`.

### T-054-06: WAL mode is present even when opening an existing database that was in DELETE mode
- Create the SQLite file manually with `PRAGMA journal_mode = DELETE`.
- Open with `Cache::new`.
- Query `PRAGMA journal_mode`.
- Expected: `"wal"` — `Cache::new` upgrades to WAL regardless of the previous mode.

---

## Unit tests — cache functionality is unaffected

### T-054-07: Insert and lookup still work after WAL is enabled
- Create `Cache::new(path)`.
- Insert `("pkg", "1.0.0", "npm", "pass", None, None)`.
- Lookup `("pkg", "1.0.0", "npm")`.
- Expected: `Ok(Some(CacheEntry { result: "pass", … }))`.

### T-054-08: `Cache::in_memory()` is unaffected by the chmod step (`:memory:` has no path)
- Call `Cache::in_memory()`.
- Expected: `Ok(_)` — no panic or error from attempting to chmod a non-existent path.

---

## Integration tests (assert_cmd)

### T-054-09: `dep-scan check pkg --registry npm` creates a cache DB with mode 0600
- `#[cfg(unix)]`
- Run `dep-scan check pkg --registry npm` (wiremock serves clean metadata).
- Locate the cache DB file (default path `~/.local/share/dep-scan/cache.db` or
  the path configured in `.dep-scan.toml`).
- Expected: `mode & 0o777 == 0o600`.

### T-054-10: The `-wal` companion file, if it exists, also has mode 0600
- `#[cfg(unix)]`
- After T-054-09, check for `<cache-path>-wal`.
- If the file exists: `mode & 0o777 == 0o600`.
- If the file does not exist: pass (SQLite may not create `-wal` until a write
  is committed in some configurations; the important guarantee is that it is not
  world-readable if created).

---

## Regression tests

### T-054-11: All task 007 cache unit tests still pass
- Run `cargo test cache`
- Expected: 0 failures — permission hardening and WAL mode do not affect
  insert/lookup/invalidate/clear behavior.

### T-054-12: All task 047 cache I/O error tests still pass
- Run `cargo test t047`
- Expected: 0 failures.

### T-054-13: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` all pass.

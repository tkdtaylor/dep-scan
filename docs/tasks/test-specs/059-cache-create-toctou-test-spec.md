# Test Spec — Task 059: Close cache DB create-then-chmod TOCTOU (N-L-1)

## Context

`Cache::new` in `src/cache.rs` currently calls `Connection::open(path)` first,
which lets SQLite create the file under the process umask (typically `0644` on
Linux and macOS), and _then_ narrows permissions with `std::fs::set_permissions`.
Between those two calls there is a brief window where the file is world-readable.
On a multi-user host a local attacker can `open(O_RDONLY)` the file during the
race and keep a live FD as SQLite writes data into it.

The fix closes the window by creating the file at `0o600` _before_ handing the
path to `Connection::open`.  On Unix a `cfg(unix)` block calls
`OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)` to
create the file atomically with the correct mode, then drops the handle so
`Connection::open` can proceed.  If the file already exists the `create_new`
call returns `ErrorKind::AlreadyExists`; in that case the code falls through to
the existing `set_permissions(0o600)` call (which fixes legacy `0644` files
upgraded from earlier releases).

---

## Unit tests — atomic create-time permission hardening (`#[cfg(unix)]`)

### T-059-01: File created by `Cache::new` on a fresh path has mode `0600` immediately
- `#[cfg(unix)]`
- Choose a temp path that does not yet exist.
- Call `Cache::new(path)`.
- Stat the file.
- Expected: `mode & 0o777 == 0o600`.

### T-059-02: No group or world read bits exist after `Cache::new` on a fresh path
- `#[cfg(unix)]`
- Same setup as T-059-01.
- Expected: `mode & 0o177 == 0` — owner execute bit is also absent.

### T-059-03: Mode is `0600` even when the process umask is `0000` (maximally permissive)
- `#[cfg(unix)]`
- Call `libc::umask(0o000)` before `Cache::new`.
- Expected: file mode is still `0600`, not `0666`.
- Restore the original umask after the test.

### T-059-04: Mode is `0600` even when the process umask is `0022` (typical default)
- `#[cfg(unix)]`
- Temporarily set umask to `0o022` before calling `Cache::new` on a fresh path.
- Expected: `mode & 0o777 == 0o600`.

### T-059-05: Stat is taken _before_ any SQLite WAL writes (no race with the connection open)
- `#[cfg(unix)]`
- Call `Cache::new(path)` and capture the path before the function returns.
- Stat the file immediately; do not insert any data first.
- Expected: `mode & 0o777 == 0o600`.
- Rationale: the mode must be correct at the moment the file descriptor becomes
  visible, not only after the first write.

### T-059-06: Re-opening an existing `0600` cache DB preserves mode `0600`
- `#[cfg(unix)]`
- Create a `Cache::new(path)` (mode is now `0600`).
- Drop the cache.
- Open a second `Cache::new(path)`.
- Stat the file.
- Expected: mode is still `0600`.

### T-059-07: Re-opening a legacy `0644` cache DB narrows it to `0600`
- `#[cfg(unix)]`
- Create the SQLite file manually with mode `0644` (simulating a pre-fix cache).
- Call `Cache::new(path)`.
- Stat the file after `Cache::new` returns.
- Expected: `mode & 0o777 == 0o600`.

### T-059-08: `Cache::in_memory()` continues to succeed without attempting a chmod
- Call `Cache::in_memory()`.
- Expected: `Ok(_)` — no panic or I/O error from attempting to create or chmod
  a file for a `:memory:` database.

---

## Unit tests — structural / implementation check

### T-059-09: `create_new(true)` (or equivalent `O_CREAT | O_EXCL`) is used in the Unix create path
- Code review assertion: the `cfg(unix)` pre-create block uses `create_new(true)`
  (from `std::fs::OpenOptions`) or an equivalent system call that is guaranteed
  atomic and fails if the file already exists, rather than `create(true)` which
  silently opens an existing file.
- Verifiable by reading the source.

### T-059-10: The pre-created file handle is dropped before `Connection::open` is called
- Code review assertion: the `File` returned by the `OpenOptions` call is dropped
  (or goes out of scope) before `Connection::open(path)` runs, so SQLite can open
  the file exclusively without a "file busy" error on platforms that use mandatory
  locking.
- Verifiable by reading the source.

---

## Unit tests — cache functionality unaffected

### T-059-11: Insert and lookup round-trip succeeds after the TOCTOU fix
- Call `Cache::new(path)`.
- Insert `("mylib", "2.0.0", "crates", "pass", None, None)`.
- Look up `("mylib", "2.0.0", "crates")`.
- Expected: `Ok(Some(CacheEntry { result: "pass", … }))`.

### T-059-12: WAL journal mode is still active after the TOCTOU fix
- Call `Cache::new(path)`.
- Query `PRAGMA journal_mode`.
- Expected: `"wal"` — the TOCTOU fix must not displace the WAL pragma introduced
  in task 054.

---

## Regression tests

### T-059-13: All task 054 cache privacy tests still pass
- Run `cargo test cache`.
- Expected: 0 failures — T-054-01 through T-054-13 must all continue to pass.

### T-059-14: All task 007 cache unit tests still pass
- Run `cargo test cache`.
- Expected: 0 failures — insert/lookup/invalidate/clear behavior is unchanged.

### T-059-15: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` all pass.

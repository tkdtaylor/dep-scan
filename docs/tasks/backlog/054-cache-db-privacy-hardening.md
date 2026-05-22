# Task 054 — Cache DB privacy hardening (L-7)

**Status:** backlog
**Depends on:** 007 (SQLite cache), 047 (cache I/O error surfacing)
**Security finding:** L-7 (LOW — privacy-of-usage leak on shared hosts)
**Touches:** `src/cache.rs` only

## Objective

Restrict the SQLite cache DB to owner-only permissions (`0600`) on Unix and enable
WAL journal mode so that dep-scan's scan history is not visible to other users
on a shared host.

## Background

`Cache::new` calls `Connection::open(path)` which creates the file with the default
OS permissions (process umask, typically `0644` on Linux and macOS).  This means
any user on the same host can:
- Read the DB with `sqlite3 ~/.local/share/dep-scan/cache.db` and enumerate every
  package name, version, verdict, and OIDC subject that dep-scan has recorded.
- Read any `-wal` companion file that SQLite creates during writes.

On a shared CI runner or a developer machine with multiple users this is a minor
privacy leak (it reveals which packages a developer scans) but not a security
vulnerability (the attacker cannot inject entries — the DB is still owned by the
correct user).

## Behavior

### Unix permission hardening (`#[cfg(unix)]`)

After `Connection::open(path)` succeeds, call:

```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
}
```

This is a no-op for `:memory:` databases (the path is `":memory:"`, which does
not correspond to a real file — the call to `set_permissions` must be guarded
with a `path != Path::new(":memory:")` check to avoid an error).

### WAL journal mode

After connection open and before table creation:

```rust
conn.execute_batch("PRAGMA journal_mode = WAL;")?;
```

WAL mode is not required for correctness but improves durability and is the
SQLite-recommended mode for applications that perform frequent small writes.
The `-wal` and `-shm` companion files SQLite creates in WAL mode will be owned
by the same user as the main DB file and will inherit the `0600` mode that was
just set (because SQLite creates companion files with the same mode as the main
file on Linux via `open(O_CREAT)` with the parent's mode mask).

### Documentation note (Windows)

On Windows, SQLite inherits the ACL of the parent directory.  No additional
permission hardening is applied.  A `// Note: on Windows, the DB file inherits
parent-directory ACLs.` comment in `Cache::new` is sufficient.

## Requirements

- **REQ-054-01:** On Unix, the cache DB file has mode `0600` after `Cache::new`
  returns, regardless of the process umask.
- **REQ-054-02:** On Unix, re-opening an existing cache DB with `Cache::new` does
  not widen its permissions (the chmod call is idempotent).
- **REQ-054-03:** `PRAGMA journal_mode = WAL` is executed during `Cache::new` on
  all platforms.
- **REQ-054-04:** `Cache::in_memory()` (`:memory:` path) continues to work — the
  chmod step is skipped for in-memory databases.
- **REQ-054-05:** All existing cache functionality (insert, lookup, invalidate,
  clear, maintainer history) is unaffected.

## Acceptance criteria

- [ ] `Cache::new(path)` produces a file with mode `0600` on Unix (REQ-054-01);
  verified by T-054-01, T-054-02, T-054-03.
- [ ] Re-opening does not widen permissions (REQ-054-02); verified by T-054-04.
- [ ] `PRAGMA journal_mode = WAL` is active after open (REQ-054-03); verified by
  T-054-05, T-054-06.
- [ ] `Cache::in_memory()` succeeds without chmod error (REQ-054-04); verified by
  T-054-08.
- [ ] Insert/lookup round-trip after WAL enabled (REQ-054-05); verified by T-054-07.
- [ ] Task 007 and 047 regression suites pass (REQ-054-05); verified by T-054-11,
  T-054-12.
- [ ] Windows comment added in `Cache::new` source.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` pass.

## Out of scope

- Encrypting the cache DB (a much larger scope).
- Hardening the `maintainer_history` table separately — it lives in the same file,
  so the DB-level chmod covers both tables.
- Handling the case where the cache directory itself is world-readable — that is a
  configuration concern, not a code defect.

## Risk notes

- The chmod call happens after `Connection::open` succeeds; if the process is
  killed between `open` and `chmod`, the file may be left with the umask-derived
  permissions.  This is an inherent race condition and acceptable for a LOW finding.
- On Linux, `PRAGMA journal_mode = WAL` requires the directory to be writable (for
  `-shm` creation).  This is already required for `Connection::open` to succeed, so
  no additional constraint is added.
- The `#[cfg(unix)]` guard ensures Windows builds are not affected by the
  `std::os::unix` import.

# Task 059 — Close cache DB create-then-chmod TOCTOU (N-L-1)

**Status:** backlog
**Depends on:** 007 (SQLite cache), 054 (cache DB privacy hardening)
**Security finding:** N-L-1 (LOW — TOCTOU between file create and chmod on Unix)
**Touches:** `src/cache.rs` only

## Objective

Eliminate the brief world-readable window that exists between `Connection::open`
(which creates the SQLite file under the process umask, typically `0644`) and the
subsequent `set_permissions(0o600)` call introduced in task 054.

## Background

Task 054 applied `set_permissions(0o600)` after `Connection::open` succeeds.
This narrowed the file's effective permissions but left a TOCTOU gap: on a
multi-user host, a local attacker can `open(O_RDONLY)` the file during the
window between creation and chmod, then hold the FD open as SQLite writes scan
history into it.

The gap is LOW severity because:
- Exploitation requires a local unprivileged attacker who can race the dep-scan
  invocation.
- The data exposed (package names + verdicts + OIDC subjects) is the same
  privacy-of-usage leak already documented in task 054.
- SQLite WAL mode means data may not be visible in the file until a checkpoint,
  limiting what the attacker actually observes.

Nonetheless, the invariant "the file is never world-readable at any instant" is
achievable at near-zero cost and should be enforced.

## Behavior

### Unix create path (`#[cfg(unix)]`)

Before calling `Connection::open(path)`, attempt to pre-create the file with
the correct permissions in one atomic step:

```rust
#[cfg(unix)]
if path != Path::new(":memory:") {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(f) => drop(f),  // release handle before Connection::open
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // File exists (upgrade case): fall through to the chmod below.
        }
        Err(e) => return Err(e.into()),
    }
}
```

After `Connection::open(path)` the existing `set_permissions(0o600)` call
(from task 054) remains in place.  It is now a no-op for freshly created files
(already `0600`) and a one-shot fix for pre-existing legacy `0644` files.

### `:memory:` databases

The guard `if path != Path::new(":memory:")` ensures `Cache::in_memory()` is
unaffected.

### Windows

No change.  Windows inherits parent-directory ACLs; the `#[cfg(unix)]` guard
keeps the `std::os::unix` import off Windows builds.

## Requirements

- **REQ-059-01:** On Unix, `Cache::new(path)` on a fresh path creates the file
  with mode `0600` atomically — there is no instant at which the file exists
  with wider permissions.
- **REQ-059-02:** On Unix, `Cache::new(path)` on a pre-existing `0644` legacy
  file narrows permissions to `0600` (existing task-054 behavior preserved).
- **REQ-059-03:** `Cache::in_memory()` is unaffected by the pre-create step.
- **REQ-059-04:** `PRAGMA journal_mode = WAL` (task 054) remains active.
- **REQ-059-05:** All existing cache functionality (insert, lookup, invalidate,
  clear) is unaffected.

## Acceptance criteria

- [ ] Fresh-path create produces mode `0600` even with umask `0000` (REQ-059-01);
  verified by T-059-01, T-059-03.
- [ ] Fresh-path create produces mode `0600` with umask `0022` (REQ-059-01);
  verified by T-059-04.
- [ ] Stat taken before any writes shows `0600` (REQ-059-01); verified by T-059-05.
- [ ] Legacy `0644` file narrowed on re-open (REQ-059-02); verified by T-059-07.
- [ ] `Cache::in_memory()` succeeds (REQ-059-03); verified by T-059-08.
- [ ] `create_new(true)` used in the Unix path (REQ-059-01); verified by T-059-09.
- [ ] Pre-created handle dropped before `Connection::open` (REQ-059-01); verified
  by T-059-10.
- [ ] WAL mode still active (REQ-059-04); verified by T-059-12.
- [ ] Insert/lookup round-trip works (REQ-059-05); verified by T-059-11.
- [ ] Task 054 and 007 regression suites pass; verified by T-059-13, T-059-14.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` pass.

## Out of scope

- Encrypting the cache DB.
- Protecting the cache directory itself from being world-readable (configuration
  concern).
- Hardening the `-wal` / `-shm` companion files at create time — SQLite creates
  them with the same mode as the main file on Linux, so they inherit `0600`.

## Risk notes

- `create_new(true)` on some network filesystems may behave differently from
  local filesystems.  The change only applies on Unix; NFS-mounted home
  directories may not respect `O_EXCL` reliably, but that is a pre-existing
  concern for SQLite itself.
- The handle drop before `Connection::open` is required because some platforms
  apply advisory locking on SQLite databases.  Holding an extra open FD should
  be harmless in practice, but dropping it first is the safe choice.

# Task 042 — Harden TempReqFile against predictable filename / symlink attack

**Status:** backlog
**Depends on:** 031 (pip require-hashes passthrough)
**Security finding:** H-6 (HIGH)
**Touches:** `src/main.rs` (`TempReqFile::create`), `Cargo.toml`

## Objective

Replace the `SystemTime::now()`-derived temp filename in `TempReqFile::create` with a CSPRNG-backed temp file handle from the `tempfile` crate. This closes two related vulnerabilities: (1) a local attacker who predicts the filename can pre-create it as a symlink to overwrite any file writable by the dep-scan user; (2) the `/tmp` default umask may allow other local users to read the requirements file (which contains package names and hashes) before pip processes it.

## Background

The current implementation in `src/main.rs`:

```rust
fn create(contents: &str) -> Result<Self> {
    let suffix: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ (d.as_secs() << 32))
        .unwrap_or(12345);
    let path = std::env::temp_dir().join(format!("dep-scan-{suffix}.txt"));
    std::fs::write(&path, contents)...
```

Problems:
1. `subsec_nanos()` is predictable on most systems — the nanosecond timestamp is observable by other processes via `/proc/timer_list` or by measuring wall time.
2. `std::fs::write` uses `O_CREAT | O_WRONLY | O_TRUNC` — it does NOT use `O_EXCL`, so if the path already exists as a symlink, the write follows the symlink and overwrites the target.
3. The file is created with the process's default umask (commonly `0o022`), giving group/world read permission on `/tmp`.

The `tempfile` crate (already a dev-dependency in `Cargo.toml`) solves all three issues: `NamedTempFile::new()` uses `O_CREAT | O_EXCL` with mode `0600` on Unix. It must be promoted to a regular dependency so it is available in production builds.

## Behavior

### Replace `TempReqFile::create`

Use `tempfile::Builder::new().prefix("dep-scan-").suffix(".txt").tempfile()` (or `tempfile::NamedTempFile::new()`) to create the file:

```rust
fn create(contents: &str) -> Result<Self> {
    use std::io::Write as _;
    let mut f = tempfile::Builder::new()
        .prefix("dep-scan-")
        .suffix(".txt")
        .tempfile()
        .context("Failed to create temp requirements file")?;
    f.write_all(contents.as_bytes())
        .context("Failed to write temp requirements file")?;
    let path = f.path().to_path_buf();
    // Persist the file — NamedTempFile deletes on drop; we want manual control
    // (or keep the NamedTempFile in the struct and delegate drop to it).
    // See implementation note below.
    Ok(Self { path })
}
```

**Implementation note on keep-open vs. persist:** `NamedTempFile` deletes the file on drop. `TempReqFile` currently also deletes on drop. The simplest approach is to store the `NamedTempFile` inside `TempReqFile` and let its `Drop` handle deletion. The `path()` method then delegates to `NamedTempFile::path()`. This avoids a separate `std::fs::remove_file` call.

### Update `Cargo.toml`

Move `tempfile` from `[dev-dependencies]` to `[dependencies]`.

### Windows note

`tempfile` handles Windows correctly — no `O_EXCL` equivalent (Windows uses named pipes / exclusive create flags internally). The mode-0600 restriction is Unix-only; on Windows the test assertions about permissions are gated with `#[cfg(unix)]`.

## Requirements

- **REQ-042-01:** The temp filename is generated using a CSPRNG (via the `tempfile` crate), not `SystemTime::now()`.
- **REQ-042-02:** The temp file is created with `O_CREAT | O_EXCL` semantics (or equivalent) so a pre-existing symlink at that path causes creation to fail, not overwrite the symlink target.
- **REQ-042-03:** The temp file is created with Unix permissions `0o600` (owner read/write only; no group or world bits).
- **REQ-042-04:** The temp file is deleted on `TempReqFile` drop regardless of whether pip succeeded, failed, or panicked.
- **REQ-042-05:** `tempfile` is listed as a regular (non-dev) dependency in `Cargo.toml`.
- **REQ-042-06:** The written file contents are byte-for-byte identical to the input string (no encoding change).

## Acceptance criteria

- [ ] `TempReqFile::create` uses `tempfile::NamedTempFile` or `tempfile::Builder` (REQ-042-01, REQ-042-02); verified by T-042-09.
- [ ] Unix permissions are `0o600` (REQ-042-03); verified by T-042-01, T-042-08.
- [ ] Two successive calls produce different paths (REQ-042-01 — entropy test); verified by T-042-03.
- [ ] File is deleted on drop (REQ-042-04); verified by T-042-05.
- [ ] Drop does not panic if the file was already deleted (REQ-042-04); verified by T-042-06.
- [ ] `tempfile` in `[dependencies]` not only `[dev-dependencies]` (REQ-042-05); verified by T-042-10.
- [ ] Written contents match input exactly (REQ-042-06); verified by T-042-07.
- [ ] Temp dir is standard temp dir (T-042-02).
- [ ] Temp file cleaned up even when pip is not available (T-042-13).
- [ ] Task 031 pip require-hashes tests pass unchanged (T-042-14).
- [ ] `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Encrypting the requirements file contents. The hashes in the file are public; the security goal is preventing symlink attacks and world-readable writes, not content confidentiality.
- Temp file on a private mount or `tmpfs`. The system temp directory is used as before; the improvement is in how the file is created, not where.
- The `TMPDIR` environment variable override — the `tempfile` crate respects `TMPDIR` by default, which is the correct behavior.

## Risk notes

- Promoting `tempfile` from a dev-dependency to a regular dependency adds it to the production binary. The crate is widely used and well-maintained; this is an acceptable trade-off.
- `NamedTempFile::path()` returns the path while the file is open. If the process is killed before `Drop` runs (e.g. `SIGKILL`), the file is not cleaned up. This is an OS-level limitation that cannot be avoided in userspace; the behavior is identical to the current implementation.
- On some Linux systems, the process's inherited umask may affect the effective permissions even when `tempfile` requests `0600`. The `tempfile` crate creates files with `0600` via explicit `libc::open` flags, bypassing the umask. Verify this behavior holds on the CI platform.

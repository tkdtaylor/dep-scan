# Task 047 — Cache I/O error surfacing

**Status:** backlog
**Depends on:** 007 (SQLite cache), 030 (content hash verify)
**Security finding:** M-3 (MEDIUM)
**Touches:** `src/main.rs` (cache lookup call site), `src/cache.rs`

## Objective

Surface `cache.lookup(...)` errors to the user instead of silently dropping
them.  A corrupted SQLite database currently causes silent cache misses; after
this fix it produces an actionable error message on `stderr` and — in
non-`--force` paths — a non-zero exit code.

## Background

The call site (simplified):

```rust
if let Ok(Some(entry)) = cache.lookup(pkg_name, resolved_version, &reg_str) {
    // ... honor cache or reverify
}
```

`Err(_)` is silently ignored.  An attacker who corrupts the local cache file
causes dep-scan to re-scan every package (not a security bypass), but the user
receives no indication that the cache is broken.  This masks potential tampering
of the DB file itself — the user cannot distinguish "I scanned this before" from
"the cache broke and I'm starting from scratch".

## Behavior

### Warn-on-error, fatal-on-persistent policy

This task implements the following policy:

- A single `cache.lookup` `Err` for a package → emit a warning to `stderr`,
  skip the cache for that package, and proceed with the full scan.  Exit code is
  determined by the scan verdict, not the cache error.
- If the `Cache::new` constructor itself fails (DB cannot be opened or
  initialized) → emit a fatal error to `stderr` and exit with code 1 before
  any scans run.  This is already an `anyhow::Result` propagated via `?`;
  the fix ensures the error message is actionable (includes the DB path and the
  underlying SQLite error).

The warn-on-lookup-error / fatal-on-constructor-error split is chosen because:
- A lookup error on a single package could be transient (e.g. SQLITE_BUSY);
  aborting the entire scan for one package would be too aggressive.
- A constructor error means the cache is fundamentally broken; continuing
  without a cache is acceptable but must be visible.

### Code change

Replace:

```rust
if let Ok(Some(entry)) = cache.lookup(pkg_name, resolved_version, &reg_str) {
```

With:

```rust
let lookup_result = cache.lookup(pkg_name, resolved_version, &reg_str);
if let Err(ref e) = lookup_result {
    eprintln!("dep-scan: cache lookup failed for {pkg_name}@{resolved_version}: {e} — re-scanning");
}
if let Ok(Some(entry)) = lookup_result {
```

Ensure the constructor error path (already propagated via `?` in `Cache::new`)
includes the DB file path in its error context:

```rust
Cache::new(&cache_path)
    .with_context(|| format!("failed to open cache at {}", cache_path.display()))?;
```

## Requirements

- **REQ-047-01:** A `cache.lookup` `Err` writes a warning to `stderr` that
  includes the package name, version, and the underlying error message.
- **REQ-047-02:** A `cache.lookup` `Err` does not cause a non-zero exit on its
  own; the process exits based on the policy scan verdict for that package.
- **REQ-047-03:** A `Cache::new` failure (constructor error) exits non-zero
  with an error message that includes the DB file path.
- **REQ-047-04:** After a lookup error, the full scan pipeline runs for the
  affected package (the cache error does not silently skip the package).
- **REQ-047-05:** All task 007 and task 030 tests continue to pass.

## Acceptance criteria

- [ ] `cache.lookup` `Err` writes to `stderr` (REQ-047-01); verified by T-047-04.
- [ ] Process does not exit non-zero on a single lookup error (REQ-047-02); verified by T-047-05, T-047-09.
- [ ] `--force` path logs the cache error but exits based on verdict (REQ-047-02); verified by T-047-06.
- [ ] Full scan still runs after a cache error (REQ-047-04); verified by T-047-09.
- [ ] Corrupted DB produces an actionable error message (REQ-047-03); verified by T-047-07.
- [ ] Unreadable DB produces an error message (REQ-047-03); verified by T-047-08.
- [ ] Task 007 and 030 regression suites pass (REQ-047-05); verified by T-047-10, T-047-11.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Re-creating the cache file automatically if it is corrupted — that is a
  separate "cache repair" feature.
- Encrypting or authenticating the SQLite file — the cache stores verdicts, not
  secrets; file-level HMAC would be a separate ADR-driven feature.
- Distinguishing transient SQLite errors (SQLITE_BUSY) from permanent ones
  (SQLITE_CORRUPT) — the distinction is informational only; both paths follow
  the same warn-and-continue policy.

## Risk notes

- Printing to `stderr` inside the scan loop (once per package with a broken
  cache) could be noisy if the user has a large lockfile.  This is acceptable
  because a broken cache is not a normal condition.
- The `eprintln!` approach is intentionally simple.  If a structured logging
  layer is added in a future task, the output can be routed through it without
  changing behavior.

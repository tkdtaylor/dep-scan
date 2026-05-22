# Task 057 — Bump `rusqlite` 0.31 → 0.39

**Status:** backlog
**Depends on:** 007 (SQLite cache), 029 (content hash capture), 038 (resolved-version
key), 040 (sha1 cache bypass), 047 (cache I/O error surfacing)
**Security finding:** dependency audit — 8 minor versions behind
**Touches:** `Cargo.toml`, `Cargo.lock`, `src/cache.rs`

## Objective

Upgrade `rusqlite` from `0.31` to `0.39`, fix any compilation errors arising from
breaking API changes in the 8 intervening releases, and verify that all cache
behaviors relied upon by security-critical tasks (029, 038, 040) are unaffected.

## Background

`rusqlite` 0.31 to 0.39 is the highest-risk dep bump in this batch because the
cache module is a load-bearing security component: it short-circuits re-scanning
using content-hash comparison and the resolved-version primary key.  A silent
behavior change in the param-binding or row-fetching API could:

- Collapse distinct version keys (breaking task 038's resolved-version guarantee).
- Fail to store `None` as SQL NULL (breaking task 040's sha1 bypass).
- Misplace the `content_hash` or `provenance_identity` columns in a row fetch
  (breaking tasks 029/032 cache integrity).

Known breaking changes in the changelog between 0.31 and 0.39 include:
- Revised `params!` macro — count limits and syntax may have changed.
- `Rows` iterator — explicit `rows.next()?` pattern may have changed to a
  different combinator.
- `Connection` open flags API — `OpenFlags` struct fields may have changed.
- `Row::get` column index semantics — `get(N)` must still fetch the Nth column
  in the SELECT list.

The implementer must audit the changelog for each of the 8 releases (0.32 through
0.39) and fix any compilation errors before running the full test suite.

## Behavior

This is a version bump with no intentional behavior change.  The cache's external
API (`insert`, `lookup`, `invalidate`, `clear`, `record_maintainers`,
`get_previous_maintainers`) must be fully preserved.

## Requirements

- **REQ-057-01:** `Cargo.toml` specifies `rusqlite = { version = "0.39", features = ["bundled"] }`.
- **REQ-057-02:** `cargo build --release` exits 0.
- **REQ-057-03:** All cache insert/lookup/invalidate/clear operations produce
  identical results to the 0.31 behavior.
- **REQ-057-04:** Content hash storage and retrieval (`None` ↔ NULL, `Some("sha512:…")` ↔ TEXT)
  are identical to the 0.31 behavior.
- **REQ-057-05:** Resolved-version composite key `(name, version, registry)` is
  preserved — distinct versions map to distinct rows.
- **REQ-057-06:** SHA-1 hash suppression (task 040) is unaffected.
- **REQ-057-07:** Additive schema migrations (`ALTER TABLE … ADD COLUMN`) execute
  without error under 0.39.
- **REQ-057-08:** `cargo audit` exits 0 after the bump.

## Acceptance criteria

- [ ] `Cargo.toml` specifies `rusqlite = "0.39"` with `bundled` feature
  (REQ-057-01).
- [ ] Changelog breaking changes from 0.32–0.39 reviewed and addressed; findings
  noted in a source comment in `cache.rs`.
- [ ] `cargo build --release` exits 0 (REQ-057-02); verified by T-057-01.
- [ ] All cache correctness tests pass (REQ-057-03 through REQ-057-07); verified
  by T-057-03 through T-057-15.
- [ ] Additive migrations work (REQ-057-07); verified by T-057-12, T-057-13.
- [ ] `cargo audit` clean (REQ-057-08); verified by T-057-02.
- [ ] Total test count >= 635 after bump (REQ-057-03); verified by T-057-16.
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` pass.

## Out of scope

- Switching from `bundled` to an external SQLite (a separate configuration task).
- Changing the cache schema — only the driver is bumped.
- Enabling rusqlite features that are not currently used (e.g. `trace`, `hooks`).

## Risk notes

- The `bundled` feature compiles SQLite from source; bumping rusqlite may also
  bump the bundled SQLite version.  Verify the bundled SQLite version in
  `Cargo.lock` after the bump.
- If the `params!` macro limit has changed, the 7-parameter `insert` call may
  need to be refactored (e.g. using a tuple or a named-params approach).
- `query_map([], …)` with a zero-length param slice is used for PRAGMA queries;
  if the signature changed to require `params![]` or `[]` explicitly, update
  accordingly.
- This task should be executed last among the three dep bumps (after 056 and
  before 058) to isolate any rusqlite-specific regressions from reqwest regressions.

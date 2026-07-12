# Test Spec — Task 112: cache-verdict-attribution

## Context

Consumer-side bug (sibling repo code-scanner): cached dep-scan verdicts are emitted as a bare `block`/`warn` with `version: "cached"`, `reason: "cached result"`, and an EMPTY `policies` array (`src/main.rs:1280-1289`). code-scanner refuses to GATE on such results because they are unattributable and not reproducible, so dep-scan's supply-chain tier silently drops out of code-scanner's CI gate on any warm cache.

Task 112 makes cached results carry the SAME full attribution as fresh results: the real resolved package version, the full per-policy `policies` array, plus a new additive `cache` object naming the dep-scan version that produced the verdict and when. The cache gains two additive nullable columns (`dep_scan_version TEXT`, `policies_json TEXT`) using the same idempotent `ALTER TABLE ... ADD COLUMN` pattern as tasks 029/032/097/106. Rows that predate attribution (either column NULL, or `policies_json` unparseable, or inconsistent with the stored `result`) are treated as cache MISSES, fail-closed, and upgraded in place by the re-scan's `INSERT OR REPLACE`.

Key code locations (verified against the tree at time of writing):

- `src/cache.rs`: `CacheEntry` (line 10), `Cache::new` migrations (lines 204-275), `lookup` (line 288), `insert` (line 333), `insert_git` (line 383)
- `src/main.rs`: `CheckResult` (line 313), registry cache-hit path (lines 1265-1316, the `version: "cached"` site is line 1282), git cache-hit path (lines 1031-1081), flat `cache.insert` write site (line 1580), flat `cache.insert_git` write site (line 1169), `verify_hash` (line 110)
- `src/policy/mod.rs`: `PolicyDetail` (line 46), `aggregate_results` (line 77)
- `src/transitive/scanner.rs`: `insert_git` write site (line 228; the `details` vec is in scope at line 220)
- `tests/check_integration.rs`: T-009-05 `cache_hit_skips_registry_query` (line 269) pre-populates a cache row WITHOUT attribution columns; under this task that fixture must gain them or the test's `.expect(1)` breaks

Contract note: `docs/spec/interfaces.md` never promised `version: "cached"` (grep it: no match). The literal was always a violation of the documented `version` field. Removing it is a contract repair, not a break, but the migration note for consumers matching the string is still required (REQ-112-07).

---

## Cache schema migration: additive and idempotent (unit tests in `src/cache.rs`)

### T-112-01: Migration adds `dep_scan_version` column when absent
- Open a fresh in-memory cache (`Cache::in_memory()`).
- `PRAGMA table_info(scanned_packages)` shows a `dep_scan_version` TEXT column.

### T-112-02: Migration adds `policies_json` column when absent
- Same setup; `PRAGMA table_info(scanned_packages)` shows a `policies_json` TEXT column.

### T-112-03: Migration is idempotent
- Open a cache against a temp DB file, drop it, open again.
- No `duplicate column` error; each new column appears exactly once in `PRAGMA table_info`.

### T-112-04: Legacy rows read None for both new fields
- Insert a row via raw SQL naming only the pre-112 columns (mirror the T-106-03 pattern).
- `lookup` returns a `CacheEntry` with `dep_scan_version == None` and `policies_json == None`.

### T-112-05: `insert` stamps the running binary's version
- Call the new `insert(...)` (any policies_json value).
- `lookup` returns `dep_scan_version == Some(env!("CARGO_PKG_VERSION").to_string())`. Assert equality against the env macro, NOT a hardcoded literal, so the test survives version bumps.

### T-112-06: `insert` round-trips `policies_json` byte-equal
- Serialize `vec![PolicyDetail { policy_name: "age".into(), result: "pass".into(), reason: None }, PolicyDetail { policy_name: "typosquatting".into(), result: "warn".into(), reason: Some("close to 'express'".into()) }]` with `serde_json::to_string`.
- `insert(..., Some(&json))`, then `lookup`: `policies_json == Some(json)` (exact string equality) AND `serde_json::from_str::<Vec<PolicyDetail>>` on the read-back value reproduces the original vec (`PolicyDetail` derives `PartialEq`; it needs a `Deserialize` derive added).

### T-112-07: `insert` with `None` policies_json writes NULL
- `insert(..., None)`; `lookup` returns `policies_json == None`.

### T-112-08: `insert_git` writes both attribution fields
- `insert_git(name, sha, "block", Some(hash), None, Some(&json))` (final param order per task file).
- `lookup(name, sha, "git")` returns `dep_scan_version == Some(env!("CARGO_PKG_VERSION"))` and the exact `policies_json`.

---

## Attribution gate on the cache-hit path (integration, `tests/cache_attribution_integration.rs`, assert_cmd + wiremock, style of `tests/check_integration.rs`)

All tests below run the REAL binary (`assert_cmd::Command::cargo_bin("dep-scan")`) against a wiremock npm endpoint and a temp cache DB, with `--format json`. Pre-populated rows are written via raw `rusqlite` with the FULL current schema (all columns through `policies_json`).

### T-112-09: Fully attributed row + matching content hash → hit with exact attributed JSON
- Pre-populate row: `('cached-pkg', '1.0.0', 'npm', 'block', '2026-07-10T08:15:00Z', 'sha512:000102', NULL, NULL, NULL, '1.2.0', <policies_json>)` where `<policies_json>` is a two-element array with `install_scripts` = block, reason `"Install script contains suspicious command: curl"`, and `age` = pass. Note `dep_scan_version` is deliberately `'1.2.0'`, NOT the current version.
- Wiremock serves matching integrity (`sha512-AAEC`) and `published_at` 72h ago.
- Run `check cached-pkg --registry npm --format json`. Parse stdout. Assert the package object is exactly:

```json
{
  "package": "cached-pkg",
  "version": "1.0.0",
  "registry": "npm",
  "age_hours": 72,
  "result": "block",
  "reason": "Install script contains suspicious command: curl",
  "policies": [
    { "policy_name": "age", "result": "pass", "reason": null },
    { "policy_name": "install_scripts", "result": "block", "reason": "Install script contains suspicious command: curl" }
  ],
  "cache": {
    "hit": true,
    "scanned_at": "2026-07-10T08:15:00Z",
    "dep_scan_version": "1.2.0"
  }
}
```

- Field-by-field assertions, not `contains`: `version` is the resolved version (the string `"cached"` must NOT appear anywhere in stdout), `policies` array equals the stored array element-for-element, `reason` equals the recomputed aggregate reason, `cache.dep_scan_version == "1.2.0"` (proves the value comes from the ROW, not from `env!` at read time; mutation guard against re-stamping), `cache.scanned_at` equals the stored timestamp verbatim. `age_hours` may be asserted as 72 with the fixture's fixed published_at offset (compute the mock timestamp as now minus 72h, same technique as `npm_json` in `tests/check_integration.rs`).
- Wiremock `.expect(1)`: exactly one metadata fetch (the hash-verification fetch), zero policy-pipeline fetches (no install-scripts endpoint call).

### T-112-10: NULL `dep_scan_version` → miss, full re-scan, row upgraded in place
- Pre-populate a row with matching content hash but `dep_scan_version = NULL`, `policies_json = <valid json>`.
- Run 1: full pipeline runs (assert via wiremock call count > 1 or via the output carrying a fresh non-cache shape: no `cache` key).
- Run 2 against the same DB: now an attributed hit (`cache.hit == true`, `cache.dep_scan_version == env!("CARGO_PKG_VERSION")`). Proves the miss upgraded the row via `INSERT OR REPLACE`.

### T-112-11: NULL `policies_json` alone → miss
- Row with matching hash, `dep_scan_version = '1.3.1'`, `policies_json = NULL`.
- Output object has no `cache` key (fresh scan ran). Both fields are required for a hit.

### T-112-12: Unparseable `policies_json` → miss, no panic
- Row with `policies_json = 'not-json{'` and matching hash.
- Exit code reflects the FRESH verdict; process does not panic; output has no `cache` key. Fail-closed on corrupt attribution.

### T-112-13: Stored result inconsistent with stored policies → miss (tamper guard)
- Row with `result = 'pass'` but `policies_json` containing a `block` entry (so `aggregate_results` yields `"block"` != stored `"pass"`), matching content hash.
- The row is NOT honored: fresh scan runs (no `cache` key in output). A tampered cached `pass` is never served. This is the negative assertion that must fail if the executor skips the consistency check: mutation-test it by mentally deleting the `aggregate == stored` comparison, T-112-13 then fails.

### T-112-14: Fresh scan output omits the `cache` key entirely
- Empty cache DB, normal scan.
- Parse stdout: the package object's key set does NOT contain `"cache"` (assert on `serde_json::Value::as_object().unwrap().contains_key("cache") == false`). The fresh JSON shape is byte-compatible with pre-112 output (additive-only contract, interfaces.md stability table).

### T-112-15: Round-trip equality between fresh run and cached run
- Empty cache. Run 1 (`--format json`): capture `policies` array P, `result` R, `reason` S, `version` V.
- Run 2, same args, same DB: cached hit. Assert `policies == P`, `result == R`, `reason == S`, `version == V`, and `cache.hit == true`. The only difference between the two package objects is the presence of the `cache` object.

### T-112-16: Exit-code contract unchanged
- Cached `block` hit → exit 1. Cached `pass` hit → exit 0. (Same DB priming as T-112-09 with `result` varied; interfaces.md exit-code table is untouched.)

### T-112-17: Native table shows the real version on a cached hit
- Same priming as T-112-09, run WITHOUT `--format json` (native).
- The `Version` column cell for the package is `1.0.0`; the string `cached` does not appear in the table row. Per-policy indented lines render from the stored policies array in the stable `  <name>: <verdict>[ — <reason>]` format.

### T-112-18: Git pinned-SHA cached hit carries attribution
- Follow the local-git fixture pattern of `tests/git_dep_scan_integration.rs`: scan a lockfile git dep pinned to a full SHA twice against the same cache DB.
- Run 2's package object has `cache.hit == true`, `cache.dep_scan_version == env!("CARGO_PKG_VERSION")`, and a non-empty `policies` array equal to run 1's (which includes the `mutable_ref` detail). No `version: "cached"` regression on this path either (this path already used the real ref; assert it still does).

---

## Existing-test migration

### T-112-19: T-009-05 fixture upgraded, hit semantics preserved
- `tests/check_integration.rs::cache_hit_skips_registry_query` pre-populates a minimal pre-029 schema. Update the fixture to write the full current schema INCLUDING `dep_scan_version` and a valid `policies_json` consistent with `result = 'pass'`.
- The test's original assertions still hold (exit 0, exactly one metadata call). Without the fixture upgrade the row would now be an attribution miss and `.expect(1)` would fail; that failure mode is the evidence the gate is live.

---

## Spec-file assertions (same commit)

### T-112-20: Spec updated with the new contract
- `docs/spec/interfaces.md`: the JSON output schema section documents the top-level shape as it actually is (a bare pretty-printed array of package objects with keys `package`, `version`, `registry`, `age_hours`, `result`, `reason`, `policies`, optional `vulns`; the current block at lines 106-129 showing a `{"scanned_at": ..., "packages": [...]}` wrapper is drifted from code, see T-083-13 in `src/main.rs` and the `render_results` Json arm at `src/main.rs:632`, and is rewritten in place, never appended to). It documents the optional additive `cache` object (`hit`, `scanned_at`, `dep_scan_version`), states it appears only on cache hits, and carries a migration note: releases before this change emitted `version: "cached"` with an empty `policies` array on cache hits; that shape was never part of the documented contract; consumers matching the literal `"cached"` must switch to `cache.hit`.
- `docs/spec/data-model.md`: migration history gains the task-112 entry (two columns, NULL for legacy rows, no backfill); the cache decision matrix section states the attribution gate (NULL/unparseable/inconsistent attribution → re-scan, fail-closed).
- `docs/spec/behaviors.md`: new B-112 section (cached verdict attribution) cross-referenced from B-020.
- `docs/spec/fitness-functions.md`: new F-028 row (block severity): a cached verdict MUST NOT be served without full attribution (real version, per-policy array, producing dep-scan version); mapped to T-112-09..13 in `tests/cache_attribution_integration.rs`.
- Grep-level checks: `grep -n '"cached"' docs/spec/interfaces.md` matches only inside the migration note; `grep -rn 'version: "cached"' src/` returns nothing.

---

## Tooling gate

### T-112-21: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.
- All pre-existing cache tests (tasks 029, 030, 038, 040, 047, 097, 106) still pass; the migration is additive.

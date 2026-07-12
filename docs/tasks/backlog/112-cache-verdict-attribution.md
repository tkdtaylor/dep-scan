# Task 112 — cache-verdict-attribution

**Status:** backlog
**Depends on:** none in this repo (builds on tasks 007/029/030/038/097/106 cache machinery, all completed)
**Consumers:** code-scanner and its CI gate; code-scanner-side tasks that GATE on attributed cached verdicts are being planned in parallel and consume this task's output contract
**ADR:** write one if the executor deviates from the design below; otherwise the spec updates carry the decision
**Scope:** medium
**Touches:** `src/cache.rs` (two additive migrations, `CacheEntry`, `lookup`, `insert`, `insert_git`), `src/main.rs` (`CheckResult`, new `CacheProvenance` struct, registry cache-hit path, git cache-hit path, both cache write sites), `src/policy/mod.rs` (`Deserialize` derive on `PolicyDetail`), `src/transitive/scanner.rs` (write site), `tests/cache_attribution_integration.rs` (new), `tests/check_integration.rs` (T-009-05 fixture), `docs/spec/interfaces.md`, `docs/spec/data-model.md`, `docs/spec/behaviors.md`, `docs/spec/fitness-functions.md`

## Objective

Cached scan results must carry the SAME full attribution as fresh results: the real resolved package version, the full per-policy `policies` array, and a new additive `cache` object recording provenance (`hit`, `scanned_at`, and the dep-scan version that produced the verdict). The literal `version: "cached"` and the empty `policies` array go away. Cache entries that predate attribution are treated as misses, fail-closed, and upgraded in place on re-scan.

## Context / Background

Sibling repo code-scanner refuses to GATE on dep-scan verdicts served from a cache hit: today a warm-cache hit emits a bare `block`/`warn` with `version: "cached"`, `reason: "cached result"`, and an EMPTY `policies` array (`src/main.rs:1280-1289`). code-scanner calls that "unattributable and not reproducible", so dep-scan's supply-chain tier silently drops out of code-scanner's CI gate on any warm cache. The fix is producer-side: never emit an unattributed verdict.

Contract check (done while writing this task): `docs/spec/interfaces.md` never promised `version: "cached"`; grep finds no match. The literal was always a violation of the documented `version` field, so removing it repairs the stable contract rather than breaking it. Anyone matching the string `"cached"` still needs a migration note in interfaces.md (REQ-112-07). Separately, the JSON schema block in interfaces.md (lines 106-129) is drifted from code: it shows a `{"scanned_at": ..., "packages": [...]}` wrapper, but the binary emits a bare pretty-printed array of package objects (`render_results` Json arm, `src/main.rs:632`; asserted by T-083-13). Per the repo convention "spec and code that disagree means one of them is wrong; fix it in the same change", this task rewrites that block in place.

## Exact changes

### 1. Cache schema (`src/cache.rs`)

Two additive nullable columns on `scanned_packages`, added in `Cache::new` with the identical idempotent pattern as tasks 029/032/097/106 (check `existing_columns`, `ALTER TABLE scanned_packages ADD COLUMN ... TEXT;`, no backfill):

- `dep_scan_version TEXT`: the `CARGO_PKG_VERSION` of the binary that wrote the row.
- `policies_json TEXT`: `serde_json::to_string` of the `Vec<PolicyDetail>` the verdict was aggregated from.

`CacheEntry` gains `pub dep_scan_version: Option<String>` and `pub policies_json: Option<String>`; `lookup`'s SELECT and row mapping read both.

`insert` (line 333) and `insert_git` (line 383) each gain a trailing `policies_json: Option<&str>` parameter and write `dep_scan_version` internally from `env!("CARGO_PKG_VERSION")` (same precedent as `src/sbom.rs:118` and `src/config.rs:728`); no version parameter, so it cannot be spoofed at a call site. The compiler surfaces every caller: pass `Some(&serde_json::to_string(&details)?)` where a `Vec<PolicyDetail>` is in scope, `None` otherwise. `None` rows are attribution-less and will never be served as top-level hits (fail-closed re-scan; acceptable for internal transitive writes).

Call sites to update (compiler-enforced; listed for orientation):
- `src/main.rs:1580` flat registry write: pass the serialized `policy_details`.
- `src/main.rs:1169` flat git write: pass the serialized details used for that aggregation.
- `src/transitive/scanner.rs:228` transitive git write: `details` is in scope at line 220; pass it serialized.
- Remaining `src/transitive/scan.rs` and unit-test callers: pass `None` unless a details vec is naturally available.

### 2. Output model (`src/main.rs`, `src/policy/mod.rs`)

New struct next to `CheckResult` (line 313):

```rust
#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct CacheProvenance {
    pub(crate) hit: bool,
    /// RFC 3339 timestamp copied verbatim from the cache row's scanned_at.
    pub(crate) scanned_at: String,
    /// The dep-scan version that produced (wrote) the cached verdict.
    pub(crate) dep_scan_version: String,
}
```

`CheckResult` gains:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub(crate) cache: Option<CacheProvenance>,
```

Every existing `CheckResult { ... }` construction site adds `cache: None` (compiler-enforced), so fresh output is byte-identical to pre-112 (the key is skipped when `None`). `PolicyDetail` (`src/policy/mod.rs:46`) additionally derives `Deserialize` so `policies_json` can be parsed back.

### 3. Attribution gate on the registry cache-hit path (`src/main.rs:1265-1316`)

Current hit arm (before):

```rust
if decision == HashVerifyDecision::HonorCache {
    ...
    results.push(CheckResult {
        package: pkg_name.clone(),
        version: "cached".to_string(),
        registry: reg_str.clone(),
        age_hours: None,
        result: cached_result,
        reason: Some("cached result".to_string()),
        policies: vec![],
        vulns: vec![],
    });
    continue;
}
```

After: a hit is honored only when ALL of the following hold, else fall through to the existing re-scan path exactly as a hash mismatch does today (do NOT invalidate; the re-scan's `INSERT OR REPLACE` upgrades the row):

1. `decision == HashVerifyDecision::HonorCache` (unchanged task-030 gate),
2. `entry.dep_scan_version` is `Some`,
3. `entry.policies_json` is `Some` and parses to `Vec<PolicyDetail>`,
4. `aggregate_results(&parsed).0 == entry.result` (tamper/corruption guard; `aggregate_results` is `src/policy/mod.rs:77`).

The honored hit pushes:

```rust
let (agg_result, agg_reason) = policy::aggregate_results(&parsed);
results.push(CheckResult {
    package: pkg_name.clone(),
    version: resolved_version.clone(),               // real version, from fresh_meta
    registry: reg_str.clone(),
    age_hours: fresh_meta.published_at.map(|t| (Utc::now() - t).num_hours()),
    result: agg_result,
    reason: agg_reason,
    policies: parsed,
    vulns: vec![],
    cache: Some(CacheProvenance {
        hit: true,
        scanned_at: entry.scanned_at.clone(),
        dep_scan_version: entry.dep_scan_version.clone().expect("gated above"),
    }),
});
```

`has_failure` logic is unchanged (`agg_result == "block" || == "warn"`). Under `--verbose`, extend the existing stderr line to `cache hit (verified) for {pkg_name}: scanned_at {ts} by dep-scan {ver}`. On an attribution miss, log (verbose) `cache entry for {pkg_name} lacks attribution (pre-112 row); re-scanning`.

### 4. Git cache-hit path (`src/main.rs:1031-1081`)

Apply the same attribution gate to `decide_git_cache_action`'s consumer: honor the hit only when the row carries parseable, result-consistent attribution; on honor, replace `policies: vec![mutable_ref_detail]` with the parsed stored array and attach the same `CacheProvenance`. On attribution miss, fall through to the existing fetch + full-pipeline path (which re-writes the row with attribution). The `version` field on this path already carries the real ref; keep it.

The transitive verdict-reuse gate in `src/transitive/scanner.rs` (returns a bare `Verdict`, not a `CheckResult`) is intentionally NOT gated on attribution; its two-gate rule from task 106 is unchanged.

### 5. Exact before/after JSON (registry cached hit, `--format json`)

Before (current output for a warm-cache block):

```json
{
  "package": "left-pad",
  "version": "cached",
  "registry": "npm",
  "age_hours": null,
  "result": "block",
  "reason": "cached result",
  "policies": []
}
```

After (same warm-cache block; row written by dep-scan 1.3.1 at the shown timestamp):

```json
{
  "package": "left-pad",
  "version": "1.3.0",
  "registry": "npm",
  "age_hours": 87600,
  "result": "block",
  "reason": "Install script contains suspicious command: curl",
  "policies": [
    { "policy_name": "age", "result": "pass", "reason": null },
    { "policy_name": "install_scripts", "result": "block", "reason": "Install script contains suspicious command: curl" },
    { "policy_name": "typosquatting", "result": "pass", "reason": null }
  ],
  "cache": {
    "hit": true,
    "scanned_at": "2026-07-10T08:15:00Z",
    "dep_scan_version": "1.3.1"
  }
}
```

Fresh results are unchanged byte-for-byte: no `cache` key (serde skips `None`). `vulns` remains omitted-when-empty as today. Native table output shows the real version in the `Version` column plus the standard per-policy indented lines rendered from the stored array; no new native lines or columns.

### 6. Spec updates (same commit, rewrite in place)

- `docs/spec/interfaces.md`: correct the JSON output schema block to the real bare-array shape (keys `package`, `version`, `registry`, `age_hours`, `result`, `reason`, `policies`, optional `vulns`); document the optional additive `cache` object and that it appears only on cache hits; add a migration note: earlier releases emitted `version: "cached"` + empty `policies` on cache hits, that shape was never part of the documented contract, and consumers matching the literal `"cached"` must switch to `cache.hit`. Add `cache` object presence to the stability table as "additive, optional; only on cache hits".
- `docs/spec/data-model.md`: append the task-112 entry to the migration history list (two columns, NULL for legacy rows, no backfill) and add the attribution gate to the cache decision-matrix section: NULL / unparseable / result-inconsistent attribution → re-scan, fail-closed.
- `docs/spec/behaviors.md`: new `### B-112: Cached verdict attribution` section (gate conditions, output shape, fail-closed rule), plus a one-line cross-reference from B-020.
- `docs/spec/fitness-functions.md`: new row `F-028` (block): a cached verdict MUST NOT be served without full attribution; tests T-112-09..13 in `tests/cache_attribution_integration.rs`.

## Step-by-step outline

1. Step 0: `scripts/start-task.sh 112 cache-verdict-attribution` (branch or worktree; `cd` in if WORKTREE).
2. Commit the test spec milestone if not already committed (`test: add spec for task 112 — cache-verdict-attribution`), adding the coverage-tracker.md row (🟡 pending).
3. `src/policy/mod.rs`: add `Deserialize` to `PolicyDetail`'s derives.
4. `src/cache.rs`: migrations, `CacheEntry` fields, `lookup` SELECT, `insert`/`insert_git` signatures + internal version stamp. Write unit tests T-112-01..08 alongside the existing cache test module.
5. Fix every `insert`/`insert_git` caller the compiler flags (see list above).
6. `src/main.rs`: `CacheProvenance`, `CheckResult.cache` field, `cache: None` at all existing construction sites, registry hit-path gate + attributed push, git hit-path gate, verbose lines.
7. New `tests/cache_attribution_integration.rs` implementing T-112-09..17 (copy the wiremock + assert_cmd scaffolding, `dep_scan()`, `write_config`, `npm_json_with_integrity` patterns from `tests/check_integration.rs`), and the git test T-112-18 following `tests/git_dep_scan_integration.rs`.
8. Upgrade the T-009-05 fixture in `tests/check_integration.rs` (T-112-19).
9. Update the four spec files (T-112-20).
10. Gate: `cargo test && cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --check`.
11. Move this file to `docs/tasks/completed/` (use `git mv`), update `coverage-tracker.md`, commit `feat: complete task 112 — cache-verdict-attribution`, push. Run spec-verifier before promoting the tracker row.

## Requirements

### REQ-112-01: Additive idempotent migrations
`dep_scan_version TEXT` and `policies_json TEXT` added only when absent; re-open does not error; legacy rows read NULL, no backfill. Mirrors 029/032/097/106 exactly.

### REQ-112-02: Writes are always attributed
`insert` and `insert_git` stamp `dep_scan_version` internally from `env!("CARGO_PKG_VERSION")` and accept `policies_json: Option<&str>`. The two flat write sites and the transitive git write site pass the serialized details vec used for aggregation.

### REQ-112-03: Attribution gate, fail-closed
A top-level cache hit (registry and flat-git paths) requires the task-030 content-hash gate AND `dep_scan_version` present AND `policies_json` parsing to `Vec<PolicyDetail>` AND `aggregate_results(policies).0 == stored result`. Any failure → miss → re-scan (no invalidate; the re-scan upgrades the row). A stale or tampered verdict is never served.

### REQ-112-04: Attributed output shape
An honored hit emits the real resolved version, recomputed `age_hours`, the stored policies array, the recomputed aggregate reason, and `cache: { hit: true, scanned_at: <row>, dep_scan_version: <row> }`. The strings `"cached"` (as a version) and `"cached result"` (as a reason) no longer appear anywhere in output.

### REQ-112-05: Additive-only contract
Fresh results omit the `cache` key entirely; their serialized bytes are unchanged from pre-112. Exit-code semantics (0/1/2 table in interfaces.md) are untouched.

### REQ-112-06: Transitive gate untouched
The task-106 two-gate rule for transitive verdict reuse is unchanged; no attribution requirement there.

### REQ-112-07: Spec in the same commit
interfaces.md (schema block corrected + `cache` object + migration note), data-model.md (migration entry + gate), behaviors.md (B-112), fitness-functions.md (F-028), all rewritten in place.

## Acceptance criteria

- [ ] Migration adds both columns when absent (T-112-01, T-112-02)
- [ ] Migration idempotent (T-112-03)
- [ ] Legacy rows read NULL for both (T-112-04)
- [ ] insert stamps `env!("CARGO_PKG_VERSION")` (T-112-05)
- [ ] policies_json round-trips byte-equal and re-parses (T-112-06)
- [ ] insert with None writes NULL (T-112-07)
- [ ] insert_git writes both fields (T-112-08)
- [ ] Attributed hit emits the exact after-JSON shape, provenance from the ROW not env! (T-112-09)
- [ ] NULL dep_scan_version → miss → row upgraded → second run hits (T-112-10)
- [ ] NULL policies_json → miss (T-112-11)
- [ ] Unparseable policies_json → miss, no panic (T-112-12)
- [ ] result/policies inconsistency → miss, tampered pass never served (T-112-13)
- [ ] Fresh output has no `cache` key (T-112-14)
- [ ] Fresh-vs-cached round-trip equality on policies/result/reason/version (T-112-15)
- [ ] Exit codes unchanged for cached block/pass (T-112-16)
- [ ] Native table shows real version, no "cached" (T-112-17)
- [ ] Git pinned-SHA hit attributed (T-112-18)
- [ ] T-009-05 fixture upgraded, still one metadata call (T-112-19)
- [ ] Four spec files updated in the same commit (T-112-20)
- [ ] `cargo test` exits 0, clippy clean (`-D warnings`), fmt clean (T-112-21)

## Verification plan

- `cargo test --test cache_attribution_integration` runs the REAL binary via assert_cmd against wiremock and a temp cache DB, so a green run is live-path evidence (validation-harness level), not just unit evidence.
- `cargo test` (full suite) for non-regression, then `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --check`.
- Manual runtime observation for the record: prime a cache by scanning any real package twice with `--format json` and quote the second run's `cache` object, e.g. `cargo run -- check left-pad --registry npm --format json` twice against a scratch `--config` pointing at a temp cache path.
- Producer→consumer trace: confirm the write site (`src/main.rs:1580`) serializes the SAME `policy_details` vec that `aggregate_results` consumed, and the read site parses it back on the live hit path; T-112-10's two-run upgrade test is the end-to-end proof.

## Test spec

`docs/tasks/test-specs/112-cache-verdict-attribution-test-spec.md`

## Out of scope

- Persisting or replaying `vulns` from cache (cached hits keep `vulns: []`; OSV/interchange formats already re-query freshness on their own paths, task 088).
- Any change to the transitive verdict-reuse gate or the transitive JSON shape (B-108).
- Cache TTL / expiry semantics.
- The version-pin channel (task 113) and any code-scanner-side changes (their GATE tasks consume this contract and are planned in that repo).
- CHANGELOG entry (release-time, per RELEASE_CHECKLIST.md).

## Dependencies

None inside dep-scan. code-scanner's "re-enable GATE on cached dep-scan verdicts" work consumes this task's output contract and is being planned in parallel in that repo; land this first.

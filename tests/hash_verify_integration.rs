/// Integration tests for task 030 — content hash verification on cache hit.
///
/// These tests use assert_cmd + wiremock to run the full binary against a
/// controlled HTTP mock server and a real (file-backed) SQLite cache, so every
/// layer of the stack is exercised.
///
/// T-038-12: Task 030 hash-verify behavior is preserved with the new resolved-version
/// cache key (task 038).  All tests in this file use the concrete version string
/// (e.g. "1.0.0") as the cache key — they will fail if the binary reverts to "latest".
use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
use rusqlite::Connection;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ──────────────────────────────────────────────────────────────────

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

/// Write a minimal config with only min_age enabled (to allow age-based blocks
/// in T-030-08/T-030-12) and other heavy checks disabled for speed.
fn write_config(npm_url: &str, cache_path: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 48
cache_path = "{cache_path}"

[registries]
npm_url = "{npm_url}"

[policies]
check_min_age = true
check_install_scripts = false
check_maintainer_changes = false
check_typosquatting = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write temp config");
    f
}

/// Pre-populate the SQLite cache with a single row.
///
/// This bypasses the dep-scan binary so we can test specific DB states
/// (e.g. mismatched hash, NULL hash, stale result).
fn seed_cache(
    db_path: &str,
    name: &str,
    version: &str,
    registry: &str,
    result: &str,
    content_hash: Option<&str>,
) {
    let conn = Connection::open(db_path).expect("open seed db");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scanned_packages (
            name         TEXT NOT NULL,
            version      TEXT NOT NULL,
            registry     TEXT NOT NULL,
            result       TEXT NOT NULL,
            scanned_at   TEXT NOT NULL,
            content_hash TEXT,
            PRIMARY KEY (name, version, registry)
        );",
    )
    .expect("create table");
    conn.execute(
        "INSERT OR REPLACE INTO scanned_packages
         (name, version, registry, result, scanned_at, content_hash)
         VALUES (?1, ?2, ?3, ?4, datetime('now'), ?5)",
        rusqlite::params![name, version, registry, result, content_hash],
    )
    .expect("seed cache row");
}

/// Read the content_hash stored in the cache for a package.
fn read_cached_hash(db_path: &str, name: &str, version: &str, registry: &str) -> Option<String> {
    let conn = Connection::open(db_path).expect("open db for read");
    conn.query_row(
        "SELECT content_hash FROM scanned_packages
         WHERE name = ?1 AND version = ?2 AND registry = ?3",
        rusqlite::params![name, version, registry],
        |row| row.get::<_, Option<String>>(0),
    )
    .ok()
    .flatten()
}

/// Read the result stored in the cache for a package. Returns None if no row.
fn read_cached_result(db_path: &str, name: &str, version: &str, registry: &str) -> Option<String> {
    let conn = Connection::open(db_path).expect("open db for read");
    conn.query_row(
        "SELECT result FROM scanned_packages
         WHERE name = ?1 AND version = ?2 AND registry = ?3",
        rusqlite::params![name, version, registry],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

/// npm JSON with `dist.integrity` in SRI format.
///
/// `integrity` is the SRI string, e.g. `"sha512-AAEC"`.
/// `hours_ago` controls the published_at timestamp for age-policy tests.
fn npm_json_with_integrity(name: &str, version: &str, hours_ago: i64, integrity: &str) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(hours_ago);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "name": "{name}",
    "description": "A test package",
    "dist-tags": {{ "latest": "{version}" }},
    "versions": {{
        "{version}": {{
            "name": "{name}",
            "version": "{version}",
            "description": "A test package",
            "dist": {{
                "integrity": "{integrity}"
            }}
        }}
    }},
    "time": {{
        "{version}": "{ts}"
    }},
    "maintainers": [
        {{ "name": "testuser", "email": "test@example.com" }}
    ]
}}"#
    )
}

/// npm JSON with NO dist.integrity and NO dist.shasum (registry hash = None).
fn npm_json_no_integrity(name: &str, version: &str, hours_ago: i64) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(hours_ago);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "name": "{name}",
    "description": "A test package",
    "dist-tags": {{ "latest": "{version}" }},
    "versions": {{
        "{version}": {{
            "name": "{name}",
            "version": "{version}",
            "description": "A test package"
        }}
    }},
    "time": {{
        "{version}": "{ts}"
    }},
    "maintainers": [
        {{ "name": "testuser", "email": "test@example.com" }}
    ]
}}"#
    )
}

// ── SRI hash constants ────────────────────────────────────────────────────────
// "sha512-AAEC" → bytes [0x00,0x01,0x02] → dep-scan normalized: "sha512:000102"
const SRI_A: &str = "sha512-AAEC";
const HASH_A: &str = "sha512:000102";

// "sha512-AQ==" → bytes [0x01] → dep-scan normalized: "sha512:01"
const SRI_B: &str = "sha512-AQ==";
const HASH_B: &str = "sha512:01";

// ── T-030-06 ──────────────────────────────────────────────────────────────────

// T-030-06: Cache hit with matching hash skips re-scan
//
// Pre-populate cache with (pkg, "1.0.0", npm, "pass", content_hash=HASH_A).
// (Task 038: cache key uses the resolved version, not the literal "latest".)
// wiremock returns dist.integrity = SRI_A (parses to HASH_A — matches).
// Run: dep-scan check pkg --registry npm --verbose
// Expected: exit 0, output contains "cache hit (verified)", wiremock observes
// exactly ONE metadata call, policy logic does not execute.
#[tokio::test]
async fn cache_hit_with_matching_hash_skips_rescan() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    seed_cache(
        db_str,
        "verify-hit-pkg",
        "1.0.0", // resolved version from registry, not "latest" (task 038)
        "npm",
        "pass",
        Some(HASH_A),
    );

    let config = write_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/verify-hit-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "verify-hit-pkg",
                "1.0.0",
                72,
                SRI_A,
            )),
        )
        .expect(1) // exactly one metadata call — the verification fetch
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "verify-hit-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains("cache hit (verified)"));

    // wiremock will assert expect(1) on drop if the count is wrong
}

// ── T-030-07 ──────────────────────────────────────────────────────────────────

// T-030-07: Cache hit with mismatched hash invalidates and re-scans
//
// Pre-populate cache with content_hash=HASH_A, result="pass".
// wiremock returns dist.integrity = SRI_B (parses to HASH_B — mismatch).
// Run: dep-scan check pkg --registry npm
// Expected: exit 0, stderr contains "cache hash mismatch for ...; re-scanning",
// the resulting cache row's content_hash is now HASH_B.
#[tokio::test]
async fn cache_hit_with_mismatched_hash_invalidates_and_rescans() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    seed_cache(
        db_str,
        "verify-mismatch-pkg",
        "1.0.0", // resolved version from registry, not "latest" (task 038)
        "npm",
        "pass",
        Some(HASH_A),
    );

    let config = write_config(&server.uri(), db_str);

    // Return HASH_B — mismatches the cached HASH_A.
    Mock::given(method("GET"))
        .and(path("/verify-mismatch-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "verify-mismatch-pkg",
                "1.0.0",
                72, // 72h old → passes age policy → result "pass"
                SRI_B,
            )),
        )
        .expect(1) // exactly one fetch; metadata is reused for re-scan
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "verify-mismatch-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains(
            "cache hash mismatch for verify-mismatch-pkg; re-scanning",
        ));

    // After re-scan the cache row should carry the new hash (HASH_B).
    let stored = read_cached_hash(db_str, "verify-mismatch-pkg", "1.0.0", "npm");
    assert_eq!(
        stored,
        Some(HASH_B.to_string()),
        "cache row should be updated with the new hash after re-scan"
    );
}

// ── T-030-08 ──────────────────────────────────────────────────────────────────

// T-030-08: Cache hit with mismatched hash where re-scan blocks
//
// Pre-populate cache with result="pass", content_hash=HASH_A.
// wiremock returns HASH_B plus a fresh published_at that fails min-age policy.
// Run: dep-scan check pkg --registry npm
// Expected: exit 1, cached "pass" was NOT honored.
#[tokio::test]
async fn cache_hit_mismatch_rescan_blocks() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    seed_cache(
        db_str,
        "verify-block-pkg",
        "1.0.0", // resolved version from registry, not "latest" (task 038)
        "npm",
        "pass", // stale cached pass
        Some(HASH_A),
    );

    let config = write_config(&server.uri(), db_str);

    // Return HASH_B and published 1h ago → fails 48h min-age policy.
    Mock::given(method("GET"))
        .and(path("/verify-block-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "verify-block-pkg",
                "1.0.0",
                1, // 1h old → fails age policy
                SRI_B,
            )),
        )
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "verify-block-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1) // re-scan produces a block — stale "pass" was not honored
        .stderr(predicate::str::contains(
            "cache hash mismatch for verify-block-pkg; re-scanning",
        ));
}

// ── T-030-09 ──────────────────────────────────────────────────────────────────

// T-030-09: Legacy cache row (NULL hash) triggers re-scan
//
// Insert a row with content_hash = NULL (simulating a pre-029 DB).
// wiremock returns clean metadata with dist.integrity = SRI_B.
// Run: dep-scan check pkg --registry npm --verbose
// Expected: exit 0, verbose output shows "cache hash mismatch — re-scanning",
// post-run the row has content_hash = HASH_B.
//
// (Task 038: the row is keyed by the resolved version "1.0.0", not "latest".)
#[tokio::test]
async fn legacy_cache_row_null_hash_triggers_rescan() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    // Seed with NULL content_hash (pre-029 row, keyed by the resolved version).
    seed_cache(db_str, "verify-legacy-pkg", "1.0.0", "npm", "pass", None);

    let config = write_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/verify-legacy-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "verify-legacy-pkg",
                "1.0.0",
                72, // passes age policy
                SRI_B,
            )),
        )
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "verify-legacy-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains(
            "cache hash mismatch for verify-legacy-pkg; re-scanning",
        ));

    // The re-scan should have stored the new hash.
    let stored = read_cached_hash(db_str, "verify-legacy-pkg", "1.0.0", "npm");
    assert_eq!(
        stored,
        Some(HASH_B.to_string()),
        "legacy row should be upgraded with the fresh hash after re-scan"
    );
}

// ── T-030-10 ──────────────────────────────────────────────────────────────────

// T-030-10: Both hashes None → re-scan (fail-closed)
//
// Pre-populate cache with content_hash = NULL, result = "pass".
// wiremock returns metadata with NO dist.integrity (registry hash = None).
// Run: dep-scan check pkg --registry npm --verbose
// Expected: exit 0, verbose output shows "cache hash mismatch — re-scanning",
// full policy pipeline executes, cache row is refreshed.
#[tokio::test]
async fn both_hashes_none_fail_closed_rescans() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    seed_cache(
        db_str,
        "verify-both-none-pkg",
        "1.0.0", // resolved version from registry, not "latest" (task 038)
        "npm",
        "pass",
        None, // cached hash = NULL
    );

    let config = write_config(&server.uri(), db_str);

    // Registry returns no digest either.
    Mock::given(method("GET"))
        .and(path("/verify-both-none-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_no_integrity(
                "verify-both-none-pkg",
                "1.0.0",
                72,
            )),
        )
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "verify-both-none-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains(
            "cache hash mismatch for verify-both-none-pkg; re-scanning",
        ));

    // Cache row is refreshed (scanned_at updated) — result should still be "pass"
    // (package is 72h old, passes age policy). content_hash remains None.
    let stored_result = read_cached_result(db_str, "verify-both-none-pkg", "1.0.0", "npm");
    assert_eq!(
        stored_result,
        Some("pass".to_string()),
        "re-scan should re-populate the cache with a fresh result"
    );
}

// ── T-030-11 ──────────────────────────────────────────────────────────────────

// T-030-11: Registry fetch failure during verification falls through to scan path
//
// Pre-populate cache with a hash.
// wiremock returns 500 on the metadata endpoint.
// Run: dep-scan check pkg --registry npm
// Expected: behaves identically to a cache-miss against a 500 — error surfaced.
#[tokio::test]
async fn registry_fetch_failure_falls_through_to_error() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    seed_cache(
        db_str,
        "verify-error-pkg",
        "1.0.0", // resolved version from registry, not "latest" (task 038)
        "npm",
        "pass",
        Some(HASH_A),
    );

    let config = write_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/verify-error-pkg"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    // A 500 from the registry is a NetworkError, which produces exit code 2.
    // This is the same behavior as a cache-miss with a 500.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "verify-error-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(2);
}

// ── T-030-12 ──────────────────────────────────────────────────────────────────

// T-030-12: `install --force` does not bypass verification
//
// Pre-populate cache with result="pass", content_hash=HASH_A.
// wiremock returns HASH_B plus fresh published_at that fails min-age.
// Run: dep-scan install pkg --registry npm --force
// Expected: stderr shows the re-scan was triggered; the post-scan verdict (block
// for min-age) is then bypassed by --force; the install is attempted.
// Critically, the install does NOT proceed using only the stale cached "pass".
#[tokio::test]
async fn install_force_does_not_bypass_verification() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    seed_cache(
        db_str,
        "verify-force-pkg",
        "1.0.0", // resolved version from registry, not "latest" (task 038)
        "npm",
        "pass", // stale cached pass
        Some(HASH_A),
    );

    let config = write_config(&server.uri(), db_str);

    // HASH_B mismatch + 1h old → would block on age policy after re-scan
    Mock::given(method("GET"))
        .and(path("/verify-force-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "verify-force-pkg",
                "1.0.0",
                1, // 1h old → fails age policy
                SRI_B,
            )),
        )
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "verify-force-pkg",
            "--registry",
            "npm",
            "--force",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verification triggered the re-scan (not silently honored).
    assert!(
        stderr.contains("cache hash mismatch for verify-force-pkg; re-scanning"),
        "stderr should show re-scan was triggered, got: {stderr}"
    );

    // --force bypassed the block verdict → install was attempted.
    assert!(
        stdout.contains("Installing via npm"),
        "install should be attempted with --force despite block, got stdout: {stdout}\nstderr: {stderr}"
    );
}

// ── T-030-13 ──────────────────────────────────────────────────────────────────

// T-030-13: Verify-loop closes — second run is a clean cache hit
//
// After T-030-07 scenario (mismatch → re-scan), the cache carries HASH_B.
// A second run with the same wiremock (still returning HASH_B) should produce
// a clean cache hit.
#[tokio::test]
async fn verify_loop_closes_second_run_is_clean_hit() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    // Seed with HASH_A (stale, keyed by resolved version per task 038).
    seed_cache(
        db_str,
        "verify-loop-pkg",
        "1.0.0", // resolved version from registry, not "latest" (task 038)
        "npm",
        "pass",
        Some(HASH_A),
    );

    let config = write_config(&server.uri(), db_str);

    // wiremock always returns HASH_B.
    Mock::given(method("GET"))
        .and(path("/verify-loop-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "verify-loop-pkg",
                "1.0.0",
                72,
                SRI_B,
            )),
        )
        .mount(&server)
        .await;

    // First run: HASH_A cached vs HASH_B from registry → mismatch → re-scan.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "verify-loop-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains(
            "cache hash mismatch for verify-loop-pkg; re-scanning",
        ));

    // Confirm cache now holds HASH_B (keyed by resolved version per task 038).
    let stored = read_cached_hash(db_str, "verify-loop-pkg", "1.0.0", "npm");
    assert_eq!(
        stored,
        Some(HASH_B.to_string()),
        "cache should hold HASH_B after first run"
    );

    // Second run: HASH_B cached vs HASH_B from registry → cache hit (verified).
    // wiremock already has the route mounted, so the second call is handled.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "verify-loop-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains("cache hit (verified)"));
}

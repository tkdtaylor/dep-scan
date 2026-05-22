/// Integration and unit tests for task 038 — use resolved version as cache key
/// instead of the literal string "latest".
///
/// Security finding H-2: a `pass` verdict cached under "latest" could apply to
/// a future different tarball at the same floating tag.  Keying by the concrete
/// version string returned by the registry (e.g. "1.2.3") closes this window.
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

/// Write a minimal config pointing at the given npm mock URL and cache path.
/// All heavy policies are disabled to keep tests fast and deterministic.
fn write_npm_config(npm_url: &str, cache_path: &str) -> NamedTempFile {
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

/// Write a config for crates.io tests.
fn write_crates_config(crates_url: &str, cache_path: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 48
cache_path = "{cache_path}"

[registries]
crates_url = "{crates_url}"

[policies]
check_min_age = true
check_install_scripts = false
check_maintainer_changes = false
check_typosquatting = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_go_sumdb = false

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

/// Count rows in scanned_packages that match the given key.
fn count_cache_rows(db_path: &str, name: &str, version: &str, registry: &str) -> usize {
    let conn = Connection::open(db_path).expect("open db");
    conn.query_row(
        "SELECT COUNT(*) FROM scanned_packages
         WHERE name = ?1 AND version = ?2 AND registry = ?3",
        rusqlite::params![name, version, registry],
        |row| row.get::<_, i64>(0),
    )
    .unwrap_or(0) as usize
}

/// Read the result column for a specific cache row.
fn read_cached_result(db_path: &str, name: &str, version: &str, registry: &str) -> Option<String> {
    let conn = Connection::open(db_path).expect("open db");
    conn.query_row(
        "SELECT result FROM scanned_packages
         WHERE name = ?1 AND version = ?2 AND registry = ?3",
        rusqlite::params![name, version, registry],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

/// npm JSON response with `dist.integrity` in SRI format, published `hours_ago` ago.
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

/// crates.io API response for a crate published `hours_ago` hours ago.
fn crates_json(name: &str, version: &str, hours_ago: i64) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(hours_ago);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "crate": {{
        "name": "{name}",
        "max_version": "{version}",
        "description": "A test crate",
        "downloads": 5000000,
        "repository": "https://github.com/test/{name}",
        "created_at": "{ts}"
    }},
    "versions": [
        {{
            "num": "{version}",
            "created_at": "{ts}",
            "published_by": {{
                "login": "testuser",
                "name": "Test User"
            }}
        }}
    ]
}}"#
    )
}

// SRI hash constants for npm tests.
// "sha512-AAEC" → bytes [0x00, 0x01, 0x02] → dep-scan normalized: "sha512:000102"
const SRI_A: &str = "sha512-AAEC";
const HASH_A: &str = "sha512:000102";

// "sha512-AQ==" → bytes [0x01] → dep-scan normalized: "sha512:01"
const SRI_B: &str = "sha512-AQ==";
const HASH_B: &str = "sha512:01";

// ── T-038-01 ─────────────────────────────────────────────────────────────────

// T-038-01: Cache insert uses resolved version, not "latest"
//
// wiremock returns metadata with version="1.2.3" for package "express".
// After run_check, exactly one row exists with (name="express", version="1.2.3",
// registry="npm"); no row exists with version="latest".
#[tokio::test]
async fn t038_01_cache_insert_uses_resolved_version() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let config = write_npm_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "express", "1.2.3", 72, // 72h old → passes age policy
                SRI_A,
            )),
        )
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "express",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0);

    // Row with resolved version must exist.
    let rows_at_resolved = count_cache_rows(db_str, "express", "1.2.3", "npm");
    assert_eq!(
        rows_at_resolved, 1,
        "T-038-01: expected exactly one cache row keyed by resolved version \"1.2.3\""
    );

    // Row with literal "latest" must NOT exist.
    let rows_at_latest = count_cache_rows(db_str, "express", "latest", "npm");
    assert_eq!(
        rows_at_latest, 0,
        "T-038-01: no cache row should be keyed by the literal string \"latest\""
    );
}

// ── T-038-02 ─────────────────────────────────────────────────────────────────

// T-038-02: Cache lookup uses resolved version, not "latest"
//
// Pre-populate cache with (name="express", version="1.2.3", registry="npm",
// result="pass", content_hash=HASH_A).
// wiremock returns metadata with version="1.2.3" and dist.integrity = SRI_A.
// Expected: "cache hit (verified)" appears in stderr — the lookup key is "1.2.3".
#[tokio::test]
async fn t038_02_cache_lookup_uses_resolved_version() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    // Pre-populate with the resolved version key.
    seed_cache(db_str, "express", "1.2.3", "npm", "pass", Some(HASH_A));

    let config = write_npm_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(npm_json_with_integrity("express", "1.2.3", 72, SRI_A)),
        )
        .expect(1) // exactly one fetch — for hash verification
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "express",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains("cache hit (verified)"));
}

// ── T-038-03 ─────────────────────────────────────────────────────────────────

// T-038-03: Old "latest" row in cache is NOT hit after this change (version isolation)
//
// Pre-populate cache with the old schema key: (name="express", version="latest", ...).
// wiremock returns metadata with version="1.2.3".
// Expected: cache miss (the "latest" row does not match the "1.2.3" lookup key);
// full scan runs; a new row (express, "1.2.3", npm, ...) is inserted.
#[tokio::test]
async fn t038_03_old_latest_row_not_hit() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    // Seed with the old "latest" key — simulates a pre-038 cache entry.
    seed_cache(db_str, "express", "latest", "npm", "pass", Some(HASH_A));

    let config = write_npm_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(npm_json_with_integrity("express", "1.2.3", 72, SRI_A)),
        )
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "express",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        // Cache miss — no "cache hit (verified)" should appear.
        .stderr(predicate::str::contains("cache hit (verified)").not());

    // A new row at the resolved version must have been inserted.
    let rows_at_resolved = count_cache_rows(db_str, "express", "1.2.3", "npm");
    assert_eq!(
        rows_at_resolved, 1,
        "T-038-03: a new row keyed by \"1.2.3\" should have been inserted on cache miss"
    );

    // The old "latest" row is still present (not touched) — it will expire naturally.
    let rows_at_latest = count_cache_rows(db_str, "express", "latest", "npm");
    assert_eq!(
        rows_at_latest, 1,
        "T-038-03: the old \"latest\" row should remain untouched"
    );
}

// ── T-038-04 ─────────────────────────────────────────────────────────────────

// T-038-04: Two different resolved versions of the same package coexist in cache
//
// Pre-populate (express, "1.2.3", npm, pass, HASH_A) and (express, "1.3.0", npm, pass, HASH_B).
// wiremock returns version "1.2.3" with HASH_A.
// Expected: the "1.2.3" row is hit; the "1.3.0" row is not touched.
#[tokio::test]
async fn t038_04_two_versions_coexist_independently() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    seed_cache(db_str, "express", "1.2.3", "npm", "pass", Some(HASH_A));
    seed_cache(db_str, "express", "1.3.0", "npm", "pass", Some(HASH_B));

    let config = write_npm_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "express", "1.2.3", 72, SRI_A, // matches HASH_A → cache hit
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "express",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains("cache hit (verified)"));

    // "1.3.0" row must still exist and be untouched.
    let rows_at_130 = count_cache_rows(db_str, "express", "1.3.0", "npm");
    assert_eq!(
        rows_at_130, 1,
        "T-038-04: the \"1.3.0\" row should remain untouched"
    );

    // "1.2.3" row is still present (the hit doesn't delete it).
    let rows_at_123 = count_cache_rows(db_str, "express", "1.2.3", "npm");
    assert_eq!(
        rows_at_123, 1,
        "T-038-04: the \"1.2.3\" row should still exist after a cache hit"
    );
}

// ── T-038-05 ─────────────────────────────────────────────────────────────────

// T-038-05: Registry returns a different resolved version — cache miss, re-scan
//
// Pre-populate (express, "1.2.3", npm, pass, HASH_A).
// wiremock now returns version="1.3.0" (new release) with HASH_B.
// Expected: cache miss (no "1.3.0" row yet); full scan runs; new row
// (express, "1.3.0", npm, ...) is inserted; the "1.2.3" row is left untouched.
#[tokio::test]
async fn t038_05_different_resolved_version_cache_miss_rescan() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    seed_cache(db_str, "express", "1.2.3", "npm", "pass", Some(HASH_A));

    let config = write_npm_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "express", "1.3.0", // new version — no cached entry at this key
                72, SRI_B,
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
            "express",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        // Cache miss — no "cache hit (verified)".
        .stderr(predicate::str::contains("cache hit (verified)").not());

    // New row for "1.3.0" must be inserted.
    let rows_at_130 = count_cache_rows(db_str, "express", "1.3.0", "npm");
    assert_eq!(
        rows_at_130, 1,
        "T-038-05: a new row keyed by \"1.3.0\" should be inserted after the scan"
    );

    // Old "1.2.3" row must remain untouched.
    let rows_at_123 = count_cache_rows(db_str, "express", "1.2.3", "npm");
    assert_eq!(
        rows_at_123, 1,
        "T-038-05: the \"1.2.3\" row should not be modified when resolving to \"1.3.0\""
    );
}

// ── T-038-06 ─────────────────────────────────────────────────────────────────

// T-038-06: "latest" is NOT used as a cache lookup key in any code path (static check)
//
// Grep src/ for the literal string "latest" as an argument to cache.lookup( or
// cache.insert(.  Any match is a regression — the resolved version must always
// be used instead.
#[test]
fn t038_06_no_latest_literal_in_cache_calls() {
    // We grep the main source file for the literal "latest" appearing as an
    // argument to cache methods.  This static assertion catches regressions
    // if someone re-introduces the hard-coded fallback.
    let src = std::fs::read_to_string("src/main.rs")
        .expect("could not read src/main.rs for static check");

    // Build a list of lines that mention "latest" AND a cache method call.
    let offending: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            (line.contains("cache.lookup(")
                || line.contains("cache.insert(")
                || line.contains("cache.invalidate("))
                && line.contains("\"latest\"")
        })
        .collect();

    assert!(
        offending.is_empty(),
        "T-038-06: the literal string \"latest\" must not appear as an argument to \
         cache.lookup / cache.insert / cache.invalidate in src/main.rs. \
         Offending lines: {offending:?}"
    );
}

// ── T-038-07 ─────────────────────────────────────────────────────────────────

// T-038-07: invalidate also targets the resolved version key
//
// Pre-populate (express, "1.2.3", npm, pass, HASH_A).
// wiremock returns dist.integrity = HASH_B (mismatch — triggers invalidation).
// Expected: the "1.2.3" row is invalidated and replaced with the new result;
// no phantom "latest" row exists.
#[tokio::test]
async fn t038_07_invalidate_targets_resolved_version() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    seed_cache(db_str, "express", "1.2.3", "npm", "pass", Some(HASH_A));

    let config = write_npm_config(&server.uri(), db_str);

    // HASH_B mismatch → triggers invalidation; package is 72h old → still passes.
    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "express", "1.2.3", 72, SRI_B, // HASH_B — mismatches cached HASH_A
            )),
        )
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "express",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains(
            "cache hash mismatch for express; re-scanning",
        ));

    // After re-scan, the row at "1.2.3" should carry the new hash.
    let result = read_cached_result(db_str, "express", "1.2.3", "npm");
    assert_eq!(
        result,
        Some("pass".to_string()),
        "T-038-07: re-scan result should be stored at the resolved version key \"1.2.3\""
    );

    // No phantom "latest" row should exist.
    let rows_at_latest = count_cache_rows(db_str, "express", "latest", "npm");
    assert_eq!(
        rows_at_latest, 0,
        "T-038-07: no phantom \"latest\" row should exist after invalidation"
    );
}

// ── T-038-08 ─────────────────────────────────────────────────────────────────

// T-038-08: Second scan within the same session uses the cache hit (resolved version)
//
// wiremock serves express at version="4.18.0", dist.integrity = SRI_A.
// First scan: populates cache with key "4.18.0".
// Second scan (same wiremock): cache hit — "cache hit (verified)" in stderr.
#[tokio::test]
async fn t038_08_second_scan_uses_cache_hit() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let config = write_npm_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "express", "4.18.0", 72, // passes age policy
                SRI_A,
            )),
        )
        .mount(&server)
        .await;

    // First scan: populates cache.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "express",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0);

    // Verify the row was inserted at the resolved version, not "latest".
    let rows_at_resolved = count_cache_rows(db_str, "express", "4.18.0", "npm");
    assert_eq!(
        rows_at_resolved, 1,
        "T-038-08: first scan should create a row at version \"4.18.0\""
    );

    // Second scan: must produce a cache hit.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "express",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains("cache hit (verified)"));
}

// ── T-038-09 ─────────────────────────────────────────────────────────────────

// T-038-09: Cross-version aliasing attack does not yield a stale cache hit
//
// Scenario: attacker republishes express at "4.18.0" with a different tarball.
// Pre-populate (express, "4.18.0", npm, pass, HASH_A).
// wiremock returns version="4.18.0" but dist.integrity=SRI_B (different tarball).
// Expected: hash mismatch detected (task 030 logic); cache invalidated; full re-scan.
// The stale "pass" verdict is NOT honored.
#[tokio::test]
async fn t038_09_cross_version_aliasing_triggers_hash_mismatch() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    // Pre-populate with "old" hash (HASH_A).
    seed_cache(db_str, "express", "4.18.0", "npm", "pass", Some(HASH_A));

    let config = write_npm_config(&server.uri(), db_str);

    // Attacker's version: same version string but different tarball (HASH_B).
    // Make it 1h old so the re-scan blocks on age policy — confirming the
    // stale "pass" was not honored.
    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "express", "4.18.0", 1, // 1h old → fails 48h age policy after re-scan
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
            "express",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1) // re-scan blocked — stale "pass" was NOT honored
        .stderr(predicate::str::contains(
            "cache hash mismatch for express; re-scanning",
        ));
}

// ── T-038-10 ─────────────────────────────────────────────────────────────────

// T-038-10: crates.io also uses resolved version as cache key
//
// wiremock serves serde at version="1.0.193" (crates.io).
// Expected: row exists with concrete version "1.0.193", not "latest".
#[tokio::test]
async fn t038_10_crates_io_uses_resolved_version_as_cache_key() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let config = write_crates_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/api/v1/crates/serde"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(crates_json("serde", "1.0.193", 72)),
        )
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "serde",
            "--registry",
            "crates",
        ])
        .assert()
        .code(0);

    // Row must be keyed by the concrete version, not "latest".
    let rows_at_resolved = count_cache_rows(db_str, "serde", "1.0.193", "crates");
    assert_eq!(
        rows_at_resolved, 1,
        "T-038-10: crates.io cache row should use the resolved version \"1.0.193\""
    );

    let rows_at_latest = count_cache_rows(db_str, "serde", "latest", "crates");
    assert_eq!(
        rows_at_latest, 0,
        "T-038-10: no cache row should be keyed by \"latest\" for crates.io"
    );
}

// ── T-038-11 ─────────────────────────────────────────────────────────────────

// T-038-11: Version fetch failure produces no cache entry (not a "latest" fallback)
//
// wiremock returns 500 for the metadata endpoint.
// Expected: scan fails with exit code 2; no cache row is inserted (there is
// no version to key on — REQ-038-06).
#[tokio::test]
async fn t038_11_fetch_failure_produces_no_cache_entry() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let config = write_npm_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "express",
            "--registry",
            "npm",
        ])
        .assert()
        .code(2); // registry error → exit 2

    // No cache row should exist — neither at "latest" nor at any version.
    let conn = Connection::open(db_str).expect("open db");
    // Database may not exist at all if the cache file was never created;
    // if it does, scanned_packages should be empty for this package.
    let row_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM scanned_packages WHERE name = 'express'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    assert_eq!(
        row_count, 0,
        "T-038-11: no cache row should be inserted when the registry fetch fails"
    );
}

// ── T-038-13 ─────────────────────────────────────────────────────────────────

// T-038-13: Maintainer history table unaffected (static check)
//
// The maintainer_history table uses (name, registry) as its key — no version
// column is involved.  Verify that cache.record_maintainers calls in src/main.rs
// do not introduce a version argument.
#[test]
fn t038_13_maintainer_history_table_unaffected() {
    let src = std::fs::read_to_string("src/main.rs")
        .expect("could not read src/main.rs for static check");

    // record_maintainers calls must NOT include a version argument.
    // The signature is record_maintainers(name, registry, maintainers).
    // If someone accidentally added &metadata.version here, it would break
    // the maintainer change detection (task 014).
    for (i, line) in src.lines().enumerate() {
        if line.contains("record_maintainers(") {
            // The call must match the three-argument form: (pkg_name, &reg_str, &metadata.maintainers)
            // It must NOT contain a fourth argument referencing a version.
            // We check that `&metadata.version` does not appear on the same line.
            assert!(
                !line.contains("&metadata.version"),
                "T-038-13: record_maintainers call at line {} should not include a version \
                 argument — the maintainer_history table is keyed by (name, registry) only. \
                 Line content: {line}",
                i + 1
            );
        }
    }
}

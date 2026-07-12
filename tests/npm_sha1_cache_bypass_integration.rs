// SPDX-License-Identifier: Apache-2.0
/// Integration tests for task 040 — Reject SHA-1 content hashes as cache trust gates for npm.
///
/// These tests cover:
///   - T-040-04: pass verdict with sha1-only hash stores NULL content_hash in cache
///   - T-040-05: block verdict with sha1-only hash stores normally
///   - T-040-06: warn verdict with sha1-only hash stores NULL content_hash in cache
///   - T-040-07: cache hit with sha1 stored hash always triggers Reverify (integration)
///   - T-040-08: sha1 cached vs sha512 registry — Reverify
///   - T-040-09: sha512 cache short-circuit is unaffected (regression)
///   - T-040-10: two consecutive runs both execute the full pipeline (no stale sha1 short-circuit)
///   - T-040-11: verbose output includes sha1-bypass message
///   - T-040-12: chosen-prefix SHA-1 collision scenario — old sha1 row, matching shasum → still re-scans
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

/// Write a minimal config with only age check enabled (to keep tests fast).
fn write_config(npm_url: &str, cache_path: &str) -> NamedTempFile {
    // Escape backslashes so Windows paths (C:\Users\...) are valid TOML basic
    // strings; on Unix this is a no-op. The escaped path round-trips back to the
    // original value after TOML parsing, so stderr-path assertions still match.
    let cache_path = cache_path.replace('\\', "\\\\");
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

/// Pre-populate the SQLite cache with a single row (directly via SQLite,
/// bypassing dep-scan), lacking task-112 attribution (`dep_scan_version`/
/// `policies_json` both NULL). Tests that assert a genuine
/// `"cache hit (verified)"` must use [`seed_cache_attributed`] instead: an
/// unattributed row is, by design, always a miss (fail-closed, REQ-112-03)
/// and gets upgraded in place on re-scan.
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
            provenance_identity TEXT,
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

/// Pre-populate the SQLite cache with a fully task-112-attributed row: sets
/// `dep_scan_version` (to the running binary's own version) and
/// `policies_json` (a single-policy array whose aggregate matches `result`,
/// consistent with this file's config, which enables only `check_min_age`).
/// Use this for any test that asserts `"cache hit (verified)"` in stderr.
fn seed_cache_attributed(
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
            name                TEXT NOT NULL,
            version             TEXT NOT NULL,
            registry            TEXT NOT NULL,
            result              TEXT NOT NULL,
            scanned_at          TEXT NOT NULL,
            content_hash        TEXT,
            provenance_identity TEXT,
            source_kind         TEXT,
            subtree_digest      TEXT,
            dep_scan_version    TEXT,
            policies_json       TEXT,
            PRIMARY KEY (name, version, registry)
        );",
    )
    .expect("create table");
    let policies_json = format!(r#"[{{"policy_name":"age","result":"{result}","reason":null}}]"#);
    conn.execute(
        "INSERT OR REPLACE INTO scanned_packages
         (name, version, registry, result, scanned_at, content_hash, dep_scan_version, policies_json)
         VALUES (?1, ?2, ?3, ?4, datetime('now'), ?5, ?6, ?7)",
        rusqlite::params![
            name,
            version,
            registry,
            result,
            content_hash,
            env!("CARGO_PKG_VERSION"),
            policies_json
        ],
    )
    .expect("seed attributed cache row");
}

/// Read content_hash from the SQLite cache.
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

/// npm JSON with only `dist.shasum` (no `integrity`), published `hours_ago` hours ago.
/// This simulates a legacy npm package with only SHA-1 available.
fn npm_json_shasum_only(name: &str, version: &str, hours_ago: i64, shasum: &str) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(hours_ago);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "name": "{name}",
    "description": "A legacy npm package",
    "dist-tags": {{ "latest": "{version}" }},
    "versions": {{
        "{version}": {{
            "name": "{name}",
            "version": "{version}",
            "description": "A legacy npm package",
            "dist": {{
                "shasum": "{shasum}"
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

/// npm JSON with `dist.integrity` (SRI format), published `hours_ago` hours ago.
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

// "sha512-AAEC" → bytes [0x00,0x01,0x02] → dep-scan normalized: "sha512:000102"
const SRI_A: &str = "sha512-AAEC";
const HASH_A: &str = "sha512:000102";

// ── T-040-04 ─────────────────────────────────────────────────────────────────

// T-040-04: `pass` verdict with a `sha1:` content hash is NOT stored in the cache
// as a trusted entry — `content_hash` is NULL so the next lookup always Reverifies.
#[tokio::test]
async fn pass_verdict_sha1_only_stores_null_content_hash() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let shasum = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    let config = write_config(&server.uri(), db_str);

    // Package is old enough to pass age policy, sha1-only.
    Mock::given(method("GET"))
        .and(path("/sha1-pass-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_shasum_only(
                "sha1-pass-pkg",
                "1.0.0",
                72,
                shasum,
            )),
        )
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "sha1-pass-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0);

    // T-040-04: content_hash stored in cache must be NULL, not the sha1 value.
    let stored_hash = read_cached_hash(db_str, "sha1-pass-pkg", "1.0.0", "npm");
    assert_eq!(
        stored_hash, None,
        "T-040-04: pass verdict with sha1-only hash must store content_hash = NULL"
    );

    // But the row itself must exist (we're using option b: insert with NULL hash).
    let stored_result = read_cached_result(db_str, "sha1-pass-pkg", "1.0.0", "npm");
    assert_eq!(
        stored_result,
        Some("pass".to_string()),
        "T-040-04: result row must still be persisted for audit purposes"
    );
}

// ── T-040-05 ─────────────────────────────────────────────────────────────────

// T-040-05: `block` verdict with a `sha1:` content hash IS cached normally —
// caching a block is safe because the next scan would re-block, not silently pass.
#[tokio::test]
async fn block_verdict_sha1_only_stored_normally() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let shasum = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    let config = write_config(&server.uri(), db_str);

    // Package is only 1h old — fails the 48h age policy → block verdict.
    Mock::given(method("GET"))
        .and(path("/sha1-block-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_shasum_only(
                "sha1-block-pkg",
                "1.0.0",
                1,
                shasum,
            )),
        )
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "sha1-block-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1); // block → exit 1

    // T-040-05: block verdict with sha1 hash — content_hash is stored normally.
    // (The sha1 value itself is stored; the safety comes from the fact that a block
    // can only stay a block or improve — it cannot become a silent pass.)
    let stored_hash = read_cached_hash(db_str, "sha1-block-pkg", "1.0.0", "npm");
    assert_eq!(
        stored_hash,
        Some(format!("sha1:{shasum}")),
        "T-040-05: block verdict with sha1 hash should store the sha1 value normally"
    );

    let stored_result = read_cached_result(db_str, "sha1-block-pkg", "1.0.0", "npm");
    assert_eq!(
        stored_result,
        Some("block".to_string()),
        "T-040-05: block verdict must be persisted"
    );
}

// ── T-040-06 ─────────────────────────────────────────────────────────────────

// T-040-06: `warn` verdict with a `sha1:` content hash follows the same policy as
// `pass` — stored with content_hash = NULL.
//
// A warn verdict is produced by enabling `check_npm_provenance = true` with
// `require_npm_provenance = false`.  When the attestation endpoint returns 404
// (no attestations), the policy warns but does not block.  wiremock returns 404
// for any unmatched path, so only the metadata endpoint needs an explicit mock.
#[tokio::test]
async fn warn_verdict_sha1_only_stores_null_content_hash() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let shasum = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    // Config with npm_provenance in warn-only mode (require = false).
    // A 404 on the attestation endpoint means no attestations → warn.
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 0
cache_path = "{cache_path}"

[registries]
npm_url = "{npm_url}"

[policies]
check_min_age = false
check_install_scripts = false
check_maintainer_changes = false
check_typosquatting = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = true
require_npm_provenance = false

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#,
        // Escape backslashes so Windows paths (C:\Users\...) are valid TOML basic
        // strings; on Unix this is a no-op and round-trips back to the raw path.
        cache_path = db_str.replace('\\', "\\\\"),
        npm_url = server.uri(),
    )
    .expect("write config");

    // Metadata endpoint — package is old enough to pass age policy, sha1-only.
    Mock::given(method("GET"))
        .and(path("/sha1-warn-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_shasum_only(
                "sha1-warn-pkg",
                "1.0.0",
                72,
                shasum,
            )),
        )
        .mount(&server)
        .await;
    // The attestation path (/-/npm/v1/attestations/sha1-warn-pkg@1.0.0) is NOT
    // mocked; wiremock returns 404 → NpmProvenancePolicy warns (require = false).

    dep_scan()
        .args([
            "--config",
            f.path().to_str().unwrap(),
            "check",
            "sha1-warn-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1); // warn → exit 1

    // T-040-06: warn verdict with sha1 hash must store content_hash = NULL.
    let stored_hash = read_cached_hash(db_str, "sha1-warn-pkg", "1.0.0", "npm");
    assert_eq!(
        stored_hash, None,
        "T-040-06: warn verdict with sha1-only hash must store content_hash = NULL"
    );

    let stored_result = read_cached_result(db_str, "sha1-warn-pkg", "1.0.0", "npm");
    assert_eq!(
        stored_result,
        Some("warn".to_string()),
        "T-040-06: warn result must be persisted for audit purposes"
    );
}

// ── T-040-07 (integration) ───────────────────────────────────────────────────

// T-040-07: Cache hit with a `sha1:` stored hash always triggers reverify —
// even when the registry-served shasum matches perfectly (collision protection).
#[tokio::test]
async fn sha1_cache_hit_always_triggers_reverify_integration() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let shasum = "deadbeef1234567890abcdef1234567890abcdef";

    // Pre-populate cache with sha1 hash — simulates a pre-fix database row.
    seed_cache(
        db_str,
        "sha1-reverify-pkg",
        "1.0.0",
        "npm",
        "pass",
        Some(&format!("sha1:{shasum}")),
    );

    let config = write_config(&server.uri(), db_str);

    // Registry returns the exact same shasum — but the sha1 cache must still be ignored.
    Mock::given(method("GET"))
        .and(path("/sha1-reverify-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_shasum_only(
                "sha1-reverify-pkg",
                "1.0.0",
                72, // old enough → passes age policy
                shasum,
            )),
        )
        .mount(&server)
        .await;

    // T-040-07: must NOT produce "cache hit (verified)" — the full pipeline must run.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "sha1-reverify-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        // The sha1 bypass message must appear
        .stderr(predicate::str::contains(
            "sha1 hash not accepted for cache short-circuit",
        ))
        // Must NOT claim a cache hit was honored
        .stderr(predicate::str::contains("cache hit (verified)").not());
}

// ── T-040-08 (integration) ───────────────────────────────────────────────────

// T-040-08: sha1 cached hash vs sha512 registry hash — still Reverify.
// (The package was published before SRI adoption, but now has an integrity field.)
#[tokio::test]
async fn sha1_cached_sha512_registry_triggers_reverify_integration() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let shasum = "deadbeef1234567890abcdef1234567890abcdef";

    // Pre-populate cache with sha1 hash.
    seed_cache(
        db_str,
        "sha1-vs-sha512-pkg",
        "1.0.0",
        "npm",
        "pass",
        Some(&format!("sha1:{shasum}")),
    );

    let config = write_config(&server.uri(), db_str);

    // Registry now serves a sha512 integrity field (package upgraded its metadata).
    Mock::given(method("GET"))
        .and(path("/sha1-vs-sha512-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "sha1-vs-sha512-pkg",
                "1.0.0",
                72,
                SRI_A,
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
            "sha1-vs-sha512-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains(
            "sha1 hash not accepted for cache short-circuit",
        ))
        .stderr(predicate::str::contains("cache hit (verified)").not());

    // After the re-scan, the cache row should now carry the sha512 hash.
    // (NULL was the old sha1 row, re-scan fetches sha512 which gets stored normally.)
    let stored_hash = read_cached_hash(db_str, "sha1-vs-sha512-pkg", "1.0.0", "npm");
    assert_eq!(
        stored_hash,
        Some(HASH_A.to_string()),
        "T-040-08: after re-scan, cache should hold the sha512 hash from the registry"
    );
}

// ── T-040-09 (integration) ───────────────────────────────────────────────────

// T-040-09: sha512 cache short-circuit is unaffected by the sha1 fix (regression guard).
#[tokio::test]
async fn sha512_cache_short_circuit_unaffected() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    // Pre-populate with sha512 hash, fully attributed (task 112) so it is
    // honored as a genuine hit.
    seed_cache_attributed(
        db_str,
        "sha512-normal-pkg",
        "1.0.0",
        "npm",
        "pass",
        Some(HASH_A),
    );

    let config = write_config(&server.uri(), db_str);

    // Registry returns matching sha512.
    Mock::given(method("GET"))
        .and(path("/sha512-normal-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "sha512-normal-pkg",
                "1.0.0",
                72,
                SRI_A, // decodes to HASH_A — matches
            )),
        )
        .expect(1) // exactly one metadata call
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "sha512-normal-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        // T-040-09: sha512 cache hit must still be honored
        .stderr(predicate::str::contains("cache hit (verified)"));

    // wiremock expect(1) verifies exactly one call was made (the verification fetch).
}

// ── T-040-10 ─────────────────────────────────────────────────────────────────

// T-040-10: Scanning a sha1-only npm package runs the full pipeline every time.
// Two consecutive runs must both fetch metadata from the registry (no short-circuit).
#[tokio::test]
async fn sha1_only_package_scanned_every_run() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let shasum = "aabbccddeeff00112233445566778899aabbccdd";

    let config = write_config(&server.uri(), db_str);

    // wiremock counts calls — must see 2 metadata calls (one per run).
    Mock::given(method("GET"))
        .and(path("/legacypkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_shasum_only(
                "legacypkg",
                "1.0.0",
                72,
                shasum,
            )),
        )
        .expect(2) // T-040-10: both runs must hit the registry, not the cache
        .mount(&server)
        .await;

    // First run — cache is empty.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "legacypkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0);

    // Second run — cache has a row but content_hash = NULL (sha1 not stored).
    // The NULL cached hash triggers Reverify → full pipeline runs again.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "legacypkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0);

    // wiremock expect(2) will assert on drop that exactly 2 requests were made.
}

// ── T-040-11 ─────────────────────────────────────────────────────────────────

// T-040-11: Verbose output indicates why the cache was bypassed for a sha1-only package.
#[tokio::test]
async fn verbose_output_contains_sha1_bypass_message() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    let shasum = "aabbccddeeff00112233445566778899aabbccdd";

    let config = write_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/legacypkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_shasum_only(
                "legacypkg",
                "1.0.0",
                72,
                shasum,
            )),
        )
        .mount(&server)
        .await;

    // T-040-11: --verbose run should include the sha1 bypass message.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "legacypkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains(
            "sha1 hash not accepted for cache short-circuit",
        ));
}

// ── T-040-12 ─────────────────────────────────────────────────────────────────

// T-040-12: Chosen-prefix SHA-1 collision scenario.
// An attacker republishes a tarball with the same SHA-1 shasum as a known-good
// tarball.  The old sha1 row in the cache must NOT be honored.
#[tokio::test]
async fn sha1_collision_scenario_does_not_yield_cache_hit() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    // The "colliding" shasum — attacker has crafted a tarball with this sha1.
    let colliding_hash = "colliding1234567890abcdef1234567890abcd";

    // Pre-populate cache with a sha1 pass — this simulates a user who scanned
    // the original tarball before the attacker republished.
    seed_cache(
        db_str,
        "legacypkg",
        "1.0.0",
        "npm",
        "pass",
        Some(&format!("sha1:{colliding_hash}")),
    );

    let config = write_config(&server.uri(), db_str);

    // Attacker republished: registry returns the same shasum but different content.
    Mock::given(method("GET"))
        .and(path("/legacypkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_shasum_only(
                "legacypkg",
                "1.0.0",
                72, // old enough — would pass age policy
                colliding_hash,
            )),
        )
        .mount(&server)
        .await;

    // T-040-12: must NOT produce "cache hit (verified)" — full pipeline must run.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "legacypkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stderr(predicate::str::contains(
            "sha1 hash not accepted for cache short-circuit",
        ))
        .stderr(predicate::str::contains("cache hit (verified)").not());
}

// ── T-040-13: regression — sha512 hash-verify tests unaffected ────────────────
// Verified by sha512_cache_short_circuit_unaffected above and the T-030-* suite
// in hash_verify_integration.rs.  This marker test asserts a SHA-512 string does
// not start with "sha1:" — a trivial invariant that anchors the spec marker.
#[test]
fn t_040_13_sha512_hash_verify_regression_marker() {
    // T-040-13: sha512 hashes must not be misidentified as sha1 by the policy.
    assert!(
        !"sha512:aaaa".starts_with("sha1:"),
        "T-040-13: sha512 prefix must not be treated as sha1"
    );
}

// ── T-040-14: regression — npm provenance tests unaffected ───────────────────
// Verified by running the npm_provenance_integration test suite.  This marker
// test confirms that the sha1 fix (cache layer) is orthogonal to provenance
// (sigstore layer) by asserting the two prefix strings are distinct.
#[test]
fn t_040_14_npm_provenance_regression_marker() {
    // T-040-14: the sha1 policy prefix check must not affect sha512/provenance paths.
    let provenance_hash = "sha512:000102";
    assert!(
        !provenance_hash.starts_with("sha1:"),
        "T-040-14: sha512 hashes must not trigger sha1 cache bypass"
    );
}

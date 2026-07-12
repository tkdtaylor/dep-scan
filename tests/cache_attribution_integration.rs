// SPDX-License-Identifier: Apache-2.0
//! Integration tests for task 112: cached-verdict attribution.
//!
//! Cached scan results must carry the SAME full attribution as fresh results:
//! the real resolved version, the full per-policy `policies` array, and an
//! additive `cache` object recording provenance (`hit`, `scanned_at`, the
//! producing dep-scan version). Cache rows that predate attribution (either
//! `dep_scan_version` or `policies_json` NULL, unparseable, or inconsistent
//! with the stored `result`) are treated as MISSES, fail-closed, and upgraded
//! in place by the re-scan.
//!
//! T-112-01..08 (schema/`Cache::insert`/`insert_git` unit tests) live in
//! `src/cache.rs`; this file covers T-112-09..18, driving the REAL binary
//! (`assert_cmd`) against wiremock (registry path) or a local git daemon
//! (git path) and a temp SQLite cache, with raw `rusqlite` pre-population for
//! the attribution-gate scenarios.

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::Duration;

use assert_cmd::Command;
use rusqlite::Connection;
use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

/// Registry-path config: only `age` and `install_scripts` policies enabled, so
/// the `policies` array in assertions is small and exact (matches the task
/// spec's worked example).
fn write_config(npm_url: &str, cache_path: &str) -> NamedTempFile {
    // Escape backslashes so Windows paths (C:\Users\...) are valid TOML basic
    // strings; on Unix this is a no-op.
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
check_install_scripts = true
check_typosquatting = false
check_maintainer_changes = false
check_npm_provenance = false
check_vulnerabilities = false
check_obfuscation = false

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write temp config");
    f
}

/// npm JSON response with a `dist.integrity` field (SRI format).
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

/// The full post-112 `scanned_packages` schema, so raw-SQL seeding can control
/// every attribution field precisely (unlike `Cache::new`'s migration, which
/// only ever writes NULL for columns it adds to an existing table).
const FULL_SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS scanned_packages (
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
);";

/// Pre-populate a single row with full control over every attribution field.
#[allow(clippy::too_many_arguments)]
fn seed_row(
    db_path: &str,
    name: &str,
    version: &str,
    registry: &str,
    result: &str,
    scanned_at: &str,
    content_hash: Option<&str>,
    dep_scan_version: Option<&str>,
    policies_json: Option<&str>,
) {
    let conn = Connection::open(db_path).expect("open seed db");
    conn.execute_batch(FULL_SCHEMA_SQL).expect("create table");
    conn.execute(
        "INSERT OR REPLACE INTO scanned_packages
         (name, version, registry, result, scanned_at, content_hash, dep_scan_version, policies_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            name,
            version,
            registry,
            result,
            scanned_at,
            content_hash,
            dep_scan_version,
            policies_json
        ],
    )
    .expect("seed row");
}

/// "sha512-AAEC" decodes to bytes [0x00,0x01,0x02] → dep-scan normalized form.
const SRI_A: &str = "sha512-AAEC";
const HASH_A: &str = "sha512:000102";

/// Return the sole package object from a `--format json` array.
fn parse_single(stdout: &[u8]) -> Value {
    let v: Value = serde_json::from_slice(stdout).expect("valid json output");
    let arr = v.as_array().expect("json output is a bare array");
    assert_eq!(arr.len(), 1, "expected exactly one package object: {v}");
    arr[0].clone()
}

// ---------------------------------------------------------------------------
// T-112-09: Fully attributed row + matching content hash → hit with exact
// attributed JSON (field-by-field, not `contains`).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn t112_09_fully_attributed_hit_emits_exact_json() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_str = tmp.path().join("cache.db");
    let db_str = db_str.to_str().unwrap();
    let config = write_config(&server.uri(), db_str);

    let policies_json = r#"[{"policy_name":"age","result":"pass","reason":null},{"policy_name":"install_scripts","result":"block","reason":"Install script contains suspicious command: curl"}]"#;
    // dep_scan_version is deliberately NOT the running binary's version: proves
    // the emitted value comes from the ROW, not re-stamped from env! at read time.
    seed_row(
        db_str,
        "attributed-pkg",
        "1.0.0",
        "npm",
        "block",
        "2026-07-10T08:15:00Z",
        Some(HASH_A),
        Some("1.2.0"),
        Some(policies_json),
    );

    Mock::given(method("GET"))
        .and(path("/attributed-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "attributed-pkg",
                "1.0.0",
                72,
                SRI_A,
            )),
        )
        .expect(1) // exactly one metadata fetch: the hash-verification fetch
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "attributed-pkg",
            "--registry",
            "npm",
            "--format",
            "json",
        ])
        .output()
        .expect("scan runs");

    assert_eq!(output.status.code(), Some(1), "block verdict must exit 1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\"cached\""),
        "the literal \"cached\" must not appear anywhere in stdout: {stdout}"
    );

    let pkg = parse_single(&output.stdout);
    assert_eq!(pkg["package"], "attributed-pkg");
    assert_eq!(
        pkg["version"], "1.0.0",
        "version must be the real resolved version"
    );
    assert_eq!(pkg["registry"], "npm");
    assert_eq!(pkg["age_hours"], 72);
    assert_eq!(pkg["result"], "block");
    assert_eq!(
        pkg["reason"],
        "Install script contains suspicious command: curl"
    );
    assert_eq!(
        pkg["policies"],
        serde_json::json!([
            {"policy_name": "age", "result": "pass", "reason": null},
            {"policy_name": "install_scripts", "result": "block", "reason": "Install script contains suspicious command: curl"}
        ]),
        "policies array must equal the stored array element-for-element"
    );
    assert_eq!(pkg["cache"]["hit"], true);
    assert_eq!(pkg["cache"]["scanned_at"], "2026-07-10T08:15:00Z");
    assert_eq!(
        pkg["cache"]["dep_scan_version"], "1.2.0",
        "dep_scan_version must come from the ROW, not env! at read time"
    );
}

// ---------------------------------------------------------------------------
// T-112-10: NULL dep_scan_version → miss, full re-scan, row upgraded in place.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn t112_10_null_dep_scan_version_misses_then_upgrades() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_str = tmp.path().join("cache.db");
    let db_str = db_str.to_str().unwrap();
    let config = write_config(&server.uri(), db_str);

    let policies_json = r#"[{"policy_name":"age","result":"pass","reason":null},{"policy_name":"install_scripts","result":"pass","reason":null}]"#;
    seed_row(
        db_str,
        "upgrade-pkg",
        "1.0.0",
        "npm",
        "pass",
        "2026-07-10T08:15:00Z",
        Some(HASH_A),
        None, // dep_scan_version NULL
        Some(policies_json),
    );

    Mock::given(method("GET"))
        .and(path("/upgrade-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "upgrade-pkg",
                "1.0.0",
                72,
                SRI_A,
            )),
        )
        .mount(&server)
        .await;

    // Run 1: unattributed row → miss → full pipeline runs → no "cache" key.
    let out1 = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "upgrade-pkg",
            "--registry",
            "npm",
            "--format",
            "json",
        ])
        .output()
        .expect("run 1");
    let pkg1 = parse_single(&out1.stdout);
    assert!(
        pkg1.get("cache").is_none(),
        "run 1 must be a miss (no cache key): {pkg1}"
    );

    // Run 2: same DB. The re-scan's INSERT OR REPLACE upgraded the row.
    let out2 = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "upgrade-pkg",
            "--registry",
            "npm",
            "--format",
            "json",
        ])
        .output()
        .expect("run 2");
    let pkg2 = parse_single(&out2.stdout);
    assert_eq!(
        pkg2["cache"]["hit"], true,
        "run 2 must be an attributed hit"
    );
    assert_eq!(pkg2["cache"]["dep_scan_version"], env!("CARGO_PKG_VERSION"));
}

// ---------------------------------------------------------------------------
// T-112-11: NULL policies_json alone → miss.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn t112_11_null_policies_json_misses() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_str = tmp.path().join("cache.db");
    let db_str = db_str.to_str().unwrap();
    let config = write_config(&server.uri(), db_str);

    seed_row(
        db_str,
        "half-attributed-pkg",
        "1.0.0",
        "npm",
        "pass",
        "2026-07-10T08:15:00Z",
        Some(HASH_A),
        Some("1.3.1"),
        None, // policies_json NULL: both fields are required for a hit
    );

    Mock::given(method("GET"))
        .and(path("/half-attributed-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "half-attributed-pkg",
                "1.0.0",
                72,
                SRI_A,
            )),
        )
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "half-attributed-pkg",
            "--registry",
            "npm",
            "--format",
            "json",
        ])
        .output()
        .expect("scan runs");
    let pkg = parse_single(&output.stdout);
    assert!(
        pkg.get("cache").is_none(),
        "NULL policies_json alone must miss: {pkg}"
    );
}

// ---------------------------------------------------------------------------
// T-112-12: Unparseable policies_json → miss, no panic. Fail-closed on
// corrupt attribution.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn t112_12_unparseable_policies_json_misses_no_panic() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_str = tmp.path().join("cache.db");
    let db_str = db_str.to_str().unwrap();
    let config = write_config(&server.uri(), db_str);

    seed_row(
        db_str,
        "corrupt-pkg",
        "1.0.0",
        "npm",
        "pass",
        "2026-07-10T08:15:00Z",
        Some(HASH_A),
        Some("1.3.1"),
        Some("not-json{"),
    );

    Mock::given(method("GET"))
        .and(path("/corrupt-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "corrupt-pkg",
                "1.0.0",
                72,
                SRI_A,
            )),
        )
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "corrupt-pkg",
            "--registry",
            "npm",
            "--format",
            "json",
        ])
        .output()
        .expect("scan runs: must not panic on corrupt policies_json");
    // Exit code reflects the FRESH verdict; process did not panic (a panic
    // would abort with a non-standard signal-derived code and no valid stdout).
    let pkg = parse_single(&output.stdout);
    assert!(
        pkg.get("cache").is_none(),
        "unparseable policies_json must miss: {pkg}"
    );
}

// ---------------------------------------------------------------------------
// T-112-13: Stored result inconsistent with stored policies → miss (tamper
// guard). A tampered cached "pass" is never served.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn t112_13_result_policies_inconsistency_misses_tamper_guard() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_str = tmp.path().join("cache.db");
    let db_str = db_str.to_str().unwrap();
    let config = write_config(&server.uri(), db_str);

    // Stored result says "pass", but the stored policies contain a block:
    // aggregate_results(policies) would yield "block" != stored "pass".
    let tampered_policies_json = r#"[{"policy_name":"age","result":"pass","reason":null},{"policy_name":"install_scripts","result":"block","reason":"tampered-in block"}]"#;
    seed_row(
        db_str,
        "tampered-pkg",
        "1.0.0",
        "npm",
        "pass",
        "2026-07-10T08:15:00Z",
        Some(HASH_A),
        Some("1.3.1"),
        Some(tampered_policies_json),
    );

    Mock::given(method("GET"))
        .and(path("/tampered-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "tampered-pkg",
                "1.0.0",
                72,
                SRI_A,
            )),
        )
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "tampered-pkg",
            "--registry",
            "npm",
            "--format",
            "json",
        ])
        .output()
        .expect("scan runs");
    let pkg = parse_single(&output.stdout);
    assert!(
        pkg.get("cache").is_none(),
        "T-112-13: a tampered cached \"pass\" must never be served (mutation guard: deleting the \
         aggregate==stored comparison in attributed_cache_hit would make this pass): {pkg}"
    );
}

// ---------------------------------------------------------------------------
// T-112-14: Fresh scan output omits the `cache` key entirely (additive-only
// contract: the fresh JSON shape is byte-compatible with pre-112 output).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn t112_14_fresh_scan_omits_cache_key() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_str = tmp.path().join("cache.db");
    let db_str = db_str.to_str().unwrap();
    let config = write_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/fresh-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "fresh-pkg",
                "1.0.0",
                72,
                SRI_A,
            )),
        )
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "fresh-pkg",
            "--registry",
            "npm",
            "--format",
            "json",
        ])
        .output()
        .expect("scan runs");
    let pkg = parse_single(&output.stdout);
    assert!(
        !pkg.as_object().unwrap().contains_key("cache"),
        "fresh scan output must not contain the \"cache\" key: {pkg}"
    );
}

// ---------------------------------------------------------------------------
// T-112-15: Round-trip equality between a fresh run and a cached run (same
// DB, same args): the only difference is the presence of the `cache` object.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn t112_15_fresh_and_cached_round_trip_equal() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_str = tmp.path().join("cache.db");
    let db_str = db_str.to_str().unwrap();
    let config = write_config(&server.uri(), db_str);

    Mock::given(method("GET"))
        .and(path("/roundtrip-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "roundtrip-pkg",
                "1.0.0",
                72,
                SRI_A,
            )),
        )
        .mount(&server)
        .await;

    let args = [
        "--config",
        config.path().to_str().unwrap(),
        "check",
        "roundtrip-pkg",
        "--registry",
        "npm",
        "--format",
        "json",
    ];

    let out1 = dep_scan().args(args).output().expect("run 1");
    let pkg1 = parse_single(&out1.stdout);
    let out2 = dep_scan().args(args).output().expect("run 2");
    let pkg2 = parse_single(&out2.stdout);

    assert_eq!(pkg1["policies"], pkg2["policies"]);
    assert_eq!(pkg1["result"], pkg2["result"]);
    assert_eq!(pkg1["reason"], pkg2["reason"]);
    assert_eq!(pkg1["version"], pkg2["version"]);
    assert!(pkg1.get("cache").is_none(), "run 1 is fresh: no cache key");
    assert_eq!(pkg2["cache"]["hit"], true, "run 2 is a cache hit");
}

// ---------------------------------------------------------------------------
// T-112-16: Exit-code contract unchanged for cached block/pass.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn t112_16_exit_codes_unchanged_for_cached_verdicts() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_str = tmp.path().join("cache.db");
    let db_str = db_str.to_str().unwrap();
    let config = write_config(&server.uri(), db_str);

    let block_policies = r#"[{"policy_name":"age","result":"pass","reason":null},{"policy_name":"install_scripts","result":"block","reason":"blocked"}]"#;
    let pass_policies = r#"[{"policy_name":"age","result":"pass","reason":null},{"policy_name":"install_scripts","result":"pass","reason":null}]"#;
    seed_row(
        db_str,
        "exit-block-pkg",
        "1.0.0",
        "npm",
        "block",
        "2026-07-10T08:15:00Z",
        Some(HASH_A),
        Some(env!("CARGO_PKG_VERSION")),
        Some(block_policies),
    );
    seed_row(
        db_str,
        "exit-pass-pkg",
        "2.0.0",
        "npm",
        "pass",
        "2026-07-10T08:15:00Z",
        Some(HASH_A),
        Some(env!("CARGO_PKG_VERSION")),
        Some(pass_policies),
    );

    Mock::given(method("GET"))
        .and(path("/exit-block-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "exit-block-pkg",
                "1.0.0",
                72,
                SRI_A,
            )),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/exit-pass-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "exit-pass-pkg",
                "2.0.0",
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
            "check",
            "exit-block-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1);
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "exit-pass-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0);
}

// ---------------------------------------------------------------------------
// T-112-17: Native table shows the real version on a cached hit; per-policy
// lines render from the stored array.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn t112_17_native_table_shows_real_version() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_str = tmp.path().join("cache.db");
    let db_str = db_str.to_str().unwrap();
    let config = write_config(&server.uri(), db_str);

    let policies_json = r#"[{"policy_name":"age","result":"pass","reason":null},{"policy_name":"install_scripts","result":"block","reason":"Install script contains suspicious command: curl"}]"#;
    seed_row(
        db_str,
        "native-pkg",
        "1.0.0",
        "npm",
        "block",
        "2026-07-10T08:15:00Z",
        Some(HASH_A),
        Some(env!("CARGO_PKG_VERSION")),
        Some(policies_json),
    );

    Mock::given(method("GET"))
        .and(path("/native-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "native-pkg",
                "1.0.0",
                72,
                SRI_A,
            )),
        )
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "native-pkg",
            "--registry",
            "npm",
        ])
        .output()
        .expect("scan runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1.0.0"),
        "native table must show the real resolved version: {stdout}"
    );
    assert!(
        !stdout.contains("cached"),
        "the string \"cached\" must not appear in native output: {stdout}"
    );
    assert!(
        stdout.contains(
            "  install_scripts: BLOCK — Install script contains suspicious command: curl"
        ),
        "per-policy line must render from the stored policies array: {stdout}"
    );
    assert!(
        stdout.contains("  age: pass"),
        "per-policy line must render from the stored policies array: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// T-112-18: Git pinned-SHA cached hit carries attribution.
// ---------------------------------------------------------------------------

fn git_available() -> bool {
    StdCommand::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_git(dir: &Path, args: &[&str]) {
    let status = StdCommand::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(
        status.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

fn run_git_capture(dir: &Path, args: &[&str]) -> String {
    let out = StdCommand::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(out.status.success(), "git {args:?} failed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct GitDaemon {
    child: Child,
    port: u16,
}
impl GitDaemon {
    fn start(base: &Path) -> Option<Self> {
        let port = TcpListener::bind("127.0.0.1:0")
            .ok()?
            .local_addr()
            .ok()?
            .port();
        let child = StdCommand::new("git")
            .args([
                "daemon",
                "--reuseaddr",
                "--listen=127.0.0.1",
                &format!("--port={port}"),
                &format!("--base-path={}", base.display()),
                "--export-all",
                "--informative-errors",
            ])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", base)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let daemon = GitDaemon { child, port };
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(daemon);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
    fn url(&self, repo: &str) -> String {
        format!("git://127.0.0.1:{}/{repo}", self.port)
    }
}
impl Drop for GitDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Build a benign repo (no malicious content), serve it over a local daemon.
fn build_served_repo() -> Option<(TempDir, GitDaemon, String, String)> {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("clean-subtree");
    std::fs::create_dir(&repo).unwrap();
    run_git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("package.json"), br#"{"name":"clean-subtree"}"#).unwrap();
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "init"]);
    let head = run_git_capture(&repo, &["rev-parse", "HEAD"]);
    let daemon = GitDaemon::start(dir.path())?;
    let url = daemon.url("clean-subtree");
    Some((dir, daemon, url, head))
}

/// Offline flat-git config: dead registry URLs (no [transitive] block, so the
/// FLAT git-dep scan arm in `run_check` handles this, not the transitive walker).
fn write_git_config(cache_path: &str) -> NamedTempFile {
    let cache_path = cache_path.replace('\\', "\\\\");
    let dead = "http://127.0.0.1:1";
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"min_package_age_hours = 0
cache_path = "{cache_path}"

[registries]
npm_url = "{dead}"
pypi_url = "{dead}"
crates_url = "{dead}"
go_proxy_url = "{dead}"
go_sum_db_url = "{dead}"

[policies]
check_min_age = false
check_install_scripts = true
check_maintainer_changes = false
check_typosquatting = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_pypi_provenance = false
check_go_sumdb = false

[osv]
osv_url = "{dead}"

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0

[vcs]
fetch_timeout_secs = 5
"#
    )
    .expect("write temp config");
    f
}

fn git_dep_cargo_lock(url: &str, sha: &str) -> String {
    format!(
        r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "clean-subtree"
version = "0.1.0"
source = "git+{url}#{sha}"
"#
    )
}

#[test]
fn t112_18_git_pinned_sha_cached_hit_carries_attribution() {
    if !git_available() {
        eprintln!("skip T-112-18: git CLI not available");
        return;
    }
    let Some((_dir, _daemon, url, head)) = build_served_repo() else {
        eprintln!("skip T-112-18: could not start local git daemon");
        return;
    };

    let tmp = TempDir::new().unwrap();
    let cache = tmp.path().join("c.db");
    let cfg = write_git_config(cache.to_str().unwrap());
    let lock = git_dep_cargo_lock(&url, &head);
    let lockfile = tmp.path().join("Cargo.lock");
    std::fs::write(&lockfile, &lock).unwrap();

    let args = [
        "--config",
        cfg.path().to_str().unwrap(),
        "check",
        "--lockfile",
        lockfile.to_str().unwrap(),
        "--lockfile-type",
        "crates",
        "--format",
        "json",
    ];

    // Run 1: real fetch + full policy pipeline; writes an attributed row.
    let out1 = dep_scan().args(args).output().expect("T-112-18: run 1");
    let pkg1 = parse_single(&out1.stdout);
    assert!(
        pkg1.get("cache").is_none(),
        "T-112-18: run 1 is a fresh fetch, no cache key: {pkg1}"
    );
    let policies1 = pkg1["policies"].clone();
    assert!(
        policies1.as_array().is_some_and(|a| !a.is_empty()),
        "T-112-18: run 1 must have a non-empty policies array (at least mutable_ref): {pkg1}"
    );

    // Run 2: same DB, same daemon. Must be an attributed hit, no re-fetch
    // (the daemon would still serve a second fetch, but the point under test
    // is the cache-hit attribution, not the no-fetch behavior of task 097).
    let out2 = dep_scan().args(args).output().expect("T-112-18: run 2");
    let pkg2 = parse_single(&out2.stdout);
    assert_eq!(
        pkg2["cache"]["hit"], true,
        "T-112-18: run 2 must be an attributed git cache hit: {pkg2}"
    );
    assert_eq!(pkg2["cache"]["dep_scan_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        pkg2["policies"], policies1,
        "T-112-18: cached policies array must equal run 1's"
    );
    assert!(
        !out2.stdout.windows(8).any(|w| w == b"\"cached\""),
        "T-112-18: no version: \"cached\" regression on the git path"
    );
}

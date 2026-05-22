/// Integration tests for task 031 — pip --require-hashes passthrough.
///
/// These tests use assert_cmd + wiremock to run the full binary against a
/// controlled HTTP mock server, and a mock pip script on PATH to verify
/// which arguments dep-scan actually passes to pip.
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

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

/// Write a minimal config file pointing at the given PyPI mock URL.
fn write_pypi_config(pypi_url: &str, cache_path: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 48
cache_path = "{cache_path}"

[registries]
pypi_url = "{pypi_url}"

[policies]
check_min_age = true
check_install_scripts = false
check_maintainer_changes = false
check_typosquatting = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_pypi_provenance = false

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write temp config");
    f
}

/// Write a minimal config with npm URL set (for T-031-11).
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

/// Create a mock pip script in a temp directory.
///
/// The script records its argv to `<argv_file>` (one arg per line) and exits 0.
/// Returns the temp directory (kept alive via TempDir) and the argv file path.
fn create_mock_pip(tmp: &TempDir) -> std::path::PathBuf {
    let bin_dir = tmp.path().join("mock-bin");
    std::fs::create_dir_all(&bin_dir).expect("create mock bin dir");

    let argv_file = tmp.path().join("pip-argv.txt");
    let argv_path_str = argv_file.to_str().expect("utf8").to_string();

    // Write a shell script that:
    // 1. Echoes each argument to the argv file (one per line).
    // 2. If a -r flag is present, records the contents of the requirements
    //    file to a separate file for inspection.
    // 3. Exits 0.
    let script = format!(
        r#"#!/bin/sh
# Mock pip: record argv to file, exit 0.
ARGV_FILE="{argv_path_str}"
printf "" > "$ARGV_FILE"
for arg in "$@"; do
    echo "$arg" >> "$ARGV_FILE"
done
# If -r was given, copy the requirements file for test inspection.
prev=""
for arg in "$@"; do
    if [ "$prev" = "-r" ]; then
        cp "$arg" "{argv_path_str}.req"
    fi
    prev="$arg"
done
exit 0
"#
    );

    let pip_path = bin_dir.join("pip");
    std::fs::write(&pip_path, script).expect("write mock pip");
    let mut perms = std::fs::metadata(&pip_path)
        .expect("metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&pip_path, perms).expect("set permissions");

    bin_dir
}

/// Read the recorded pip argv from the file (split by newline, filter empties).
fn read_pip_argv(tmp: &TempDir) -> Vec<String> {
    let path = tmp.path().join("pip-argv.txt");
    if !path.exists() {
        return vec![];
    }
    let contents = std::fs::read_to_string(&path).unwrap_or_default();
    contents
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

/// Read the requirements file that pip was passed (captured by mock script).
fn read_pip_req_file(tmp: &TempDir) -> Option<String> {
    let path = tmp.path().join("pip-argv.txt.req");
    if path.exists() {
        Some(std::fs::read_to_string(&path).unwrap_or_default())
    } else {
        None
    }
}

/// PyPI JSON response for a package with a sha256 digest (passes age policy).
fn pypi_json_with_hash(name: &str, version: &str, hours_ago: i64, sha256: &str) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(hours_ago);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "info": {{
        "name": "{name}",
        "version": "{version}",
        "summary": "A test package",
        "author": "Test Author",
        "author_email": "",
        "maintainer": "",
        "maintainer_email": "",
        "home_page": "",
        "project_urls": null
    }},
    "releases": {{
        "{version}": [
            {{
                "filename": "{name}-{version}.tar.gz",
                "packagetype": "sdist",
                "upload_time_iso_8601": "{ts}",
                "digests": {{ "sha256": "{sha256}" }}
            }}
        ]
    }}
}}"#
    )
}

/// PyPI JSON response with NO digests block (content_hash = None).
fn pypi_json_no_hash(name: &str, version: &str, hours_ago: i64) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(hours_ago);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "info": {{
        "name": "{name}",
        "version": "{version}",
        "summary": "A test package",
        "author": "Test Author",
        "author_email": "",
        "maintainer": "",
        "maintainer_email": "",
        "home_page": "",
        "project_urls": null
    }},
    "releases": {{
        "{version}": [
            {{
                "filename": "{name}-{version}.tar.gz",
                "packagetype": "sdist",
                "upload_time_iso_8601": "{ts}",
                "digests": {{}}
            }}
        ]
    }}
}}"#
    )
}

/// npm JSON for T-031-11.
fn npm_json(name: &str, version: &str, hours_ago: i64) -> String {
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

// ── T-031-08 ──────────────────────────────────────────────────────────────────

// T-031-08: Clean pip install uses --require-hashes -r passthrough
//
// wiremock PyPI returns metadata with sdist digests.sha256 = "abcd…", age passes
// Mock pip records its argv to a file
// Run: dep-scan install requests --registry pypi
// Expected: exit 0, pip's recorded argv contains "install", "--require-hashes",
// "-r", and a path to a temp file; the temp file is deleted post-run.
#[tokio::test]
async fn clean_pip_install_uses_require_hashes_passthrough() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    let sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    Mock::given(method("GET"))
        .and(path("/pypi/requests/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(pypi_json_with_hash("requests", "2.31.0", 72, sha256)),
        )
        .mount(&server)
        .await;

    let bin_dir = create_mock_pip(&tmp);
    let original_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{original_path}", bin_dir.display());

    dep_scan()
        .env("PATH", &new_path)
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "requests",
            "--registry",
            "pypi",
        ])
        .assert()
        .code(0);

    let argv = read_pip_argv(&tmp);
    assert!(
        argv.contains(&"install".to_string()),
        "pip argv should contain 'install', got: {argv:?}"
    );
    assert!(
        argv.contains(&"--require-hashes".to_string()),
        "pip argv should contain '--require-hashes', got: {argv:?}"
    );
    assert!(
        argv.contains(&"-r".to_string()),
        "pip argv should contain '-r', got: {argv:?}"
    );

    // The path after -r should point to a file that no longer exists (cleaned up).
    let r_idx = argv.iter().position(|a| a == "-r").unwrap();
    let req_path = std::path::Path::new(&argv[r_idx + 1]);
    assert!(
        !req_path.exists(),
        "temp requirements file should be removed post-run, but {} still exists",
        req_path.display()
    );

    // Also verify the requirements file contents (captured by mock pip).
    let req_contents = read_pip_req_file(&tmp)
        .expect("mock pip should have captured the requirements file contents");
    assert!(
        req_contents.contains(&format!("requests==2.31.0 --hash=sha256:{sha256}")),
        "requirements file should contain the hash line, got: {req_contents}"
    );
}

// ── T-031-09 ──────────────────────────────────────────────────────────────────

// T-031-09: Missing hash falls back to plain pip install
//
// wiremock PyPI returns metadata with no digests block (content_hash = None)
// Run: dep-scan install obscure-pkg --registry pypi
// Expected: exit 0, pip argv is "install obscure-pkg" (no --require-hashes),
// stderr contains a warning naming the registry URL and the package.
#[tokio::test]
async fn missing_hash_falls_back_to_plain_pip_install() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/pypi/obscure-pkg/json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(pypi_json_no_hash(
                "obscure-pkg",
                "1.0.0",
                72,
            )),
        )
        .mount(&server)
        .await;

    let bin_dir = create_mock_pip(&tmp);
    let original_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{original_path}", bin_dir.display());

    let output = dep_scan()
        .env("PATH", &new_path)
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "obscure-pkg",
            "--registry",
            "pypi",
        ])
        .output()
        .expect("run dep-scan");

    assert_eq!(output.status.code(), Some(0), "expected exit 0");

    let argv = read_pip_argv(&tmp);
    assert!(
        argv.contains(&"install".to_string()),
        "pip argv should contain 'install', got: {argv:?}"
    );
    assert!(
        argv.contains(&"obscure-pkg".to_string()),
        "pip argv should contain 'obscure-pkg' (plain install fallback), got: {argv:?}"
    );
    assert!(
        !argv.contains(&"--require-hashes".to_string()),
        "pip argv should NOT contain '--require-hashes' for missing hash, got: {argv:?}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning:"),
        "stderr should contain a warning, got: {stderr}"
    );
    assert!(
        stderr.contains("obscure-pkg"),
        "warning should name the package, got: {stderr}"
    );
    // The warning should name the registry URL.
    assert!(
        stderr.contains(&server.uri()),
        "warning should name the registry URL, got: {stderr}"
    );
}

// ── T-031-10 ──────────────────────────────────────────────────────────────────

// T-031-10: Mixed packages — fallback (all-or-nothing)
//
// wiremock returns hash for pkg-a but not for pkg-b
// Run: dep-scan install pkg-a pkg-b --registry pypi
// Expected: pip argv is "install pkg-a pkg-b" (no --require-hashes),
// stderr contains a warning naming pkg-b.
#[tokio::test]
async fn mixed_packages_fallback_all_or_nothing() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    let sha256 = "aaaa1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";
    Mock::given(method("GET"))
        .and(path("/pypi/pkg-a/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(pypi_json_with_hash("pkg-a", "1.0.0", 72, sha256)),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/pypi/pkg-b/json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(pypi_json_no_hash("pkg-b", "2.0.0", 72)),
        )
        .mount(&server)
        .await;

    let bin_dir = create_mock_pip(&tmp);
    let original_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{original_path}", bin_dir.display());

    let output = dep_scan()
        .env("PATH", &new_path)
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "pkg-a",
            "pkg-b",
            "--registry",
            "pypi",
        ])
        .output()
        .expect("run dep-scan");

    assert_eq!(output.status.code(), Some(0), "expected exit 0");

    let argv = read_pip_argv(&tmp);
    // Fallback: no --require-hashes
    assert!(
        !argv.contains(&"--require-hashes".to_string()),
        "pip argv should NOT contain '--require-hashes' for mixed packages, got: {argv:?}"
    );
    // Plain install with both packages
    assert!(
        argv.contains(&"pkg-a".to_string()),
        "pip argv should contain 'pkg-a', got: {argv:?}"
    );
    assert!(
        argv.contains(&"pkg-b".to_string()),
        "pip argv should contain 'pkg-b', got: {argv:?}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("pkg-b"),
        "stderr warning should name pkg-b (the package missing a hash), got: {stderr}"
    );
}

// ── T-031-11 ──────────────────────────────────────────────────────────────────

// T-031-11: Non-pip registries are unchanged
//
// Run: dep-scan install lodash --registry npm against clean wiremock
// Expected: pip-related code is not exercised; npm argv is "install lodash" exactly.
#[tokio::test]
async fn non_pip_registries_are_unchanged() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_npm_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/lodash"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json("lodash", "4.17.21", 72)))
        .mount(&server)
        .await;

    // Create a mock npm binary (not pip) to capture npm's argv.
    let bin_dir = tmp.path().join("mock-npm-bin");
    std::fs::create_dir_all(&bin_dir).expect("create dir");
    let argv_file = tmp.path().join("npm-argv.txt");
    let argv_path_str = argv_file.to_str().expect("utf8").to_string();

    let npm_script = format!(
        r#"#!/bin/sh
printf "" > "{argv_path_str}"
for arg in "$@"; do
    echo "$arg" >> "{argv_path_str}"
done
exit 0
"#
    );
    let npm_path = bin_dir.join("npm");
    std::fs::write(&npm_path, npm_script).expect("write mock npm");
    let mut perms = std::fs::metadata(&npm_path)
        .expect("metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&npm_path, perms).expect("set permissions");

    let original_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{original_path}", bin_dir.display());

    dep_scan()
        .env("PATH", &new_path)
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "lodash",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0);

    let npm_argv_contents = std::fs::read_to_string(&argv_file).unwrap_or_default();
    let npm_argv: Vec<&str> = npm_argv_contents
        .lines()
        .filter(|l| !l.is_empty())
        .collect();

    assert!(
        npm_argv.contains(&"install"),
        "npm argv should contain 'install', got: {npm_argv:?}"
    );
    assert!(
        npm_argv.contains(&"lodash"),
        "npm argv should contain 'lodash', got: {npm_argv:?}"
    );
    // Verify no pip-related flags leaked into npm invocation.
    assert!(
        !npm_argv.contains(&"--require-hashes"),
        "npm argv should NOT contain '--require-hashes', got: {npm_argv:?}"
    );

    // Also verify that the pip argv file was NOT created (pip was not invoked).
    let pip_argv_file = tmp.path().join("pip-argv.txt");
    assert!(
        !pip_argv_file.exists(),
        "pip should not have been invoked for npm registry"
    );
}

// ── T-031-12 ──────────────────────────────────────────────────────────────────

// T-031-12: --force after hash-mismatch re-scan still uses --require-hashes
// with the new hash (not the stale cached one).
//
// Pre-populate cache with (pkg, "latest", pypi, "pass", content_hash="sha256:aaaa")
// wiremock returns metadata with digests.sha256 = "bbbb" and a fresh published_at
// (fails age policy — forces the re-scan path).
// Run: dep-scan install pkg --registry pypi --force
// Expected: re-scan is triggered (per task 030), verdict is block for age,
// --force bypasses the verdict, pip argv contains --require-hashes -r <file>
// and the requirements file contains --hash=sha256:bbbb (the freshly observed
// hash, NOT the stale cached "aaaa").
#[tokio::test]
async fn force_after_hash_mismatch_rescan_uses_new_hash() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("cache.db");
    let db_str = db_path.to_str().unwrap();

    // Seed with stale hash "sha256:aaaa" and result "pass".
    seed_cache(
        db_str,
        "force-pkg",
        "latest",
        "pypi",
        "pass",
        Some("sha256:aaaa"),
    );

    let config = write_pypi_config(&server.uri(), db_str);

    // Registry returns "bbbb" + fresh published_at (1h old → fails 48h age policy).
    let sha256_new = "bbbb1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";
    Mock::given(method("GET"))
        .and(path("/pypi/force-pkg/json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(pypi_json_with_hash(
                "force-pkg",
                "1.0.0",
                1, // 1h old → fails age policy
                sha256_new,
            )),
        )
        .mount(&server)
        .await;

    let bin_dir = create_mock_pip(&tmp);
    let original_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{original_path}", bin_dir.display());

    let output = dep_scan()
        .env("PATH", &new_path)
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "force-pkg",
            "--registry",
            "pypi",
            "--force",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify re-scan was triggered (hash mismatch → invalidation).
    assert!(
        stderr.contains("cache hash mismatch for force-pkg; re-scanning"),
        "stderr should show re-scan was triggered (hash mismatch), got: {stderr}"
    );

    // --force should bypass the block verdict → install attempted.
    assert!(
        stdout.contains("Installing via pip"),
        "install should be attempted with --force, got stdout: {stdout}\nstderr: {stderr}"
    );

    let argv = read_pip_argv(&tmp);
    assert!(
        argv.contains(&"--require-hashes".to_string()),
        "pip argv should contain '--require-hashes' (new hash available), got: {argv:?}"
    );
    assert!(
        argv.contains(&"-r".to_string()),
        "pip argv should contain '-r', got: {argv:?}"
    );

    // The requirements file must contain the NEW hash (bbbb…), not the stale aaaa.
    let req_contents = read_pip_req_file(&tmp)
        .expect("mock pip should have captured the requirements file contents");
    assert!(
        req_contents.contains(&format!("--hash=sha256:{sha256_new}")),
        "requirements file should contain the new hash (bbbb...), got: {req_contents}"
    );
    assert!(
        !req_contents.contains("sha256:aaaa"),
        "requirements file should NOT contain the stale hash (aaaa), got: {req_contents}"
    );
}

// ── T-031-13 ──────────────────────────────────────────────────────────────────

// T-031-13: Empty package list is a no-op
//
// Run: dep-scan install --registry pypi with no positional args
// Expected: CLI rejects empty input (existing behavior), no temp file created.
#[tokio::test]
async fn empty_package_list_is_noop() {
    dep_scan()
        .args(["install", "--registry", "pypi"])
        .assert()
        .code(predicate::ne(0)); // any non-zero exit — CLI should reject this
    // No temp file assertions needed since dep-scan should exit before creating one.
}

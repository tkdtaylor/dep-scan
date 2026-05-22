use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build a `Command` for the dep-scan binary.
fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

/// Write a temporary config file that points at the given wiremock URL and cache path.
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
check_typosquatting = true
check_install_scripts = true
check_maintainer_changes = true
check_npm_provenance = false
"#
    )
    .expect("write temp config");
    f
}

/// npm JSON response for a package published `hours_ago` hours in the past.
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
            "description": "A test package",
            "repository": {{
                "type": "git",
                "url": "git+https://github.com/test/{name}.git"
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

/// npm JSON response with a dist.integrity field (SRI format).
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
            "repository": {{
                "type": "git",
                "url": "git+https://github.com/test/{name}.git"
            }},
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

// T-009-01: Check passing package exits 0
// Setup: wiremock returns npm JSON for package published 72h ago
// Run: dep-scan check old-package --registry npm
// Expected: exit code 0, output shows "pass"
#[tokio::test]
async fn check_passing_package_exits_0() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/old-package"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "old-package",
            "1.0.0",
            72,
        )))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "old-package",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("pass"));
}

// T-009-02: Check failing package exits 1
// Setup: wiremock returns npm JSON for package published 1h ago
// Run: dep-scan check new-package --registry npm
// Expected: exit code 1, output shows "BLOCK" with age reason
#[tokio::test]
async fn check_failing_package_exits_1() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/new-package"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "new-package",
            "1.0.0",
            1,
        )))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "new-package",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("BLOCK"))
        .stdout(predicate::str::contains("new-package"));
}

// T-009-03: Check with --json outputs valid JSON
// Setup: wiremock returns npm JSON
// Run: dep-scan check some-package --registry npm --json
// Expected: exit code 0 or 1, output is valid JSON with expected fields
#[tokio::test]
async fn check_with_json_flag_outputs_valid_json() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/some-package"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "some-package",
            "2.0.0",
            72,
        )))
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "some-package",
            "--registry",
            "npm",
            "--json",
        ])
        .output()
        .expect("run dep-scan");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");

    // Should be an array
    let arr = parsed.as_array().expect("should be a JSON array");
    assert_eq!(arr.len(), 1);

    let entry = &arr[0];
    assert_eq!(entry["package"], "some-package");
    assert_eq!(entry["version"], "2.0.0");
    assert_eq!(entry["registry"], "npm");
    assert!(entry["age_hours"].is_number());
    assert!(entry["result"].is_string());
}

// T-009-04: Multiple packages (one old, one new) exits 1, shows both results
// Setup: wiremock returns JSON for two packages
// Run: dep-scan check old-pkg new-pkg --registry npm
// Expected: exit code 1 (at least one failure), output shows results for both
#[tokio::test]
async fn check_multiple_packages_mixed_results_exits_1() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/old-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json("old-pkg", "1.0.0", 72)))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/new-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json("new-pkg", "0.1.0", 1)))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "old-pkg",
            "new-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("old-pkg"))
        .stdout(predicate::str::contains("new-pkg"))
        .stdout(predicate::str::contains("pass"))
        .stdout(predicate::str::contains("BLOCK"));
}

// T-009-05: Cache hit with verified hash uses cached result
//
// Task 030 changed the semantics: a cache hit now always makes one registry
// call (for content-hash verification) before deciding whether to honor the
// cache.  When the cached hash matches the registry hash, the cached verdict
// is returned without running the full policy pipeline.
#[tokio::test]
async fn cache_hit_skips_registry_query() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    // Pre-populate the cache with a known content_hash.
    // "sha512-AAEC" → bytes [0x00,0x01,0x02] → dep-scan normalized: "sha512:000102"
    let hash = "sha512:000102";
    {
        let cache = rusqlite::Connection::open(&cache_path).unwrap();
        cache
            .execute_batch(
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
            .unwrap();
        cache
            .execute(
                "INSERT INTO scanned_packages
                 (name, version, registry, result, scanned_at, content_hash)
                 VALUES ('cached-pkg', '1.0.0', 'npm', 'pass', '2025-01-01T00:00:00Z', ?1)",
                rusqlite::params![hash],
            )
            .unwrap();
    }

    // Mount a wiremock endpoint that returns the same hash — cache will be honored.
    Mock::given(method("GET"))
        .and(path("/cached-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "cached-pkg",
                "1.0.0",
                72,
                "sha512-AAEC",
            )),
        )
        .expect(1) // exactly ONE metadata call: the verification fetch
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "cached-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("cached-pkg"));
}

// T-009-06: New results are cached (second run verifies hash and uses cache)
//
// Task 030: a cache hit now always makes one verification fetch.  When the
// registry returns the same hash that was cached, the verdict is reused.
// Total requests: first run = 2 (metadata + install_scripts),
// second run = 1 (verification fetch only; HonorCache skips install_scripts).
#[tokio::test]
async fn new_results_are_cached() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    // Use a JSON that includes dist.integrity so the cache stores a hash and
    // the second run can verify and honor the cache.
    Mock::given(method("GET"))
        .and(path("/fresh-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "fresh-pkg",
                "1.0.0",
                72,
                "sha512-AAEC",
            )),
        )
        .mount(&server)
        .await;

    // First run: queries registry (metadata) + install scripts = 2 requests.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "fresh-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("pass"));

    // Second run: one verification fetch (HonorCache), no install_scripts fetch.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "fresh-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0);

    // Total: 2 (first run) + 1 (second run verification) = 3.
    let received = server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        3,
        "Expected 3 HTTP requests total (2 first run + 1 verification), got {}",
        received.len()
    );
}

// T-009-07: Registry error exits 2
// Setup: wiremock returns 500
// Run: dep-scan check broken-pkg --registry npm
// Expected: exit code 2, error message shown
#[tokio::test]
async fn registry_error_exits_2() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/broken-pkg"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "broken-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("ERROR"));
}

// T-009-08: Human-readable output format includes package name, version, age, result
// Setup: wiremock returns npm JSON
// Run: dep-scan check table-pkg --registry npm
// Expected: output contains package name, version, age, and policy result
#[tokio::test]
async fn human_readable_output_format() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/table-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "table-pkg",
            "3.2.1",
            100,
        )))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "table-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Package"))
        .stdout(predicate::str::contains("Version"))
        .stdout(predicate::str::contains("Age"))
        .stdout(predicate::str::contains("Result"))
        .stdout(predicate::str::contains("table-pkg"))
        .stdout(predicate::str::contains("3.2.1"))
        .stdout(predicate::str::contains("pass"));
}

// T-010-09: Check with only age policy — backwards compatible exit 0
// Setup: wiremock npm JSON for package published 72h ago
// Run: dep-scan check old-package --registry npm
// Expected: same behavior as v0.1 — exit 0, pass result
#[tokio::test]
async fn check_with_age_policy_backwards_compatible() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/compat-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "compat-pkg",
            "2.0.0",
            72,
        )))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "compat-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("pass"))
        .stdout(predicate::str::contains("compat-pkg"));
}

// T-010-10: JSON output includes policies array
// Setup: wiremock npm JSON
// Run: dep-scan check package --registry npm --json
// Expected: JSON has "policies" array with at least age policy entry
#[tokio::test]
async fn json_output_includes_policies_array() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/json-policies-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "json-policies-pkg",
            "1.5.0",
            72,
        )))
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "json-policies-pkg",
            "--registry",
            "npm",
            "--json",
        ])
        .output()
        .expect("run dep-scan");

    assert!(output.status.success(), "should exit 0 for old package");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: Value = serde_json::from_str(&stdout).expect("output should be valid JSON");

    let arr = parsed.as_array().expect("should be a JSON array");
    assert_eq!(arr.len(), 1);

    let entry = &arr[0];
    assert_eq!(entry["package"], "json-policies-pkg");
    assert_eq!(entry["result"], "pass");

    // Verify the policies array exists and has the age policy
    let policies = entry["policies"]
        .as_array()
        .expect("should have policies array");
    assert!(
        !policies.is_empty(),
        "policies array should not be empty when age policy is enabled"
    );
    assert_eq!(policies[0]["policy_name"], "age");
    assert_eq!(policies[0]["result"], "pass");
}

// T-010-11: Multiple policies in output (per-policy breakdown in human output)
// Setup: wiremock npm JSON, age policy enabled, package passes age check
// Expected: output shows individual policy results
#[tokio::test]
async fn human_output_shows_per_policy_breakdown() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/breakdown-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "breakdown-pkg",
            "1.0.0",
            72,
        )))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "breakdown-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("breakdown-pkg"))
        .stdout(predicate::str::contains("age: pass"));
}

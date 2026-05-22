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

/// Write a temporary config file with all v0.3 policies enabled,
/// pointing at the given wiremock servers for all registries.
fn write_v3_config(
    npm_url: &str,
    osv_url: &str,
    crates_url: &str,
    go_proxy_url: &str,
    cache_path: &str,
) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 48
cache_path = "{cache_path}"

[registries]
npm_url = "{npm_url}"
crates_url = "{crates_url}"
go_proxy_url = "{go_proxy_url}"

[policies]
check_min_age = true
check_install_scripts = true
check_maintainer_changes = true
check_typosquatting = true
check_vulnerabilities = true
check_obfuscation = true
check_npm_provenance = false
check_pypi_provenance = false
check_go_sumdb = false

[osv]
osv_url = "{osv_url}"

[dependency_confusion]
internal_prefixes = ["internal-", "private-"]

[popularity]
min_downloads = 1000
"#
    )
    .expect("write temp config");
    f
}

/// Write a v3 config with a custom min_downloads threshold for popularity.
fn write_v3_config_with_popularity(
    crates_url: &str,
    osv_url: &str,
    cache_path: &str,
    min_downloads: u64,
) -> NamedTempFile {
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
check_install_scripts = true
check_maintainer_changes = true
check_typosquatting = true
check_vulnerabilities = true
check_obfuscation = true
check_npm_provenance = false

[osv]
osv_url = "{osv_url}"

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = {min_downloads}
"#
    )
    .expect("write temp config");
    f
}

/// crates.io API response JSON for a crate published `hours_ago` hours in the past.
fn crates_json(name: &str, version: &str, hours_ago: i64, downloads: u64) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(hours_ago);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "crate": {{
        "name": "{name}",
        "max_version": "{version}",
        "description": "A test crate",
        "downloads": {downloads},
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

/// Go proxy version list (plain text, one version per line).
fn go_version_list(versions: &[&str]) -> String {
    versions.join("\n")
}

/// Go proxy version info JSON.
fn go_version_info(version: &str, hours_ago: i64) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(hours_ago);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(r#"{{"Version":"{version}","Time":"{ts}"}}"#)
}

/// OSV response with no vulnerabilities.
fn osv_clean_response() -> String {
    "{}".to_string()
}

// =========================================================================
// T-022-05: crates.io package check end-to-end
//
// Setup: wiremock serves crates.io JSON for a crate (72h old, 50M downloads).
// Expected: exit 0, shows policy results including age: pass.
// =========================================================================
#[tokio::test]
async fn crates_io_package_check_e2e() {
    let crates_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    let go_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");

    let config = write_v3_config(
        &npm_server.uri(),
        &osv_server.uri(),
        &crates_server.uri(),
        &go_server.uri(),
        cache_path.to_str().unwrap(),
    );

    // crates.io: well-established crate, 72h old, 50M downloads
    Mock::given(method("GET"))
        .and(path("/api/v1/crates/test-crate"))
        .respond_with(ResponseTemplate::new(200).set_body_string(crates_json(
            "test-crate",
            "1.0.0",
            72,
            50_000_000,
        )))
        .mount(&crates_server)
        .await;

    // OSV: clean
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(osv_clean_response()))
        .mount(&osv_server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "test-crate",
            "--registry",
            "crates",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("age: pass"))
        .stdout(predicate::str::contains("popularity: pass"));
}

// =========================================================================
// T-022-06: Go module check end-to-end
//
// Setup: wiremock serves Go proxy list + info (72h old).
// Expected: exit 0, shows policy results.
// =========================================================================
#[tokio::test]
async fn go_module_check_e2e() {
    let go_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    let crates_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");

    let config = write_v3_config(
        &npm_server.uri(),
        &osv_server.uri(),
        &crates_server.uri(),
        &go_server.uri(),
        cache_path.to_str().unwrap(),
    );

    // Go proxy: version list
    Mock::given(method("GET"))
        .and(path("/github.com/test/module/@v/list"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(go_version_list(&["v1.0.0", "v1.1.0"])),
        )
        .mount(&go_server)
        .await;

    // Go proxy: version info for latest (v1.1.0), 72h old
    Mock::given(method("GET"))
        .and(path("/github.com/test/module/@v/v1.1.0.info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(go_version_info("v1.1.0", 72)))
        .mount(&go_server)
        .await;

    // OSV: clean
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(osv_clean_response()))
        .mount(&osv_server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "github.com/test/module",
            "--registry",
            "go",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("age: pass"))
        // Go modules have downloads: None, so popularity should pass
        .stdout(predicate::str::contains("popularity: pass"));
}

// =========================================================================
// T-022-07: Low-popularity warning in output
//
// Setup: wiremock serves crates.io JSON with downloads: 5.
// Expected: output contains "popularity" and "5 downloads".
// =========================================================================
#[tokio::test]
async fn low_popularity_warning_in_output() {
    let crates_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");

    let config = write_v3_config_with_popularity(
        &crates_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
        1000,
    );

    // crates.io: crate with very few downloads (5), but 72h old to pass age
    Mock::given(method("GET"))
        .and(path("/api/v1/crates/low-pop-crate"))
        .respond_with(ResponseTemplate::new(200).set_body_string(crates_json(
            "low-pop-crate",
            "0.1.0",
            72,
            5,
        )))
        .mount(&crates_server)
        .await;

    // OSV: clean
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(osv_clean_response()))
        .mount(&osv_server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "low-pop-crate",
            "--registry",
            "crates",
        ])
        .assert()
        // exit 1 because popularity warns, which triggers has_failure
        .code(1)
        .stdout(predicate::str::contains("popularity"))
        .stdout(predicate::str::contains("5 downloads"));
}

// =========================================================================
// T-022-08: JSON output includes all registries (crates.io)
//
// Setup: wiremock serves crates.io JSON.
// Expected: valid JSON with policies array including popularity.
// =========================================================================
#[tokio::test]
async fn json_output_includes_crates_policies() {
    let crates_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    let go_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");

    let config = write_v3_config(
        &npm_server.uri(),
        &osv_server.uri(),
        &crates_server.uri(),
        &go_server.uri(),
        cache_path.to_str().unwrap(),
    );

    // crates.io: established crate, 72h old, 50M downloads
    Mock::given(method("GET"))
        .and(path("/api/v1/crates/json-test-crate"))
        .respond_with(ResponseTemplate::new(200).set_body_string(crates_json(
            "json-test-crate",
            "2.0.0",
            72,
            50_000_000,
        )))
        .mount(&crates_server)
        .await;

    // OSV: clean
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(osv_clean_response()))
        .mount(&osv_server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "json-test-crate",
            "--registry",
            "crates",
            "--json",
        ])
        .output()
        .expect("run dep-scan");

    assert!(
        output.status.success(),
        "Should exit 0 for clean crate, got code {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: Value = serde_json::from_str(&stdout).expect("output should be valid JSON");

    let arr = parsed.as_array().expect("should be a JSON array");
    assert_eq!(arr.len(), 1);

    let entry = &arr[0];
    assert_eq!(entry["package"], "json-test-crate");
    assert_eq!(entry["version"], "2.0.0");
    assert_eq!(entry["registry"], "crates");
    assert_eq!(entry["result"], "pass");

    // Verify the policies array structure
    let policies = entry["policies"]
        .as_array()
        .expect("should have policies array");
    assert!(!policies.is_empty(), "policies array should not be empty");

    // Collect policy names
    let policy_names: Vec<&str> = policies
        .iter()
        .filter_map(|p| p["policy_name"].as_str())
        .collect();

    // Should contain age, popularity, and vulnerability at minimum
    assert!(
        policy_names.contains(&"age"),
        "Should contain age policy, got: {:?}",
        policy_names
    );
    assert!(
        policy_names.contains(&"popularity"),
        "Should contain popularity policy, got: {:?}",
        policy_names
    );
    assert!(
        policy_names.contains(&"vulnerability"),
        "Should contain vulnerability policy, got: {:?}",
        policy_names
    );

    // Every policy entry must have valid structure
    for policy in policies {
        assert!(
            policy["policy_name"].is_string(),
            "policy_name should be a string, got: {:?}",
            policy["policy_name"]
        );
        let result = policy["result"]
            .as_str()
            .expect("result should be a string");
        assert!(
            result == "pass" || result == "warn" || result == "block",
            "result should be pass/warn/block, got: {result}"
        );
        assert!(
            policy["reason"].is_null() || policy["reason"].is_string(),
            "reason should be null or string, got: {:?}",
            policy["reason"]
        );
    }
}

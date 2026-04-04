use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
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

// =========================================================================
// T-024-03: Install blocks on policy violation
//
// Setup: wiremock returns npm JSON for a 1h-old package (fails age policy).
// Run: dep-scan install new-pkg --registry npm (no --force)
// Expected: exit 1, output contains "blocked", package manager NOT invoked.
// =========================================================================
#[tokio::test]
async fn install_blocks_on_policy_violation() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/new-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json("new-pkg", "1.0.0", 1)))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "new-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("BLOCK"))
        .stderr(predicate::str::contains("blocked"));
}

// =========================================================================
// T-024-04: Install with --force proceeds despite violations
//
// Setup: wiremock returns npm JSON for a 1h-old package (fails age policy).
// Run: dep-scan install new-pkg --registry npm --force
// Expected: output contains "Warning" about violations and "Installing".
//           The actual npm exec will likely fail (npm not in PATH in test env),
//           but we verify the scan gate was bypassed.
// =========================================================================
#[tokio::test]
async fn install_with_force_proceeds_despite_violations() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/new-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json("new-pkg", "1.0.0", 1)))
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "new-pkg",
            "--registry",
            "npm",
            "--force",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The scan should detect violations and warn
    assert!(
        stderr.contains("Warning"),
        "stderr should contain 'Warning', got stderr: {stderr}\nstdout: {stdout}"
    );

    // It should attempt to install (print "Installing via npm...")
    assert!(
        stdout.contains("Installing via npm"),
        "stdout should contain 'Installing via npm', got stdout: {stdout}\nstderr: {stderr}"
    );
}

// =========================================================================
// T-024-05: Install succeeds for clean package (command construction)
//
// Setup: wiremock returns npm JSON for a 72h-old clean package.
// Run: dep-scan install clean-pkg --registry npm
// Expected: scan passes. The actual npm exec may fail (npm not in PATH in
//           test env) but we verify the scan passed and the install was
//           attempted.
// =========================================================================
#[tokio::test]
async fn install_succeeds_for_clean_package() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/clean-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "clean-pkg",
            "1.0.0",
            72,
        )))
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "clean-pkg",
            "--registry",
            "npm",
        ])
        .output()
        .expect("run dep-scan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Scan should pass (no "blocked" message)
    assert!(
        !stderr.contains("blocked"),
        "stderr should NOT contain 'blocked', got stderr: {stderr}"
    );

    // Should attempt to install (print "Installing via npm...")
    assert!(
        stdout.contains("Installing via npm"),
        "stdout should contain 'Installing via npm', got stdout: {stdout}\nstderr: {stderr}"
    );

    // The exit code may be 0 (if npm is available) or non-zero (if npm is not installed).
    // We accept either since the point is the scan passed the gate.
}

// =========================================================================
// T-024-06: Install shows scan results before exec
//
// Setup: wiremock returns npm JSON for a clean package.
// Expected: output includes policy results (e.g., "age: pass") before
//           "Installing..." message.
// =========================================================================
#[tokio::test]
async fn install_shows_scan_results_before_exec() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/scan-first-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json(
            "scan-first-pkg",
            "1.0.0",
            72,
        )))
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "scan-first-pkg",
            "--registry",
            "npm",
        ])
        .output()
        .expect("run dep-scan");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Policy results should appear before the "Installing" message
    let age_pos = stdout
        .find("age: pass")
        .expect("should contain 'age: pass' in output");
    let install_pos = stdout
        .find("Installing via npm")
        .expect("should contain 'Installing via npm' in output");

    assert!(
        age_pos < install_pos,
        "Scan results should appear before 'Installing via npm' message. age_pos={age_pos}, install_pos={install_pos}"
    );
}

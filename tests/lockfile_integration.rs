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

/// Write a temporary config file pointing at the given wiremock PyPI URL.
fn write_pypi_config(pypi_url: &str, cache_path: &str) -> NamedTempFile {
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
pypi_url = "{pypi_url}"

[policies]
check_min_age = true
check_typosquatting = false
check_install_scripts = false
check_maintainer_changes = false
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

/// Write a config for npm with lockfile testing.
fn write_npm_config(npm_url: &str, cache_path: &str) -> NamedTempFile {
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
check_typosquatting = false
check_install_scripts = false
check_maintainer_changes = false
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

/// PyPI JSON response for a package published `hours_ago` hours in the past.
fn pypi_json(name: &str, version: &str, hours_ago: i64) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(hours_ago);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "info": {{
        "name": "{name}",
        "version": "{version}",
        "summary": "A test package",
        "home_page": "https://example.com",
        "author": "testuser",
        "maintainer": "testuser"
    }},
    "releases": {{
        "{version}": [
            {{
                "upload_time_iso_8601": "{ts}",
                "filename": "{name}-{version}.tar.gz",
                "packagetype": "sdist"
            }}
        ]
    }}
}}"#
    )
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
// T-023-09: check --lockfile with real fixture (requirements.txt)
//
// Setup: create temp requirements.txt with known packages, wiremock
// Expected: scans all packages from file
// =========================================================================
#[tokio::test]
async fn check_lockfile_requirements_txt() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    // Create a requirements.txt fixture
    let lockfile_path = tmp.path().join("requirements.txt");
    std::fs::write(&lockfile_path, "requests==2.31.0\nflask==3.0.0\n").unwrap();

    // Mock PyPI responses for both packages
    Mock::given(method("GET"))
        .and(path("/pypi/requests/json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(pypi_json("requests", "2.31.0", 72)),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/pypi/flask/json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(pypi_json("flask", "3.0.0", 72)))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lockfile_path.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("requests"))
        .stdout(predicate::str::contains("flask"));
}

// =========================================================================
// T-023-10: check --lockfile combined with explicit packages
//
// Setup: requirements.txt + explicit package on command line
// Expected: scans both lockfile packages and explicit package
// =========================================================================
#[tokio::test]
async fn check_lockfile_combined_with_explicit_packages() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    // Create a requirements.txt with one package
    let lockfile_path = tmp.path().join("requirements.txt");
    std::fs::write(&lockfile_path, "requests==2.31.0\n").unwrap();

    // Mock PyPI responses for lockfile package and explicit package
    Mock::given(method("GET"))
        .and(path("/pypi/requests/json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(pypi_json("requests", "2.31.0", 72)),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/pypi/extra-pkg/json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(pypi_json(
            "extra-pkg",
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
            "--lockfile",
            lockfile_path.to_str().unwrap(),
            "--registry",
            "pypi",
            "extra-pkg",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("requests"))
        .stdout(predicate::str::contains("extra-pkg"));
}

// =========================================================================
// T-023-09b: check --lockfile with package-lock.json
// =========================================================================
#[tokio::test]
async fn check_lockfile_package_lock_json() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_npm_config(&server.uri(), cache_path.to_str().unwrap());

    // Create a package-lock.json fixture
    let lockfile_path = tmp.path().join("package-lock.json");
    std::fs::write(
        &lockfile_path,
        r#"{
            "name": "test-project",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "test-project", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.21" }
            }
        }"#,
    )
    .unwrap();

    // Mock npm response
    Mock::given(method("GET"))
        .and(path("/lodash"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json("lodash", "4.17.21", 72)))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lockfile_path.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("lodash"));
}

// =========================================================================
// T-023-06: --lockfile-type override with non-standard filename
// =========================================================================
#[tokio::test]
async fn check_lockfile_type_override() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    // Create a file with non-standard name but requirements.txt format
    let lockfile_path = tmp.path().join("deps.txt");
    std::fs::write(&lockfile_path, "requests==2.31.0\n").unwrap();

    Mock::given(method("GET"))
        .and(path("/pypi/requests/json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(pypi_json("requests", "2.31.0", 72)),
        )
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lockfile_path.to_str().unwrap(),
            "--lockfile-type",
            "pypi",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("requests"));
}

// =========================================================================
// Check that --lockfile alone (no packages) works
// =========================================================================
#[tokio::test]
async fn check_lockfile_no_explicit_packages() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    let lockfile_path = tmp.path().join("requirements.txt");
    std::fs::write(&lockfile_path, "flask==3.0.0\n").unwrap();

    Mock::given(method("GET"))
        .and(path("/pypi/flask/json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(pypi_json("flask", "3.0.0", 72)))
        .mount(&server)
        .await;

    // No explicit packages -- only --lockfile
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lockfile_path.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("flask"));
}

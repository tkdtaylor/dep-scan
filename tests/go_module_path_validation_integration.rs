//! Integration tests for Go module path validation (task 041, H-5 finding).
//!
//! Covers T-041-21 through T-041-24 from the test spec:
//! CLI exits with code 2 and an informative message when the Go module path
//! contains forbidden characters or path-traversal sequences, and zero HTTP
//! requests are issued.

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

/// Write a minimal config that uses the given Go proxy URL and cache path.
fn write_go_config(go_proxy_url: &str, cache_path: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 0
cache_path = "{cache_path}"

[registries]
go_proxy_url = "{go_proxy_url}"

[policies]
check_min_age = false
check_install_scripts = false
check_maintainer_changes = false
check_typosquatting = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_pypi_provenance = false
check_go_sumdb = false

[popularity]
min_downloads = 0
"#
    )
    .expect("write temp config");
    f
}

/// A minimal Go proxy `/@v/list` response.
fn go_version_list_response() -> String {
    "v1.9.1\n".to_string()
}

/// A minimal Go proxy `/@v/v1.9.1.info` response.
fn go_version_info_response() -> String {
    r#"{"Version":"v1.9.1","Time":"2023-06-15T10:30:00Z"}"#.to_string()
}

// =========================================================================
// T-041-21: `dep-scan check 'github.com/../etc/passwd' --registry go`
//           exits with code 2; wiremock observes zero calls.
// =========================================================================
#[tokio::test]
async fn t041_21_dotdot_path_traversal_rejected_exit2() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_go_config(&server.uri(), cache_path.to_str().unwrap());

    // No routes mounted — any HTTP call would be an unexpected request.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--registry",
            "go",
            "github.com/../etc/passwd",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid Go module path"));

    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "T-041-21: no registry calls should occur when path validation fails"
    );
}

// =========================================================================
// T-041-22: `dep-scan check 'github.com/foo?registry=evil' --registry go`
//           exits with code 2; error names the `?` character.
// =========================================================================
#[tokio::test]
async fn t041_22_question_mark_rejected_exit2() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_go_config(&server.uri(), cache_path.to_str().unwrap());

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--registry",
            "go",
            "github.com/foo?registry=evil",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid Go module path"))
        .stderr(predicate::str::contains("?"));

    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "T-041-22: no registry calls should occur for forbidden `?` character"
    );
}

// =========================================================================
// T-041-23: `dep-scan check 'github.com/gin-gonic/gin' --registry go`
//           succeeds normally when wiremock serves valid Go proxy metadata.
// =========================================================================
#[tokio::test]
async fn t041_23_valid_module_path_succeeds() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_go_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/github.com/gin-gonic/gin/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(go_version_list_response()))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/github.com/gin-gonic/gin/@v/v1.9.1.info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(go_version_info_response()))
        .mount(&server)
        .await;

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--registry",
            "go",
            "github.com/gin-gonic/gin",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("invalid Go module path").not());
}

// =========================================================================
// T-041-24: Error message includes the bad module path verbatim so the user
//           can identify the problem.
// =========================================================================
#[tokio::test]
async fn t041_24_error_message_contains_bad_path_verbatim() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_go_config(&server.uri(), cache_path.to_str().unwrap());

    let bad_path = "github.com/foo#fragment=sneaky";

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--registry",
            "go",
            bad_path,
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(bad_path));

    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "T-041-24: no registry calls should occur for forbidden `#` character"
    );
}

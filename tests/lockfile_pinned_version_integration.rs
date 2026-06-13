/// Integration tests for task 078 — Lockfile scanner uses pinned versions.
///
/// These tests verify that when a lockfile is used, the scanner passes the
/// pinned version to the registry client so that the exact pinned bytes are
/// inspected, not whatever the registry currently serves as "latest".
///
/// For npm, PyPI, and crates the registry URL is the same regardless of version;
/// the version affects which version's data is extracted from the response.
/// For Go the URL changes: /{module}/@v/{version}.info is used for a specific
/// version instead of /@v/list + the "latest" entry.
use std::io::Write;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

/// Minimal config that disables all policies that could trigger on synthetic data.
fn write_minimal_crates_config(crates_url: &str, cache_path: &str) -> NamedTempFile {
    // Escape backslashes so Windows paths (C:\Users\...) are valid TOML basic
    // strings; on Unix this is a no-op. The escaped path round-trips back to the
    // original value after TOML parsing, so stderr-path assertions still match.
    let cache_path = cache_path.replace('\\', "\\\\");
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 0
cache_path = "{cache_path}"

[registries]
crates_url = "{crates_url}"

[policies]
check_min_age = false
check_typosquatting = false
check_install_scripts = false
check_maintainer_changes = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_pypi_provenance = false
check_go_sumdb = false

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write config");
    f
}

fn write_minimal_npm_config(npm_url: &str, cache_path: &str) -> NamedTempFile {
    // Escape backslashes so Windows paths (C:\Users\...) are valid TOML basic
    // strings; on Unix this is a no-op. The escaped path round-trips back to the
    // original value after TOML parsing, so stderr-path assertions still match.
    let cache_path = cache_path.replace('\\', "\\\\");
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
check_typosquatting = false
check_install_scripts = false
check_maintainer_changes = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_pypi_provenance = false
check_go_sumdb = false

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write config");
    f
}

fn write_minimal_pypi_config(pypi_url: &str, cache_path: &str) -> NamedTempFile {
    // Escape backslashes so Windows paths (C:\Users\...) are valid TOML basic
    // strings; on Unix this is a no-op. The escaped path round-trips back to the
    // original value after TOML parsing, so stderr-path assertions still match.
    let cache_path = cache_path.replace('\\', "\\\\");
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 0
cache_path = "{cache_path}"

[registries]
pypi_url = "{pypi_url}"

[policies]
check_min_age = false
check_typosquatting = false
check_install_scripts = false
check_maintainer_changes = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_pypi_provenance = false
check_go_sumdb = false

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write config");
    f
}

fn write_minimal_go_config(go_proxy_url: &str, cache_path: &str) -> NamedTempFile {
    // Escape backslashes so Windows paths (C:\Users\...) are valid TOML basic
    // strings; on Unix this is a no-op. The escaped path round-trips back to the
    // original value after TOML parsing, so stderr-path assertions still match.
    let cache_path = cache_path.replace('\\', "\\\\");
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 0
cache_path = "{cache_path}"

[registries]
go_proxy_url = "{go_proxy_url}"
go_sum_db_url = "https://sum.golang.org"

[policies]
check_min_age = false
check_typosquatting = false
check_install_scripts = false
check_maintainer_changes = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_pypi_provenance = false
check_go_sumdb = false

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write config");
    f
}

/// A minimal crates.io JSON response containing two versions.
/// The "pinned" version 1.0.0 has a known age (100 hours old).
/// The "latest" version 1.0.1 has a different publish date.
fn crates_json_two_versions() -> String {
    let old_ts = (chrono::Utc::now() - chrono::TimeDelta::hours(100))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let new_ts = (chrono::Utc::now() - chrono::TimeDelta::hours(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
          "crate": {{
            "name": "serde",
            "max_version": "1.0.1",
            "description": "Serialization framework",
            "downloads": 100000,
            "repository": "https://github.com/serde-rs/serde",
            "created_at": "{old_ts}"
          }},
          "versions": [
            {{
              "num": "1.0.1",
              "created_at": "{new_ts}",
              "published_by": {{ "login": "dtolnay", "name": "David Tolnay" }},
              "cksum": "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
            }},
            {{
              "num": "1.0.0",
              "created_at": "{old_ts}",
              "published_by": {{ "login": "dtolnay", "name": "David Tolnay" }},
              "cksum": "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
            }}
          ]
        }}"#
    )
}

/// A minimal npm JSON response containing two versions.
fn npm_json_two_versions(name: &str) -> String {
    let old_ts = (chrono::Utc::now() - chrono::TimeDelta::hours(100))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let new_ts = (chrono::Utc::now() - chrono::TimeDelta::hours(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
          "name": "{name}",
          "description": "A test package",
          "dist-tags": {{ "latest": "4.17.21" }},
          "versions": {{
            "4.17.21": {{
              "name": "{name}",
              "version": "4.17.21",
              "description": "A test package"
            }},
            "4.17.20": {{
              "name": "{name}",
              "version": "4.17.20",
              "description": "A test package"
            }}
          }},
          "time": {{
            "4.17.21": "{new_ts}",
            "4.17.20": "{old_ts}"
          }},
          "maintainers": [{{ "name": "testuser", "email": "test@example.com" }}]
        }}"#
    )
}

/// A minimal PyPI JSON response with two versions.
fn pypi_json_two_versions(name: &str) -> String {
    let old_ts = (chrono::Utc::now() - chrono::TimeDelta::hours(100))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let new_ts = (chrono::Utc::now() - chrono::TimeDelta::hours(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
          "info": {{
            "name": "{name}",
            "version": "2.32.0",
            "summary": "A test package",
            "author": "testuser",
            "maintainer": null,
            "home_page": "https://example.com"
          }},
          "releases": {{
            "2.32.0": [
              {{
                "filename": "{name}-2.32.0.tar.gz",
                "packagetype": "sdist",
                "upload_time_iso_8601": "{new_ts}",
                "digests": {{ "sha256": "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000" }}
              }}
            ],
            "2.31.0": [
              {{
                "filename": "{name}-2.31.0.tar.gz",
                "packagetype": "sdist",
                "upload_time_iso_8601": "{old_ts}",
                "digests": {{ "sha256": "bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111" }}
              }}
            ]
          }}
        }}"#
    )
}

// =========================================================================
// T-078-08: Crates registry receives the pinned version
//
// The Cargo.lock pins serde@1.0.0. The registry response contains both
// 1.0.0 and 1.0.1. The JSON output's `version` field MUST be "1.0.0" (the
// lockfile-pinned value), not "1.0.1" (the registry "latest").
// =========================================================================
#[tokio::test]
async fn t078_08_crates_registry_uses_pinned_version() {
    // T-078-08
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_minimal_crates_config(&server.uri(), cache_path.to_str().unwrap());

    // Lockfile pins serde@1.0.0
    let lockfile = tmp.path().join("Cargo.lock");
    std::fs::write(
        &lockfile,
        r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
"#,
    )
    .unwrap();

    Mock::given(method("GET"))
        .and(path("/api/v1/crates/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(crates_json_two_versions()))
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--lockfile-type",
            "crates",
            "--json",
        ])
        .output()
        .expect("run dep-scan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse failed: {e}\nstdout: {stdout}"));

    let packages = json.as_array().expect("JSON is array");
    let serde_pkg = packages
        .iter()
        .find(|p| p["package"].as_str() == Some("serde"))
        .expect("serde in results");

    let reported_version = serde_pkg["version"].as_str().unwrap_or("");
    assert_eq!(
        reported_version, "1.0.0",
        "T-078-08: reported version must be the lockfile-pinned '1.0.0', got '{reported_version}'"
    );
}

// =========================================================================
// T-078-09: npm registry receives the pinned version
//
// The package-lock.json pins lodash@4.17.20. The registry response has both
// 4.17.20 and 4.17.21. The JSON output's `version` MUST be "4.17.20".
// =========================================================================
#[tokio::test]
async fn t078_09_npm_registry_uses_pinned_version() {
    // T-078-09
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_minimal_npm_config(&server.uri(), cache_path.to_str().unwrap());

    // package-lock.json pins lodash@4.17.20
    let lockfile = tmp.path().join("package-lock.json");
    std::fs::write(
        &lockfile,
        r#"{
          "name": "test-project",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "test-project", "version": "1.0.0" },
            "node_modules/lodash": { "version": "4.17.20" }
          }
        }"#,
    )
    .unwrap();

    Mock::given(method("GET"))
        .and(path("/lodash"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json_two_versions("lodash")))
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run dep-scan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse failed: {e}\nstdout: {stdout}"));

    let packages = json.as_array().expect("JSON is array");
    let lodash_pkg = packages
        .iter()
        .find(|p| p["package"].as_str() == Some("lodash"))
        .expect("lodash in results");

    let reported_version = lodash_pkg["version"].as_str().unwrap_or("");
    assert_eq!(
        reported_version, "4.17.20",
        "T-078-09: reported version must be the lockfile-pinned '4.17.20', got '{reported_version}'"
    );
}

// =========================================================================
// T-078-10: PyPI registry receives the pinned version
//
// requirements.txt pins requests==2.31.0. The registry response has both
// 2.31.0 and 2.32.0. The JSON output's `version` MUST be "2.31.0".
// =========================================================================
#[tokio::test]
async fn t078_10_pypi_registry_uses_pinned_version() {
    // T-078-10
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_minimal_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    // requirements.txt pins requests==2.31.0
    let lockfile = tmp.path().join("requirements.txt");
    std::fs::write(&lockfile, "requests==2.31.0\n").unwrap();

    Mock::given(method("GET"))
        .and(path("/pypi/requests/json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(pypi_json_two_versions("requests")),
        )
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run dep-scan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse failed: {e}\nstdout: {stdout}"));

    let packages = json.as_array().expect("JSON is array");
    let requests_pkg = packages
        .iter()
        .find(|p| p["package"].as_str() == Some("requests"))
        .expect("requests in results");

    let reported_version = requests_pkg["version"].as_str().unwrap_or("");
    assert_eq!(
        reported_version, "2.31.0",
        "T-078-10: reported version must be lockfile-pinned '2.31.0', got '{reported_version}'"
    );
}

// =========================================================================
// T-078-11: Go proxy receives the pinned version
//
// go.sum pins github.com/gin-gonic/gin@v1.9.1. The Go registry client
// calls /{module}/@v/{version}.info when version is provided. This test
// verifies the mock receives a request to that specific endpoint, not the
// version list endpoint (/@v/list).
// =========================================================================
#[tokio::test]
async fn t078_11_go_proxy_uses_pinned_version_url() {
    // T-078-11
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_minimal_go_config(&server.uri(), cache_path.to_str().unwrap());

    // go.sum pins github.com/gin-gonic/gin at v1.9.1
    let lockfile = tmp.path().join("go.sum");
    std::fs::write(
        &lockfile,
        "github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=\n\
         github.com/gin-gonic/gin v1.9.1/go.mod h1:hPys6ity2QU7q1i6v0a9ItZhf6Rv9JjqTTm7SoE7D4=\n",
    )
    .unwrap();

    // The Go proxy client calls /{module}/@v/{version}.info when version is provided.
    // Verify that the mock receives a request to the versioned endpoint.
    let version_info = r#"{"Version": "v1.9.1", "Time": "2023-06-12T00:00:00Z"}"#;
    Mock::given(method("GET"))
        .and(path("/github.com/gin-gonic/gin/@v/v1.9.1.info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(version_info))
        .expect(1) // T-078-11: exactly one request to the versioned endpoint
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run dep-scan");

    // The mock's expect(1) assertion fires on drop — but we also verify version in output.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse failed: {e}\nstdout: {stdout}"));

    let packages = json.as_array().expect("JSON is array");
    let gin_pkg = packages
        .iter()
        .find(|p| p["package"].as_str() == Some("github.com/gin-gonic/gin"))
        .expect("gin in results");

    let reported_version = gin_pkg["version"].as_str().unwrap_or("");
    assert_eq!(
        reported_version, "v1.9.1",
        "T-078-11: reported version must be pinned 'v1.9.1', got '{reported_version}'"
    );
    // If the mock did NOT receive a request to the versioned URL, wiremock would panic on drop.
}

// =========================================================================
// T-078-12: CLI-arg scan still queries latest (no regression)
//
// When a package is specified via CLI arg (not lockfile), no version is
// passed, so the registry should serve "latest". For crates, the first
// version in the response is "latest" (1.0.1). The JSON output MUST
// report "1.0.1", not "1.0.0".
// =========================================================================
#[tokio::test]
async fn t078_12_cli_arg_scan_queries_latest() {
    // T-078-12
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_minimal_crates_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/api/v1/crates/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(crates_json_two_versions()))
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "serde",
            "--registry",
            "crates",
            "--json",
        ])
        .output()
        .expect("run dep-scan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse failed: {e}\nstdout: {stdout}"));

    let packages = json.as_array().expect("JSON is array");
    let serde_pkg = packages
        .iter()
        .find(|p| p["package"].as_str() == Some("serde"))
        .expect("serde in results");

    // CLI arg with no version → should get "latest" (first in list = 1.0.1)
    let reported_version = serde_pkg["version"].as_str().unwrap_or("");
    assert_eq!(
        reported_version, "1.0.1",
        "T-078-12: CLI-arg scan must query latest (1.0.1), got '{reported_version}'"
    );
}

// =========================================================================
// T-078-13: Verbose log line includes version when known
//
// When scanning from a lockfile with a pinned version, the verbose log
// line must include the version: "Checking serde@1.0.0 on crates...".
// =========================================================================
#[tokio::test]
async fn t078_13_verbose_log_includes_version_when_known() {
    // T-078-13
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_minimal_crates_config(&server.uri(), cache_path.to_str().unwrap());

    let lockfile = tmp.path().join("Cargo.lock");
    std::fs::write(
        &lockfile,
        r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
"#,
    )
    .unwrap();

    Mock::given(method("GET"))
        .and(path("/api/v1/crates/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(crates_json_two_versions()))
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--lockfile-type",
            "crates",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Checking serde@1.0.0 on crates"),
        "T-078-13: verbose stderr must contain 'Checking serde@1.0.0 on crates', got:\n{stderr}"
    );
}

// =========================================================================
// T-078-14: Verbose log line omits version when unknown (CLI arg path)
//
// When scanning a package supplied via CLI arg (no pinned version), the
// verbose log must NOT include "@<version>" — it should be "Checking serde
// on crates..." without any @ suffix.
// =========================================================================
#[tokio::test]
async fn t078_14_verbose_log_omits_version_for_cli_arg() {
    // T-078-14
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_minimal_crates_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/api/v1/crates/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(crates_json_two_versions()))
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "serde",
            "--registry",
            "crates",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Must contain "Checking serde on crates" (without @version)
    assert!(
        stderr.contains("Checking serde on crates"),
        "T-078-14: verbose stderr must contain 'Checking serde on crates', got:\n{stderr}"
    );
    // Must NOT contain "Checking serde@" (with @ version)
    assert!(
        !stderr.contains("Checking serde@"),
        "T-078-14: verbose stderr must NOT contain 'Checking serde@', got:\n{stderr}"
    );
}

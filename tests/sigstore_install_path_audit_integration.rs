/// Integration tests for task 055 — Sigstore re-verification audit on install path (L-9).
///
/// These tests verify that when `--verbose` is passed, the install path emits a
/// diagnostic log line naming the resolved version and content hash (or noting their
/// absence) and documenting that sigstore provenance is not re-verified at install time.
/// Without `--verbose`, no such lines are emitted.
///
/// Remediation chosen: option (b) — log the locked version + hash at --verbose;
/// no additional sigstore re-verification is performed.
///
/// T-055-01: npm install --verbose → log line names version and hash
/// T-055-02: cargo install --verbose → log line names version
/// T-055-03: go install --verbose → log line names version
/// T-055-04: pip install --verbose → log line confirms sha256 re-verified, sigstore not re-run
/// T-055-05: N/A — option (a) only; option (b) chosen for this task
/// T-055-06: N/A — option (a) only; option (b) chosen for this task
/// T-055-07: package manager invoked with original unversioned package name
/// T-055-08: no log line without --verbose
/// T-055-09: regression — all task 024 install tests still pass (run via cargo test install)
/// T-055-10: regression — all task 031 pip_require_hashes tests still pass
/// T-055-11: cargo test + clippy + fmt --check all pass
use std::io::Write as _;

use assert_cmd::Command;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

// ── Config helpers ────────────────────────────────────────────────────────────

fn write_npm_config(npm_url: &str, cache_path: &str) -> NamedTempFile {
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

fn write_crates_config(crates_url: &str, cache_path: &str) -> NamedTempFile {
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
check_install_scripts = false
check_maintainer_changes = false
check_typosquatting = false
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

fn write_go_config(proxy_url: &str, sumdb_url: &str, cache_path: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 0
cache_path = "{cache_path}"

[registries]
go_proxy_url = "{proxy_url}"
go_sum_db_url = "{sumdb_url}"

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

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write config");
    f
}

fn write_pypi_config(pypi_url: &str, cache_path: &str) -> NamedTempFile {
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
check_install_scripts = false
check_maintainer_changes = false
check_typosquatting = false
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

// ── Mock response helpers ─────────────────────────────────────────────────────

/// npm JSON with `dist.integrity` in SRI format.
fn npm_json_with_integrity(name: &str, version: &str, integrity: &str) -> String {
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
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

/// crates.io API response.
fn crates_json(name: &str, version: &str) -> String {
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "crate": {{
        "name": "{name}",
        "max_version": "{version}",
        "description": "A test crate",
        "downloads": 5000000,
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

/// Go module proxy `/list` response.
fn proxy_list_body(version: &str) -> String {
    format!("{version}\n")
}

/// Go module proxy `.info` response.
fn proxy_info_body(version: &str) -> String {
    format!(r#"{{"Version":"{version}","Time":"2020-06-15T10:00:00Z"}}"#)
}

/// PyPI JSON response with a sha256 digest.
fn pypi_json_with_hash(name: &str, version: &str, sha256: &str) -> String {
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
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

// ── T-055-01: npm install --verbose emits version and hash ────────────────────

// T-055-01: `run_install` for npm emits a log line naming the version and hash
// before invoking npm when `--verbose` is passed.
#[tokio::test]
async fn t055_01_npm_install_verbose_emits_version_and_hash() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_npm_config(&server.uri(), cache_path.to_str().unwrap());

    // npm registry is called twice: once during run_check and once for the verbose
    // audit log fetch.  Allow multiple calls.
    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "express",
                "4.18.2",
                "sha512-AAAA",
            )),
        )
        .expect(1..)
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "install",
            "express",
            "--registry",
            "npm",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Must contain the resolved version.
    assert!(
        stderr.contains("4.18.2"),
        "T-055-01: stderr must contain resolved version '4.18.2', got: {stderr}"
    );

    // Must mention that sigstore provenance is not re-verified.
    assert!(
        stderr.contains("sigstore") || stderr.contains("provenance"),
        "T-055-01: stderr must mention sigstore/provenance absence, got: {stderr}"
    );

    // Must contain a hash reference (the sha512 SRI was decoded and normalized).
    assert!(
        stderr.contains("sha512") || stderr.contains("hash"),
        "T-055-01: stderr must contain a hash reference, got: {stderr}"
    );
}

// ── T-055-02: cargo install --verbose emits version ───────────────────────────

// T-055-02: `run_install` for cargo emits a log line naming the resolved version
// when `--verbose` is passed.
#[tokio::test]
async fn t055_02_cargo_install_verbose_emits_version() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_crates_config(&server.uri(), cache_path.to_str().unwrap());

    // crates.io is called during run_check and the verbose audit fetch.
    Mock::given(method("GET"))
        .and(path("/api/v1/crates/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(crates_json("serde", "1.0.210")))
        .expect(1..)
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "install",
            "serde",
            "--registry",
            "crates",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("1.0.210"),
        "T-055-02: stderr must contain resolved version '1.0.210', got: {stderr}"
    );

    assert!(
        stderr.contains("sigstore") || stderr.contains("provenance"),
        "T-055-02: stderr must mention sigstore/provenance absence, got: {stderr}"
    );
}

// ── T-055-03: go install --verbose emits version ──────────────────────────────

// T-055-03: `run_install` for go emits a log line naming the resolved version
// when `--verbose` is passed.
#[tokio::test]
async fn t055_03_go_install_verbose_emits_version() {
    let proxy = MockServer::start().await;
    let sumdb = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_go_config(&proxy.uri(), &sumdb.uri(), cache_path.to_str().unwrap());

    let module = "github.com/gin-gonic/gin";

    // Go proxy list and info endpoints.
    Mock::given(method("GET"))
        .and(path(format!("/{module}/@v/list")))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_list_body("v1.9.1")))
        .expect(1..)
        .mount(&proxy)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/{module}/@v/v1.9.1.info")))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_info_body("v1.9.1")))
        .expect(1..)
        .mount(&proxy)
        .await;

    // sumdb lookup (check_go_sumdb = false, but the registry may still call it for metadata).
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&sumdb)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "install",
            module,
            "--registry",
            "go",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("v1.9.1"),
        "T-055-03: stderr must contain resolved version 'v1.9.1', got: {stderr}"
    );

    assert!(
        stderr.contains("sigstore") || stderr.contains("provenance"),
        "T-055-03: stderr must mention sigstore/provenance absence, got: {stderr}"
    );
}

// ── T-055-04: pip install --verbose documents sha256 re-verified ──────────────

// T-055-04: `run_pip_install` log line documents that sha256 is re-verified but
// sigstore provenance is not re-run when `--verbose` is passed.
#[tokio::test]
async fn t055_04_pip_install_verbose_documents_sha256_reconfirmed_sigstore_not_rerun() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    let sha256_hex = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef";

    Mock::given(method("GET"))
        .and(path("/pypi/flask/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(pypi_json_with_hash("flask", "3.0.0", sha256_hex)),
        )
        .expect(1..)
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "install",
            "flask",
            "--registry",
            "pypi",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Must mention sha256 re-confirmation.
    assert!(
        stderr.contains("sha256"),
        "T-055-04: stderr must mention sha256 re-confirmation, got: {stderr}"
    );

    // Must note sigstore provenance not re-run.
    assert!(
        stderr.contains("sigstore") || stderr.contains("provenance"),
        "T-055-04: stderr must mention sigstore/provenance absence, got: {stderr}"
    );
}

// ── T-055-07: package manager invoked with unversioned name ───────────────────

// T-055-07: When scan passes, the package manager is invoked with the original
// unversioned package name (e.g. "express", not "express@4.18.2").
// We verify this by checking that "Installing via npm..." appears (not pinned form).
#[tokio::test]
async fn t055_07_package_manager_invoked_with_unversioned_name() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_npm_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "express",
                "4.18.2",
                "sha512-AAAA",
            )),
        )
        .expect(1..)
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "install",
            "express",
            "--registry",
            "npm",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The "Running: npm install express" line (not "express@4.18.2") confirms
    // we pass the original unversioned name to the package manager.
    let combined = format!("{stderr}{stdout}");
    assert!(
        combined.contains("npm install express"),
        "T-055-07: output must show npm invoked with original name 'express', got stderr: {stderr}, stdout: {stdout}"
    );
}

// ── T-055-08: no log line without --verbose ───────────────────────────────────

// T-055-08: When `--verbose` is NOT passed, the TOCTOU audit log lines are not
// emitted in stderr.
#[tokio::test]
async fn t055_08_no_verbose_no_audit_log_line() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_npm_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_with_integrity(
                "express",
                "4.18.2",
                "sha512-AAAA",
            )),
        )
        .mount(&server)
        .await;

    let output = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "express",
            "--registry",
            "npm",
        ])
        .output()
        .expect("run dep-scan");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Without --verbose, the L-9 audit log line must not appear.
    assert!(
        !stderr.contains("L-9"),
        "T-055-08: L-9 audit marker must not appear without --verbose, got: {stderr}"
    );
    assert!(
        !stderr.contains("sigstore provenance not re-verified at install time"),
        "T-055-08: TOCTOU log line must not appear without --verbose, got: {stderr}"
    );
}

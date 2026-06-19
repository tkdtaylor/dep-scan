// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]
/// Integration tests for task 042 — TempReqFile symlink / predictable-name hardening.
///
/// Tests T-042-11 and T-042-13: verify that the temp requirements file is
/// cleaned up after a successful pip install (with wiremock) and when pip is
/// not found in PATH.
use std::io::Write;

use assert_cmd::Command;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

/// Write a minimal config file pointing at the given PyPI mock URL and cache path.
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

/// PyPI JSON response for a package that passes the age policy (published 72h ago)
/// and includes a sha256 digest.
fn pypi_json_with_hash(name: &str, version: &str, sha256: &str) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(72);
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

/// Create a mock pip script that exits 0 and records its argv.
/// Returns the bin directory path (kept alive by the caller's TempDir).
fn create_mock_pip(tmp: &TempDir) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let bin_dir = tmp.path().join("mock-bin");
    std::fs::create_dir_all(&bin_dir).expect("create mock bin dir");

    let argv_file = tmp.path().join("pip-argv.txt");
    let argv_path_str = argv_file.to_str().expect("utf8").to_string();

    let script = format!(
        r#"#!/bin/sh
printf "" > "{argv_path_str}"
for arg in "$@"; do
    echo "$arg" >> "{argv_path_str}"
done
exit 0
"#
    );

    let pip_path = bin_dir.join("pip");
    std::fs::write(&pip_path, &script).expect("write mock pip");
    let mut perms = std::fs::metadata(&pip_path)
        .expect("metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&pip_path, perms).expect("set permissions");

    bin_dir
}

/// Return all dep-scan-*.txt files in the given directory.
fn find_dep_scan_temp_files_in(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .expect("read temp dir")
        .filter_map(|entry| {
            let e = entry.ok()?;
            let name = e.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("dep-scan-") && s.ends_with(".txt") {
                Some(e.path())
            } else {
                None
            }
        })
        .collect()
}

// ── T-042-11 ──────────────────────────────────────────────────────────────────
//
// After `dep-scan install flask --registry pypi` exits (successfully, with a
// mock pip), no dep-scan-*.txt files should remain in the temp directory.
//
// We redirect TMPDIR to a private directory so the test is not sensitive to
// other tests concurrently creating dep-scan temp files in the shared /tmp.
#[tokio::test]
async fn temp_file_cleaned_up_after_successful_pip_run() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    // Private TMPDIR — isolates this test from parallel runs that also write
    // dep-scan-*.txt files to the shared /tmp.
    let private_tmp = tmp.path().join("private-tmp");
    std::fs::create_dir_all(&private_tmp).expect("create private tmp dir");

    let sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    Mock::given(method("GET"))
        .and(path("/pypi/flask/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(pypi_json_with_hash("flask", "3.0.0", sha256)),
        )
        .mount(&server)
        .await;

    let bin_dir = create_mock_pip(&tmp);
    let original_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{original_path}", bin_dir.display());

    dep_scan()
        .env("PATH", &new_path)
        .env("TMPDIR", &private_tmp) // dep-scan uses std::env::temp_dir() → respects TMPDIR
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "flask",
            "--registry",
            "pypi",
        ])
        .assert()
        .code(0);

    // After run: private TMPDIR must contain no dep-scan-*.txt files.
    let leftover = find_dep_scan_temp_files_in(&private_tmp);
    assert!(
        leftover.is_empty(),
        "T-042-11: dep-scan temp files left in {:?} after process exit: {leftover:?}",
        private_tmp
    );
}

// ── T-042-13 ──────────────────────────────────────────────────────────────────
//
// If pip is not available in PATH, the temp file must still be cleaned up.
//
// We redirect TMPDIR to a private directory so the test is not sensitive to
// other tests concurrently creating dep-scan temp files in the shared /tmp.
#[tokio::test]
async fn temp_file_cleaned_up_when_pip_not_found() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_pypi_config(&server.uri(), cache_path.to_str().unwrap());

    // Private TMPDIR — isolates this test from parallel runs.
    let private_tmp = tmp.path().join("private-tmp");
    std::fs::create_dir_all(&private_tmp).expect("create private tmp dir");

    let sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    Mock::given(method("GET"))
        .and(path("/pypi/flask/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(pypi_json_with_hash("flask", "3.0.0", sha256)),
        )
        .mount(&server)
        .await;

    // Use an empty directory as PATH so pip cannot be found.
    let empty_bin = tmp.path().join("empty-bin");
    std::fs::create_dir_all(&empty_bin).expect("create empty bin dir");

    // The run will fail (pip not found) but must not leave temp files behind.
    let _output = dep_scan()
        .env("PATH", empty_bin.to_str().unwrap())
        .env("TMPDIR", &private_tmp) // dep-scan uses std::env::temp_dir() → respects TMPDIR
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "install",
            "flask",
            "--registry",
            "pypi",
        ])
        .output()
        .expect("run dep-scan (pip-not-found path)");
    // We don't assert the exit code — it may be 0 or non-zero depending on
    // how dep-scan handles the pip-not-found error.  The important assertion
    // is that no temp file was left behind.

    let leftover = find_dep_scan_temp_files_in(&private_tmp);
    assert!(
        leftover.is_empty(),
        "T-042-13: dep-scan temp files left in {:?} when pip was not found: {leftover:?}",
        private_tmp
    );
}

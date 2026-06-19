// SPDX-License-Identifier: Apache-2.0
//! Task 087 — fail-closed behavior for signed interchange output at the binary
//! level (T-087-15) plus the offline operator-key happy path (T-087-16) and the
//! `--allow-unsigned` escape hatch.
//!
//! These exercise the live `run_check` output dispatch, which task 087 changed
//! from an ephemeral per-run signer to `resolve_signer`:
//!   - offline + no `signing.key_path` + signed `--format osv` → exit 2, a
//!     message naming `signing.key_path` and `--allow-unsigned`, and NO output
//!     on stdout (REQ-087-05, fail closed);
//!   - offline + `signing.key_path` set → a DSSE envelope is emitted (exit 0);
//!   - offline + no key + `--allow-unsigned` → raw unsigned-marked output.

use std::io::Write;

use assert_cmd::Command;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use predicates::prelude::*;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

/// crates.io response for an established crate (72h old, lots of downloads) so
/// the scan itself produces a clean PASS (exit code is then governed by the
/// signing path, not a scan error).
fn crates_json(name: &str, version: &str) -> String {
    let published = chrono::Utc::now() - chrono::TimeDelta::hours(72);
    let ts = published.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    format!(
        r#"{{
    "crate": {{
        "name": "{name}",
        "max_version": "{version}",
        "description": "A test crate",
        "downloads": 50000000,
        "repository": "https://github.com/test/{name}",
        "created_at": "{ts}"
    }},
    "versions": [
        {{ "num": "{version}", "created_at": "{ts}",
           "published_by": {{ "login": "testuser", "name": "Test User" }} }}
    ]
}}"#
    )
}

/// Write a config pointed at the stub crates/osv servers, with the optional
/// `[signing]` body appended verbatim.
fn write_config(crates_url: &str, osv_url: &str, cache_path: &str, signing: &str) -> NamedTempFile {
    // Escape backslashes so Windows paths (C:\Users\...) are valid TOML basic
    // strings; on Unix this is a no-op. The escaped path round-trips back to the
    // original value after TOML parsing, so stderr-path assertions still match.
    // (The `signing` fragment is escaped at its source by the caller.)
    let cache_path = cache_path.replace('\\', "\\\\");
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
check_pypi_provenance = false
check_go_sumdb = false

[osv]
osv_url = "{osv_url}"

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 1000

{signing}
"#
    )
    .expect("write temp config");
    f
}

async fn stub_servers() -> (MockServer, MockServer) {
    let crates_server = MockServer::start().await;
    let osv_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/crates/test-crate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(crates_json("test-crate", "1.0.0")),
        )
        .mount(&crates_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&osv_server)
        .await;
    (crates_server, osv_server)
}

// T-087-15: offline + no key_path + signed format → exit 2, fail-closed message,
// no output on stdout.
#[tokio::test]
async fn t_087_15_offline_no_key_signed_format_fails_closed() {
    let (crates_server, osv_server) = stub_servers().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    // [signing] present but key_path empty.
    let config = write_config(
        &crates_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
        "[signing]\noffline = true\nkey_path = \"\"",
    );

    dep_scan()
        .env("DEP_SCAN_OFFLINE", "1")
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "test-crate",
            "--registry",
            "crates",
            "--format",
            "osv",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("signing.key_path"))
        .stderr(predicate::str::contains("--allow-unsigned"))
        // No DSSE envelope and no unsigned-marked payload leaked to stdout.
        .stdout(predicate::str::contains("payloadType").not())
        .stdout(predicate::str::contains("_dep_scan_unsigned").not());
}

// T-087-15 (cont.): the same fail-closed case but with --allow-unsigned →
// the run succeeds and emits raw output carrying the unsigned marker.
#[tokio::test]
async fn t_087_15_allow_unsigned_is_the_escape_hatch() {
    let (crates_server, osv_server) = stub_servers().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_config(
        &crates_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
        "[signing]\noffline = true",
    );

    dep_scan()
        .env("DEP_SCAN_OFFLINE", "1")
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "test-crate",
            "--registry",
            "crates",
            "--format",
            "osv",
            "--allow-unsigned",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("_dep_scan_unsigned"));
}

// T-087-16: offline + operator key_path set → a DSSE envelope is emitted (exit 0).
#[tokio::test]
async fn t_087_16_offline_operator_key_signs() {
    let (crates_server, osv_server) = stub_servers().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");

    // Generate an operator key into the tempdir (NEVER committed).
    use rand_core::OsRng;
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pem = sk
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .expect("pem")
        .to_string();
    let key_path = tmp.path().join("operator-key.pem");
    std::fs::write(&key_path, pem).unwrap();

    let signing = format!(
        "[signing]\noffline = true\nkey_path = \"{}\"",
        // Escape backslashes so Windows paths are valid TOML basic strings; no-op on Unix.
        key_path.to_str().unwrap().replace('\\', "\\\\")
    );
    let config = write_config(
        &crates_server.uri(),
        &osv_server.uri(),
        cache_path.to_str().unwrap(),
        &signing,
    );

    dep_scan()
        .env("DEP_SCAN_OFFLINE", "1")
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "test-crate",
            "--registry",
            "crates",
            "--format",
            "osv",
        ])
        .assert()
        .code(0)
        // A DSSE envelope: payloadType + signatures, and NOT the unsigned marker.
        .stdout(predicate::str::contains("payloadType"))
        .stdout(predicate::str::contains("signatures"))
        .stdout(predicate::str::contains("_dep_scan_unsigned").not());
}

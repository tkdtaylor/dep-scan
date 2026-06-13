/// Integration tests for task 061 — Verbose-gate parse_tlog_entries diagnostic.
///
/// T-061-10: dep-scan check pkg --registry npm (no --verbose) with a malformed
///   tlog entry suppresses the "skipping malformed tlog entry" diagnostic on
///   stderr.
/// T-061-11: dep-scan check pkg --registry npm --verbose with a malformed tlog
///   entry emits the "skipping malformed tlog entry" diagnostic on stderr.
/// T-061-14: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
///   `cargo fmt --check` all pass — verified as part of the pre-commit gate
///   (see CLAUDE.md pre-commit verification gate).
use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

fn write_npm_provenance_config(npm_url: &str, cache_path: &str) -> NamedTempFile {
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
check_install_scripts = false
check_maintainer_changes = false
check_typosquatting = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = true
require_npm_provenance = false

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write config");
    f
}

fn npm_json_stub(name: &str, version: &str) -> String {
    format!(
        r#"{{
    "name": "{name}",
    "description": "Test package",
    "dist-tags": {{ "latest": "{version}" }},
    "versions": {{
        "{version}": {{
            "name": "{name}",
            "version": "{version}",
            "description": "Test package",
            "dist": {{
                "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "shasum": "0000000000000000000000000000000000000000"
            }}
        }}
    }},
    "time": {{ "{version}": "2020-01-01T00:00:00.000Z" }},
    "maintainers": [{{ "name": "testuser" }}]
}}"#
    )
}

/// Build an attestation response JSON where one tlogEntries element is missing
/// `treeSize`. This is the malformed entry shape that triggers the diagnostic.
fn attestation_json_with_malformed_tlog() -> String {
    r#"{
    "attestations": [
        {
            "predicateType": "https://slsa.dev/provenance/v1",
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
                "verificationMaterial": {
                    "x509CertificateChain": {
                        "certificates": [{ "rawBytes": "MIIB..." }]
                    },
                    "tlogEntries": [
                        {
                            "logIndex": 12345,
                            "integratedTime": 1716300000,
                            "logId": { "keyId": "wNI9atQ=" },
                            "kindVersion": { "kind": "intoto", "version": "0.0.2" },
                            "canonicalizedBody": "e30=",
                            "inclusionProof": {
                                "logIndex": 12345,
                                "rootHash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                "hashes": []
                            }
                        }
                    ],
                    "timestampVerificationData": { "rfc3161Timestamps": [] }
                },
                "dsseEnvelope": {
                    "payload": "e30K",
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [{ "sig": "MEYCIQCY+TSB151Y=", "keyid": "" }]
                }
            }
        }
    ]
}"#
    .to_string()
}

// ---------------------------------------------------------------------------
// T-061-10: No --verbose suppresses the tlog diagnostic
// ---------------------------------------------------------------------------

/// T-061-10: When run without --verbose and the attestation response contains a
/// malformed tlog entry (missing treeSize), the binary must NOT emit
/// "skipping malformed tlog entry" on stderr.
#[tokio::test]
async fn t_061_10_no_verbose_suppresses_tlog_diagnostic() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_npm_provenance_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/test-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_stub("test-pkg", "1.0.0")),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/-/npm/v1/attestations/test-pkg@1.0.0"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(attestation_json_with_malformed_tlog()),
        )
        .mount(&server)
        .await;

    // Run without --verbose; stderr must not contain the tlog diagnostic.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "test-pkg",
            "--registry",
            "npm",
            // No --verbose flag
        ])
        .assert()
        .stderr(
            predicate::str::contains("skipping malformed tlog entry")
                .not()
                .and(predicate::str::contains("treeSize").not()),
        );
}

// ---------------------------------------------------------------------------
// T-061-11: --verbose emits the tlog diagnostic
// ---------------------------------------------------------------------------

/// T-061-11: When run with --verbose and the attestation response contains a
/// malformed tlog entry (missing treeSize), the binary MUST emit
/// "skipping malformed tlog entry" on stderr.
#[tokio::test]
async fn t_061_11_verbose_emits_tlog_diagnostic() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_npm_provenance_config(&server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/test-pkg"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(npm_json_stub("test-pkg", "1.0.0")),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/-/npm/v1/attestations/test-pkg@1.0.0"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(attestation_json_with_malformed_tlog()),
        )
        .mount(&server)
        .await;

    // Run with --verbose; stderr must contain the tlog diagnostic.
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "--verbose",
            "check",
            "test-pkg",
            "--registry",
            "npm",
        ])
        .assert()
        .stderr(predicate::str::contains("skipping malformed tlog entry"));
}

//! Task 089 — process-level integration tests for `dep-scan signing export-pubkey`.
//!
//! T-089-17: `dep-scan signing export-pubkey` with a valid key → exit 0, stdout
//!   contains `# key-id:` comment and PEM block, stderr empty.
//! T-089-18: same command with no config (empty default) → exit non-zero, stderr
//!   contains message mentioning `signing.key_path`.
//! T-089-19 is the tooling gate (cargo test + clippy + fmt), checked in the
//!   pre-commit gate rather than a dedicated process test.

use std::io::Write as _;

use assert_cmd::Command;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use predicates::prelude::*;
use tempfile::{NamedTempFile, TempDir};

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

/// Write a minimal config with `[signing] key_path = <path>` to a temp file.
fn write_signing_config(key_path: &std::path::Path) -> NamedTempFile {
    // Escape backslashes so Windows paths (C:\Users\...) are valid TOML basic
    // strings; on Unix this is a no-op. The escaped path round-trips back to the
    // original value after TOML parsing, so stderr-path assertions still match.
    let key_path = key_path.display().to_string().replace('\\', "\\\\");
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"min_package_age_hours = 48

[signing]
key_path = "{}"
"#,
        key_path
    )
    .expect("write temp config");
    f
}

/// Generate an Ed25519 private key PEM and write it to a temp file.
fn gen_key_tempfile() -> (NamedTempFile, TempDir) {
    use rand_core::OsRng;
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pem = sk
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .expect("encode pkcs8 pem")
        .to_string();
    let dir = TempDir::new().expect("tempdir");
    let key_path = dir.path().join("operator-key.pem");
    std::fs::write(&key_path, pem).expect("write key");
    // Return a NamedTempFile-like guard by wrapping; use the dir to keep paths alive.
    // We can't return a NamedTempFile for a path that already exists, so return a
    // regular temp file for the config and the dir for cleanup.
    let config = write_signing_config(&key_path);
    (config, dir)
}

// T-089-17: `dep-scan signing export-pubkey` with a valid key → exit 0, correct output.
#[test]
fn t_089_17_export_pubkey_process_success() {
    let (config, _dir) = gen_key_tempfile();

    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "signing",
            "export-pubkey",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("# key-id: "))
        .stdout(predicate::str::contains("-----BEGIN PUBLIC KEY-----"))
        .stdout(predicate::str::contains("-----END PUBLIC KEY-----"))
        .stderr(predicate::str::is_empty());
}

// T-089-18: `dep-scan signing export-pubkey` with no config (empty default) →
// exit non-zero, stderr mentions `signing.key_path`.
#[test]
fn t_089_18_export_pubkey_no_config_fails() {
    // Write a config with no [signing] section (key_path defaults to "").
    let mut empty_cfg = NamedTempFile::new().expect("tempfile");
    writeln!(empty_cfg, "min_package_age_hours = 48").expect("write");
    empty_cfg.flush().expect("flush");

    dep_scan()
        .args([
            "--config",
            empty_cfg.path().to_str().unwrap(),
            "signing",
            "export-pubkey",
        ])
        .assert()
        .code(predicate::ne(0))
        .stderr(predicate::str::contains("signing.key_path"));
}

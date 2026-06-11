//! Public-key export for consumers (task 089).
//!
//! Provides `export_pubkey`: reads the operator's private signing key from
//! `signing.key_path`, derives the public half, and writes it to a
//! `dyn Write` sink as:
//!
//! ```text
//! # key-id: <64 lowercase hex chars>\n
//! -----BEGIN PUBLIC KEY-----\n
//! <base64 SPKI DER, line-wrapped at 64 chars>
//! -----END PUBLIC KEY-----\n
//! ```
//!
//! Output is pipe/redirect-friendly: only printable ASCII, ends with a newline,
//! no ANSI escape sequences. Zero network calls. No private key material in
//! output.
//!
//! ## Spec marker coverage
//! T-089-01 .. T-089-19

use std::io::Write;

use anyhow::{Result, anyhow};

use crate::config::Config;
use crate::interchange_sign::ed25519_keyid;

/// Export the operator's Ed25519 public key to `out` in PEM SPKI format.
///
/// Output format:
/// ```text
/// # key-id: <64 lowercase hex SHA-256 of 32-byte public key>\n
/// -----BEGIN PUBLIC KEY-----\n
/// <base64-wrapped SPKI DER>\n
/// -----END PUBLIC KEY-----\n
/// ```
///
/// Errors are returned (not written to `out`) for every failure mode:
/// - `signing.key_path` empty/unset
/// - File unreadable (message includes path)
/// - File not a valid PEM PKCS#8 Ed25519 private key (message includes path)
///
/// No network calls are made. No private key bytes appear in `out`.
pub fn export_pubkey(config: &Config, out: &mut dyn Write) -> Result<()> {
    // REQ-089-02 step 1: signing.key_path must be set.
    let key_path_str = config.signing.key_path.trim();
    if key_path_str.is_empty() {
        return Err(anyhow!(
            "signing.key_path is not configured; set signing.key_path in .dep-scan.toml"
        ));
    }

    let key_path = std::path::Path::new(key_path_str);

    // REQ-089-02 step 2: read the file.
    let pem = std::fs::read_to_string(key_path)
        .map_err(|e| anyhow!("failed to read signing key at {}: {e}", key_path.display()))?;

    // REQ-089-02 step 3: parse as PEM PKCS#8 Ed25519 private key.
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(&pem).map_err(|e| {
        anyhow!(
            "failed to parse PEM PKCS#8 Ed25519 signing key at {}: {e}",
            key_path.display()
        )
    })?;

    // REQ-089-02 step 4: derive the public key.
    let verifying_key = signing_key.verifying_key();

    // REQ-089-02 step 5: compute key-id — MUST use the shared ed25519_keyid
    // function from interchange_sign so signer and export tool cannot drift.
    let keyid = ed25519_keyid(verifying_key.as_bytes());

    // REQ-089-02 step 6: encode public key as PEM SPKI.
    use ed25519_dalek::pkcs8::EncodePublicKey as _;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    let pubkey_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| anyhow!("failed to encode public key as PEM SPKI: {e}"))?;

    // REQ-089-02 step 6: write output.
    // Format: comment line, then PEM block. Output is pure ASCII, ends with '\n'.
    writeln!(out, "# key-id: {keyid}")?;
    // to_public_key_pem already ends with '\n' (LF line ending), so just write it.
    write!(out, "{pubkey_pem}")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    /// Generate a fresh Ed25519 key-pair; return (PEM PKCS#8 private key, raw
    /// 32-byte public key, VerifyingKey).
    fn gen_ed25519() -> (String, [u8; 32], ed25519_dalek::VerifyingKey) {
        use rand_core::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let vk_bytes = *vk.as_bytes();
        let pem = sk
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .expect("encode pkcs8 pem")
            .to_string();
        (pem, vk_bytes, vk)
    }

    /// Write a PEM private key to a NamedTempFile; return the guard.
    fn write_key_tempfile(pem: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(pem.as_bytes()).expect("write key");
        f.flush().expect("flush");
        f
    }

    /// Build a Config with signing.key_path set to the given path.
    fn config_with_key_path(path: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.signing.key_path = path.to_string_lossy().into_owned();
        cfg
    }

    // -----------------------------------------------------------------------
    // T-089-03: Exports public key as PEM SPKI to stdout
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_03_exports_pem_spki() {
        let (pem, _vk_bytes, _vk) = gen_ed25519();
        let keyfile = write_key_tempfile(&pem);
        let config = config_with_key_path(keyfile.path());

        let mut out = Vec::<u8>::new();
        export_pubkey(&config, &mut out).expect("export_pubkey");

        let output = String::from_utf8(out).expect("utf8");
        assert!(
            output.contains("-----BEGIN PUBLIC KEY-----"),
            "T-089-03: output must contain '-----BEGIN PUBLIC KEY-----', got:\n{output}"
        );
        assert!(
            output.contains("-----END PUBLIC KEY-----"),
            "T-089-03: output must contain '-----END PUBLIC KEY-----', got:\n{output}"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-04: Exported PEM decodes to the correct Ed25519 public key
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_04_pem_decodes_to_correct_key() {
        let (pem, vk_bytes, _vk) = gen_ed25519();
        let keyfile = write_key_tempfile(&pem);
        let config = config_with_key_path(keyfile.path());

        let mut out = Vec::<u8>::new();
        export_pubkey(&config, &mut out).expect("export_pubkey");

        let output = String::from_utf8(out).expect("utf8");

        // Extract the PEM SPKI block and decode to raw bytes.
        // Ed25519 SPKI DER = 12-byte OID prefix + 32-byte key material.
        // OID prefix for Ed25519: 30 2a 30 05 06 03 2b 65 70 03 21 00
        use ed25519_dalek::pkcs8::DecodePublicKey as _;
        let decoded_vk = ed25519_dalek::VerifyingKey::from_public_key_pem(
            &output[output.find("-----BEGIN PUBLIC KEY-----").unwrap()..],
        )
        .expect("T-089-04: decoded VerifyingKey from exported PEM must succeed");

        assert_eq!(
            decoded_vk.as_bytes(),
            &vk_bytes,
            "T-089-04: decoded public key must match the original key pair's public half"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-05: Key-id comment line precedes the PEM block
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_05_keyid_comment_precedes_pem() {
        let (pem, vk_bytes, _vk) = gen_ed25519();
        let keyfile = write_key_tempfile(&pem);
        let config = config_with_key_path(keyfile.path());

        let mut out = Vec::<u8>::new();
        export_pubkey(&config, &mut out).expect("export_pubkey");

        let output = String::from_utf8(out).expect("utf8");
        let first_line = output.lines().next().expect("at least one line");

        // First line must match "# key-id: <64 lowercase hex chars>"
        assert!(
            first_line.starts_with("# key-id: "),
            "T-089-05: first line must start with '# key-id: ', got: {first_line:?}"
        );
        let hex_part = first_line.trim_start_matches("# key-id: ");
        assert_eq!(
            hex_part.len(),
            64,
            "T-089-05: key-id must be 64 hex chars (SHA-256), got len={}: {hex_part}",
            hex_part.len()
        );
        assert!(
            hex_part
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "T-089-05: key-id must be lowercase hex, got: {hex_part}"
        );

        // Verify the key-id is SHA-256 of the raw public key bytes.
        let expected_keyid = ed25519_keyid(&vk_bytes);
        assert_eq!(
            hex_part, expected_keyid,
            "T-089-05: key-id must be SHA-256(raw pubkey bytes)"
        );

        // The comment line must be immediately followed by the PEM block.
        let pem_start_pos = output
            .find("-----BEGIN PUBLIC KEY-----")
            .expect("PEM block");
        let comment_end_pos = first_line.len() + 1; // +1 for '\n'
        assert_eq!(
            comment_end_pos, pem_start_pos,
            "T-089-05: PEM block must immediately follow the key-id comment"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-06: Key-id matches task 087's OperatorKeySigner derivation
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_06_keyid_matches_operator_key_signer() {
        use crate::interchange_sign::OperatorKeySigner;

        let (pem, _vk_bytes, _vk) = gen_ed25519();
        let keyfile = write_key_tempfile(&pem);
        let config = config_with_key_path(keyfile.path());

        // Get the keyid from export_pubkey.
        let mut out = Vec::<u8>::new();
        export_pubkey(&config, &mut out).expect("export_pubkey");
        let output = String::from_utf8(out).expect("utf8");
        let first_line = output.lines().next().expect("line");
        let export_keyid = first_line.trim_start_matches("# key-id: ");

        // Get the keyid from OperatorKeySigner for the same key.
        let signer = OperatorKeySigner::from_key_path(keyfile.path()).expect("load signer");
        let signer_keyid = signer.keyid();

        assert_eq!(
            export_keyid, signer_keyid,
            "T-089-06: export_pubkey keyid must equal OperatorKeySigner keyid for the same key"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-07: No private key bytes appear in stdout
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_07_no_private_key_bytes_in_output() {
        use rand_core::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let sk_bytes = sk.to_bytes(); // 32 raw secret scalar bytes
        let pem = sk
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .expect("encode pkcs8 pem")
            .to_string();

        let keyfile = write_key_tempfile(&pem);
        let config = config_with_key_path(keyfile.path());

        let mut out = Vec::<u8>::new();
        export_pubkey(&config, &mut out).expect("export_pubkey");
        let output = String::from_utf8(out.clone()).expect("utf8");

        // Check that the raw private key bytes are not present (hex encoding).
        let sk_hex: String = sk_bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !output.contains(&sk_hex),
            "T-089-07: private key bytes (hex) must not appear in output"
        );

        // Check base64 encoding.
        use base64::Engine as _;
        let sk_b64 = base64::engine::general_purpose::STANDARD.encode(sk_bytes);
        assert!(
            !output.contains(&sk_b64),
            "T-089-07: private key bytes (base64) must not appear in output"
        );

        // Ensure the output is not trivially empty (sanity check).
        assert!(
            output.contains("-----BEGIN PUBLIC KEY-----"),
            "T-089-07: output must still contain a valid public key PEM block"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-08: Output is pipe/redirect friendly — no ANSI codes or extra
    // decoration; ends with newline; only printable ASCII.
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_08_output_is_pipe_friendly() {
        let (pem, _vk_bytes, _vk) = gen_ed25519();
        let keyfile = write_key_tempfile(&pem);
        let config = config_with_key_path(keyfile.path());

        let mut out = Vec::<u8>::new();
        export_pubkey(&config, &mut out).expect("export_pubkey");

        // Only printable ASCII + newlines.
        for &b in &out {
            assert!(
                b == b'\n' || (0x20..=0x7e).contains(&b),
                "T-089-08: non-printable byte {b:#04x} found in output"
            );
        }

        // No ANSI escape sequences.
        let output = String::from_utf8(out.clone()).expect("utf8");
        assert!(
            !output.contains('\x1b'),
            "T-089-08: output must not contain ANSI escape sequences"
        );

        // Ends with a newline.
        assert!(
            out.last() == Some(&b'\n'),
            "T-089-08: output must end with a newline"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-09: signing.key_path unset → Err, message names signing.key_path
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_09_unset_key_path_returns_err() {
        let config = Config::default(); // key_path is ""
        let mut out = Vec::<u8>::new();
        let result = export_pubkey(&config, &mut out);

        assert!(
            result.is_err(),
            "T-089-09: export_pubkey must return Err when signing.key_path is unset"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("signing.key_path"),
            "T-089-09: error message must mention 'signing.key_path', got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-10: Non-existent key file → Err, message contains the path
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_10_missing_key_file_returns_err() {
        let mut config = Config::default();
        let missing_path = "/tmp/dep-scan-no-such-key-089-missing.pem";
        config.signing.key_path = missing_path.to_string();

        let mut out = Vec::<u8>::new();
        let result = export_pubkey(&config, &mut out);

        assert!(
            result.is_err(),
            "T-089-10: export_pubkey must return Err for a non-existent key file"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(missing_path),
            "T-089-10: error message must contain the missing path, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-11: Garbage bytes → Err, clear message about invalid key
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_11_garbage_key_file_returns_err() {
        use rand_core::OsRng;
        use rand_core::RngCore as _;
        let mut garbage = [0u8; 64];
        OsRng.fill_bytes(&mut garbage);

        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(&garbage).expect("write garbage");
        f.flush().expect("flush");

        let config = config_with_key_path(f.path());
        let mut out = Vec::<u8>::new();
        let result = export_pubkey(&config, &mut out);

        assert!(
            result.is_err(),
            "T-089-11: export_pubkey must return Err for garbage key bytes"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-12: Empty key file → Err
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_12_empty_key_file_returns_err() {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        // Do not write anything — file is empty.
        let config = config_with_key_path(f.path());
        let mut out = Vec::<u8>::new();
        let result = export_pubkey(&config, &mut out);
        assert!(
            result.is_err(),
            "T-089-12: export_pubkey must return Err for empty key file"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-13: Wrong PEM type (certificate) → Err, mentions unexpected type
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_13_wrong_pem_type_returns_err() {
        // Write a fake certificate PEM block (not a private key).
        let cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBXzCCAQWgAwIBAgIJALzGzTuXhI8oMA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNV\n-----END CERTIFICATE-----\n";
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(cert_pem.as_bytes()).expect("write cert pem");
        f.flush().expect("flush");

        let config = config_with_key_path(f.path());
        let mut out = Vec::<u8>::new();
        let result = export_pubkey(&config, &mut out);

        assert!(
            result.is_err(),
            "T-089-13: export_pubkey must return Err for a certificate PEM (not a private key)"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-14: No network calls are made during export
    // -----------------------------------------------------------------------
    /// This test verifies zero network calls by standing up a wiremock server
    /// with a catch-all `expect(0)` stub. If export_pubkey ever issues an HTTP
    /// request, the mock server trips on drop and the explicit assertion below
    /// fires first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t_089_14_no_network_calls() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let (pem, _vk_bytes, _vk) = gen_ed25519();
        let keyfile = write_key_tempfile(&pem);
        let config = config_with_key_path(keyfile.path());

        let result = tokio::task::spawn_blocking(move || {
            let mut out = Vec::<u8>::new();
            export_pubkey(&config, &mut out)
        })
        .await
        .expect("join");
        assert!(
            result.is_ok(),
            "T-089-14: export_pubkey must succeed with a valid key"
        );

        // Explicit zero-request assertion.
        let requests = server
            .received_requests()
            .await
            .expect("wiremock records requests");
        assert!(
            requests.is_empty(),
            "T-089-14: export_pubkey must make ZERO network calls, but received {} request(s)",
            requests.len()
        );
    }

    // -----------------------------------------------------------------------
    // T-089-15: Absolute path with spaces works on all platforms
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_15_path_with_spaces() {
        let (pem, _vk_bytes, _vk) = gen_ed25519();

        // Create a temp dir whose name contains a space.
        let dir = tempfile::Builder::new()
            .prefix("dep scan spaces ")
            .tempdir()
            .expect("tempdir with spaces");

        let key_path = dir.path().join("signing key.pem");
        std::fs::write(&key_path, pem.as_bytes()).expect("write key");

        let config = config_with_key_path(&key_path);
        let mut out = Vec::<u8>::new();
        let result = export_pubkey(&config, &mut out);
        assert!(
            result.is_ok(),
            "T-089-15: export_pubkey must succeed with a path containing spaces, got: {:?}",
            result.err()
        );
        let output = String::from_utf8(out).expect("utf8");
        assert!(
            output.contains("-----BEGIN PUBLIC KEY-----"),
            "T-089-15: output must contain PEM block"
        );
    }

    // -----------------------------------------------------------------------
    // T-089-16: Relative path in signing.key_path is resolved from cwd
    // -----------------------------------------------------------------------
    #[test]
    fn t_089_16_relative_path_resolved_from_cwd() {
        let (pem, _vk_bytes, _vk) = gen_ed25519();

        // Create a temp dir, write the key there.
        let dir = tempfile::tempdir().expect("tempdir");
        let key_filename = "my-signing-key.pem";
        let key_path = dir.path().join(key_filename);
        std::fs::write(&key_path, pem.as_bytes()).expect("write key");

        // Change cwd to the temp dir for this test. Use env::set_current_dir.
        let original_cwd = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(dir.path()).expect("set_current_dir");

        let mut config = Config::default();
        config.signing.key_path = key_filename.to_string(); // relative path

        let mut out = Vec::<u8>::new();
        let result = export_pubkey(&config, &mut out);

        // Restore cwd before any assertions to avoid leaving test environment dirty.
        std::env::set_current_dir(&original_cwd).expect("restore cwd");

        assert!(
            result.is_ok(),
            "T-089-16: export_pubkey must succeed with a relative path resolved from cwd, got: {:?}",
            result.err()
        );
        let output = String::from_utf8(out).expect("utf8");
        assert!(
            output.contains("-----BEGIN PUBLIC KEY-----"),
            "T-089-16: output must contain a valid PEM block"
        );
    }
}

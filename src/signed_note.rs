//! Shared signed-note parser + verifier (task 036).
//!
//! A "signed note" is a plain-text, append-only manifest with one or more
//! signature lines appended.  The format is shared between Go's checksum
//! database (`sum.golang.org`) and Sigstore's Rekor transparency log:
//!
//! ```text
//! <note-text>
//! <may be many lines>
//!
//! — <key-name> <base64(key-id || sig)>
//! — <key-name> <base64(key-id || sig)>
//! ```
//!
//! Two sections, separated by a blank line.  The signature lines start with
//! the em-dash U+2014 (`—`).  The base64-decoded signature payload is
//! `[4-byte key-id] || <raw-sig-bytes>`.
//!
//! Algorithms differ:
//!
//! | Ecosystem | Signing key | Sig bytes | Key-hash formula |
//! |-----------|-------------|-----------|------------------|
//! | Go sumdb  | Ed25519     | 64 bytes  | `sha256("hash:1:" + name + "\n" + (0x01 || raw_ed25519_pubkey))[:4]` |
//! | Rekor     | ECDSA P-256 | DER (~70 bytes) | `sha256(SPKI_DER)[:4]` |
//!
//! This module exposes:
//!
//! - [`parse`] — parse a signed-note string into note text + signature lines.
//!   Algorithm-agnostic.
//! - [`verify_ed25519`] — verify against a sumdb-style Ed25519 key
//!   (used by `policy::go_sumdb`).
//! - [`verify_ecdsa_p256`] — verify against a PEM-encoded ECDSA P-256 key
//!   (used by `sigstore_verify` for Rekor checkpoints).
//!
//! ## Spec marker coverage
//! T-036-08, T-036-09, T-036-10 (Rekor ECDSA path) +
//! T-034-06, T-034-07, T-034-08 (Ed25519 path, unchanged behavior).
//!
//! Task 043 (multi-sig iteration for key rotation):
//! T-043-01 through T-043-13 (new tests in the `tests` module below).
//! T-043-14 — see `verify_ed25519` and `verify_ecdsa_p256` loops: key-id
//! mismatch uses `continue`, not `return`.
//! T-043-15 — verified by CI: `cargo test`, `cargo clippy`, `cargo fmt` all pass.

use base64::Engine as _;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use p256::ecdsa::signature::Verifier as P256Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use sha2::{Digest, Sha256};

/// Outcome of verifying a signed note.
#[derive(Debug, Clone, PartialEq)]
pub enum NoteVerifyOutcome {
    /// At least one signature line was successfully verified against the
    /// pinned key.
    Valid,
    /// No signature line could be verified — bad parse, wrong key-id,
    /// wrong key name, or cryptographic failure.
    Invalid { reason: String },
}

/// A parsed signed note: the note text and one or more signature lines.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedNote<'a> {
    /// The note text, including the trailing newline before the blank line.
    /// This is the exact byte string the signature was computed over.
    pub note_text: &'a str,
    /// Signature lines (one per signer), each parsed into name + key-id +
    /// raw signature bytes.
    pub signatures: Vec<NoteSignature>,
}

/// A single parsed signature line.
#[derive(Debug, Clone, PartialEq)]
pub struct NoteSignature {
    /// Key name (e.g. `sum.golang.org`, `rekor.sigstore.dev`).
    pub key_name: String,
    /// First 4 bytes of the base64-decoded sig payload — identifies which
    /// key was used.
    pub key_id: [u8; 4],
    /// Remaining bytes after the 4-byte key-id.  For Ed25519 this is exactly
    /// 64 bytes; for ECDSA P-256 it is a DER-encoded `Signature`.
    pub sig_bytes: Vec<u8>,
}

/// Parse a signed-note string into note text + signature lines.
///
/// Returns `Err(_)` for structural failures (no blank-line separator,
/// no signature lines, malformed signature line, bad base64).
pub fn parse(signed_note: &str) -> Result<ParsedNote<'_>, String> {
    // Split note text from signature lines: the last "\n\n" is the boundary.
    // Per the Rekor reference implementation, the note text includes the
    // trailing newline before the blank line.
    let note_end = signed_note
        .rfind("\n\n")
        .ok_or_else(|| "signed note missing blank-line separator before signatures".to_string())?;
    let note_text = &signed_note[..note_end + 1]; // include trailing \n
    let sig_section = signed_note[note_end + 2..].trim_end_matches('\n');

    let mut signatures = Vec::new();
    for line in sig_section.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Em-dash U+2014 is 3 bytes in UTF-8.
        if !line.starts_with('\u{2014}') {
            return Err(format!(
                "signature line does not start with em-dash: {line}"
            ));
        }
        let rest = line['\u{2014}'.len_utf8()..].trim();
        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return Err(format!("malformed signature line: {line}"));
        }
        let key_name = parts[0].to_string();
        let sig_b64 = parts[1];
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|e| format!("signature base64 decode failed: {e}"))?;
        if raw.len() < 5 {
            return Err(format!(
                "signature payload too short ({} bytes; need at least 5 for key-id + signature)",
                raw.len()
            ));
        }
        let mut key_id = [0u8; 4];
        key_id.copy_from_slice(&raw[..4]);
        signatures.push(NoteSignature {
            key_name,
            key_id,
            sig_bytes: raw[4..].to_vec(),
        });
    }

    if signatures.is_empty() {
        return Err("signed note has no signature lines".to_string());
    }

    Ok(ParsedNote {
        note_text,
        signatures,
    })
}

// ---------------------------------------------------------------------------
// Ed25519 verifier (used by go_sumdb — task 034)
// ---------------------------------------------------------------------------

/// Verify a signed note against an Ed25519 key in Go's sumdb key string
/// format (`<key-name>+<key-id-hex>+<base64-key>`).
///
/// `key_str` decodes as 33 bytes: a 0x01 algorithm marker followed by the
/// 32-byte raw Ed25519 public key.
///
/// The key-hash format is sumdb-specific:
/// `sha256("hash:1:" + key_name + "\n" + 33-byte-key-bytes)[:4]`.
pub fn verify_ed25519(signed_note: &str, key_str: &str) -> NoteVerifyOutcome {
    let key_parts: Vec<&str> = key_str.splitn(3, '+').collect();
    if key_parts.len() != 3 {
        return NoteVerifyOutcome::Invalid {
            reason: format!("malformed key string: expected 3 '+'-separated fields, got {key_str}"),
        };
    }
    let key_name = key_parts[0];
    let key_b64 = key_parts[2];

    let key_bytes = match base64::engine::general_purpose::STANDARD.decode(key_b64) {
        Ok(b) => b,
        Err(e) => {
            return NoteVerifyOutcome::Invalid {
                reason: format!("failed to decode public key base64: {e}"),
            };
        }
    };

    if key_bytes.len() != 33 || key_bytes[0] != 0x01 {
        return NoteVerifyOutcome::Invalid {
            reason: format!(
                "public key has unexpected format (expected 33 bytes with 0x01 prefix, got {} bytes with prefix 0x{:02x})",
                key_bytes.len(),
                key_bytes.first().copied().unwrap_or(0)
            ),
        };
    }

    let ed_key_bytes: [u8; 32] = key_bytes[1..33]
        .try_into()
        .expect("slice is 32 bytes by length check above");
    let verifying_key = match VerifyingKey::from_bytes(&ed_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            return NoteVerifyOutcome::Invalid {
                reason: format!("invalid Ed25519 public key: {e}"),
            };
        }
    };

    // sumdb key-id: SHA256("hash:1:" || name || "\n" || key_bytes)[:4]
    let mut hasher = Sha256::new();
    hasher.update(b"hash:1:");
    hasher.update(key_name.as_bytes());
    hasher.update(b"\n");
    hasher.update(&key_bytes);
    let expected_key_id = &hasher.finalize()[..4];

    let parsed = match parse(signed_note) {
        Ok(p) => p,
        Err(e) => return NoteVerifyOutcome::Invalid { reason: e },
    };

    // T-043-14: iterate all lines; continue on key-id mismatch (REQ-043-01).
    for sig in &parsed.signatures {
        if sig.key_name != key_name {
            continue;
        }
        // Key-id mismatch: this line was signed by a different key (e.g. old
        // key during rotation).  Continue to the next line rather than
        // returning Invalid immediately (REQ-043-01).
        if sig.key_id != expected_key_id {
            continue;
        }
        if sig.sig_bytes.len() != 64 {
            // Malformed line length — continue in case a later line is valid.
            continue;
        }
        let sig_arr: [u8; 64] = sig
            .sig_bytes
            .as_slice()
            .try_into()
            .expect("len == 64 by check above");
        let signature = Ed25519Signature::from_bytes(&sig_arr);
        // On cryptographic success return Valid immediately; on failure
        // continue so a second line with the same key-id but a valid
        // signature can succeed (REQ-043-01, per task spec "continue
        // iterating rather than returning immediately").
        if Verifier::verify(&verifying_key, parsed.note_text.as_bytes(), &signature).is_ok() {
            return NoteVerifyOutcome::Valid;
        }
    }

    NoteVerifyOutcome::Invalid {
        reason: format!("no signature line found for key '{key_name}'"),
    }
}

// ---------------------------------------------------------------------------
// ECDSA P-256 verifier (used by Rekor — task 036)
// ---------------------------------------------------------------------------

/// Verify a signed note against an ECDSA P-256 key in PEM (`-----BEGIN PUBLIC KEY-----`)
/// SubjectPublicKeyInfo form.
///
/// The expected key name is matched against the signature line; mismatched
/// names produce `Invalid` (no signature line for the pinned key).
///
/// The Rekor key-hash is `sha256(SPKI_DER)[:4]` (no name prefix — see
/// `getPublicKeyHash` in `sigstore/rekor/pkg/util/signed_note.go`).
///
/// The signature is verified over the note text bytes; the underlying ECDSA
/// implementation internally hashes with SHA-256 before verification.
pub fn verify_ecdsa_p256(
    signed_note: &str,
    expected_key_name: &str,
    pem_pubkey: &str,
) -> NoteVerifyOutcome {
    // Parse PEM and extract SPKI DER bytes.
    let spki_der = match pem_to_spki_der(pem_pubkey) {
        Ok(d) => d,
        Err(e) => return NoteVerifyOutcome::Invalid { reason: e },
    };

    // The Rekor key-id format: first 4 bytes of sha256(SPKI_DER).
    let mut hasher = Sha256::new();
    hasher.update(&spki_der);
    let expected_key_id_full = hasher.finalize();
    let expected_key_id = &expected_key_id_full[..4];

    // Extract the uncompressed SEC1 point bytes from the SPKI for the
    // verifying key. Look for the `0x04` uncompressed-point byte that starts
    // the 65-byte public key region.  This is robust for the standard
    // P-256 SPKI shape used by sigstore (`MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...`).
    let ec_point = match extract_ec_point_p256(&spki_der) {
        Some(p) => p,
        None => {
            return NoteVerifyOutcome::Invalid {
                reason: "PEM key did not look like a P-256 SPKI (no uncompressed point found)"
                    .to_string(),
            };
        }
    };

    let verifying_key = match P256VerifyingKey::from_sec1_bytes(&ec_point) {
        Ok(k) => k,
        Err(e) => {
            return NoteVerifyOutcome::Invalid {
                reason: format!("invalid P-256 public key: {e}"),
            };
        }
    };

    let parsed = match parse(signed_note) {
        Ok(p) => p,
        Err(e) => return NoteVerifyOutcome::Invalid { reason: e },
    };

    // T-043-14: iterate all lines; continue on key-id mismatch (REQ-043-02).
    for sig in &parsed.signatures {
        if sig.key_name != expected_key_name {
            continue;
        }
        // Key-id mismatch: this line was signed by a different key (e.g. old
        // key during rotation).  Continue to the next line rather than
        // returning Invalid immediately (REQ-043-02).
        if sig.key_id != expected_key_id {
            continue;
        }
        // DER parse failure — continue in case a later line with the same
        // key-id has valid DER (REQ-043-02, per task spec).
        let Ok(signature) = P256Signature::from_der(&sig.sig_bytes) else {
            continue;
        };
        // On cryptographic success return Valid; on failure continue so a
        // second line with the same key-id but a valid signature can succeed.
        if P256Verifier::verify(&verifying_key, parsed.note_text.as_bytes(), &signature).is_ok() {
            return NoteVerifyOutcome::Valid;
        }
    }

    NoteVerifyOutcome::Invalid {
        reason: format!("no signature line found for key '{expected_key_name}'"),
    }
}

/// Decode a `-----BEGIN PUBLIC KEY-----` PEM string into raw SPKI DER bytes.
fn pem_to_spki_der(pem: &str) -> Result<Vec<u8>, String> {
    let begin = "-----BEGIN PUBLIC KEY-----";
    let end = "-----END PUBLIC KEY-----";
    let bstart = pem
        .find(begin)
        .ok_or_else(|| "PEM missing BEGIN PUBLIC KEY marker".to_string())?;
    let body_start = bstart + begin.len();
    let body_end = pem[body_start..]
        .find(end)
        .ok_or_else(|| "PEM missing END PUBLIC KEY marker".to_string())?
        + body_start;
    let b64: String = pem[body_start..body_end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("PEM base64 decode failed: {e}"))
}

/// Find the 65-byte uncompressed SEC1 EC point inside a P-256 SPKI DER blob.
///
/// The point is the last 65 bytes of a standard P-256 SPKI; we locate the
/// `0x04` uncompressed-point tag in the tail of the DER (after the
/// algorithm identifier, which ends around offset 23).
fn extract_ec_point_p256(spki_der: &[u8]) -> Option<Vec<u8>> {
    if spki_der.len() < 65 {
        return None;
    }
    let tail_start = spki_der.len() - 65;
    if spki_der[tail_start] == 0x04 {
        return Some(spki_der[tail_start..].to_vec());
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;
    use p256::ecdsa::signature::Signer as P256Signer;
    use rand_core::OsRng;

    fn build_ed25519_signed_note(note_text: &str) -> (String, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let mut key_bytes = vec![0x01u8];
        key_bytes.extend_from_slice(verifying_key.as_bytes());
        let key_name = "test-key";
        let mut hasher = Sha256::new();
        hasher.update(b"hash:1:");
        hasher.update(key_name.as_bytes());
        hasher.update(b"\n");
        hasher.update(&key_bytes);
        let key_id = &hasher.finalize()[..4];
        let key_id_hex = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            key_id[0], key_id[1], key_id[2], key_id[3]
        );
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&key_bytes);
        let key_str = format!("{key_name}+{key_id_hex}+{key_b64}");
        let sig = Signer::sign(&signing_key, note_text.as_bytes());
        let mut sig_payload = key_id.to_vec();
        sig_payload.extend_from_slice(&sig.to_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_payload);
        let signed_note = format!("{note_text}\n\u{2014} {key_name} {sig_b64}\n");
        (key_str, signed_note)
    }

    fn build_ecdsa_p256_signed_note(note_text: &str, key_name: &str) -> (String, String) {
        use p256::pkcs8::EncodePublicKey;
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let spki_pem = verifying_key
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .expect("encode pem");
        // key-hash = sha256(SPKI_DER)[:4]
        let spki_der = pem_to_spki_der(&spki_pem).expect("extract spki");
        let mut hasher = Sha256::new();
        hasher.update(&spki_der);
        let key_id = &hasher.finalize()[..4];
        let sig: p256::ecdsa::Signature = P256Signer::sign(&signing_key, note_text.as_bytes());
        let sig_der = sig.to_der();
        let mut payload = key_id.to_vec();
        payload.extend_from_slice(sig_der.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        let signed_note = format!("{note_text}\n\u{2014} {key_name} {sig_b64}\n");
        (spki_pem, signed_note)
    }

    #[test]
    fn parse_extracts_note_text_and_one_signature() {
        let note = "hello world\nmore text\n\n\u{2014} foo AAAABwgJ\n";
        let parsed = parse(note).unwrap();
        assert_eq!(parsed.note_text, "hello world\nmore text\n");
        assert_eq!(parsed.signatures.len(), 1);
        assert_eq!(parsed.signatures[0].key_name, "foo");
    }

    #[test]
    fn parse_rejects_missing_blank_line() {
        assert!(parse("no blank line here").is_err());
    }

    #[test]
    fn parse_rejects_no_signature() {
        assert!(parse("text\n\n").is_err());
    }

    #[test]
    fn ed25519_round_trip_verifies() {
        let note_text = "go.sum database tree\n12345\nabc\n";
        let (key_str, signed_note) = build_ed25519_signed_note(note_text);
        assert_eq!(
            verify_ed25519(&signed_note, &key_str),
            NoteVerifyOutcome::Valid
        );
    }

    // T-036-08
    #[test]
    fn t_036_08_ecdsa_p256_round_trip_verifies() {
        let note_text = "rekor.sigstore.dev - 1\n42\nabc=\n";
        let (pem, signed_note) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        let outcome = verify_ecdsa_p256(&signed_note, "rekor.sigstore.dev", &pem);
        assert_eq!(outcome, NoteVerifyOutcome::Valid, "got {outcome:?}");
    }

    // T-036-09
    #[test]
    fn t_036_09_ecdsa_p256_tampered_sig_rejected() {
        let note_text = "rekor.sigstore.dev - 1\n42\nabc=\n";
        let (pem, signed_note) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");

        // Tamper with the signature line — flip one base64 character.
        let tampered: String = signed_note
            .lines()
            .map(|l| {
                if l.starts_with('\u{2014}') {
                    let mut chars: Vec<char> = l.chars().collect();
                    // Flip the second-to-last char of the line (a base64 char,
                    // not whitespace) so we corrupt the signature without
                    // breaking the structural format.
                    let idx = chars.len() - 2;
                    chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
                    chars.into_iter().collect()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";

        match verify_ecdsa_p256(&tampered, "rekor.sigstore.dev", &pem) {
            NoteVerifyOutcome::Invalid { .. } => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    // T-036-10
    #[test]
    fn t_036_10_ecdsa_p256_wrong_key_rejected() {
        let note_text = "rekor.sigstore.dev - 1\n42\nabc=\n";
        // Sign with key A
        let (_pem_a, signed_note_a) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        // Verify with key B (entirely different)
        let (pem_b, _) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        match verify_ecdsa_p256(&signed_note_a, "rekor.sigstore.dev", &pem_b) {
            NoteVerifyOutcome::Invalid { .. } => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn ecdsa_p256_real_rekor_checkpoint_verifies() {
        // The production Rekor pubkey (PEM).
        let pem = include_str!("../rekor-roots/rekor.pub");
        // A real checkpoint envelope from a public sigstore bundle
        // (sigstore@2.3.1 on npm, attestation index 1).
        let envelope = "rekor.sigstore.dev - 2605736670972794746\n90244708\nCOSIc1jqxpbuuTChPdiTqtZBBve7GAVJqTYjqAaM940=\n\n— rekor.sigstore.dev wNI9ajBEAiAkKWVCpp/N5yF/GlQkAyKQxUsjc3Vpu04YyALJvrBsvAIgcZfXJsJdwLdgUAWwnekWg8YXS4gfz/DM1wVhhcouJBE=\n";
        assert_eq!(
            verify_ecdsa_p256(envelope, "rekor.sigstore.dev", pem),
            NoteVerifyOutcome::Valid
        );
    }

    // -----------------------------------------------------------------------
    // Task 043 helpers
    // -----------------------------------------------------------------------

    /// Build an Ed25519 signed note with a configurable key name.
    /// Returns `(key_str, signing_key, signed_note)`.
    fn build_ed25519_signed_note_named(
        note_text: &str,
        key_name: &str,
    ) -> (String, SigningKey, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let mut key_bytes = vec![0x01u8];
        key_bytes.extend_from_slice(verifying_key.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(b"hash:1:");
        hasher.update(key_name.as_bytes());
        hasher.update(b"\n");
        hasher.update(&key_bytes);
        let key_id = &hasher.finalize()[..4];
        let key_id_hex = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            key_id[0], key_id[1], key_id[2], key_id[3]
        );
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&key_bytes);
        let key_str = format!("{key_name}+{key_id_hex}+{key_b64}");
        let sig = Signer::sign(&signing_key, note_text.as_bytes());
        let mut sig_payload = key_id.to_vec();
        sig_payload.extend_from_slice(&sig.to_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_payload);
        let signed_note = format!("{note_text}\n\u{2014} {key_name} {sig_b64}\n");
        (key_str, signing_key, signed_note)
    }

    /// Extract the signature line (the `— name b64` part) from a single-sig note.
    fn extract_sig_line(signed_note: &str) -> &str {
        signed_note
            .lines()
            .find(|l| l.starts_with('\u{2014}'))
            .expect("no sig line found")
    }

    /// Build an ECDSA P-256 signed note with configurable key name.
    /// Returns `(pem, signing_key, signed_note)`.
    fn build_ecdsa_p256_signed_note_full(
        note_text: &str,
        key_name: &str,
    ) -> (String, P256SigningKey, String) {
        use p256::pkcs8::EncodePublicKey;
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let spki_pem = verifying_key
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .expect("encode pem");
        let spki_der = pem_to_spki_der(&spki_pem).expect("extract spki");
        let mut hasher = Sha256::new();
        hasher.update(&spki_der);
        let key_id = &hasher.finalize()[..4];
        let sig: p256::ecdsa::Signature = P256Signer::sign(&signing_key, note_text.as_bytes());
        let sig_der = sig.to_der();
        let mut payload = key_id.to_vec();
        payload.extend_from_slice(sig_der.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        let signed_note = format!("{note_text}\n\u{2014} {key_name} {sig_b64}\n");
        (spki_pem, signing_key, signed_note)
    }

    // -----------------------------------------------------------------------
    // T-043-01 through T-043-08: verify_ed25519 multi-sig iteration tests
    // -----------------------------------------------------------------------

    // T-043-01
    #[test]
    fn t_043_01_ed25519_single_sig_correct_key_verifies() {
        let note_text = "go.sum database tree\n100\nabc=\n";
        let (key_str, _sk, signed_note) =
            build_ed25519_signed_note_named(note_text, "sum.golang.org");
        assert_eq!(
            verify_ed25519(&signed_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-043-01: single correct signature must verify"
        );
    }

    // T-043-02
    #[test]
    fn t_043_02_ed25519_single_sig_wrong_key_name_returns_invalid() {
        let note_text = "go.sum database tree\n100\nabc=\n";
        let (key_str_k1, _sk, signed_note) =
            build_ed25519_signed_note_named(note_text, "sum.golang.org");
        // Build a key_str for a different key name — key-hash is irrelevant here
        // because the name won't match the sig line.
        let (key_str_k2, _sk2, _) =
            build_ed25519_signed_note_named(note_text, "other.registry.dev");
        // signed_note was signed by key_str_k1 (sum.golang.org); verify with key_str_k2 (other.registry.dev)
        let _ = key_str_k1; // suppress unused
        match verify_ed25519(&signed_note, &key_str_k2) {
            NoteVerifyOutcome::Invalid { reason } => {
                assert!(
                    reason.contains("no signature line found"),
                    "T-043-02: reason should mention 'no signature line found', got: {reason}"
                );
            }
            other => panic!("T-043-02: expected Invalid, got {other:?}"),
        }
    }

    // T-043-03: two lines — old key first, new key second; pinned = new key
    #[test]
    fn t_043_03_ed25519_two_lines_old_first_new_second_verifies() {
        let note_text = "go.sum database tree\n200\nxyz=\n";
        let key_name = "sum.golang.org";

        // Build old-key signature line (different key-id, not the pinned one).
        let (_, _sk_old, note_old) = build_ed25519_signed_note_named(note_text, key_name);
        let old_sig_line = extract_sig_line(&note_old).to_string();

        // Build new-key (the pinned key).
        let (key_str_new, _sk_new, note_new) = build_ed25519_signed_note_named(note_text, key_name);
        let new_sig_line = extract_sig_line(&note_new).to_string();

        // Assemble: note_text + blank + old sig line + new sig line
        let two_line_note = format!("{note_text}\n{old_sig_line}\n{new_sig_line}\n");

        assert_eq!(
            verify_ed25519(&two_line_note, &key_str_new),
            NoteVerifyOutcome::Valid,
            "T-043-03: old key first, new key second — must find pinned key and verify"
        );
    }

    // T-043-04: two lines — new key first, old key second; pinned = new key
    #[test]
    fn t_043_04_ed25519_two_lines_new_first_old_second_verifies() {
        let note_text = "go.sum database tree\n201\nxyz=\n";
        let key_name = "sum.golang.org";

        let (_, _sk_old, note_old) = build_ed25519_signed_note_named(note_text, key_name);
        let old_sig_line = extract_sig_line(&note_old).to_string();

        let (key_str_new, _sk_new, note_new) = build_ed25519_signed_note_named(note_text, key_name);
        let new_sig_line = extract_sig_line(&note_new).to_string();

        // Reversed order: new first, old second
        let two_line_note = format!("{note_text}\n{new_sig_line}\n{old_sig_line}\n");

        assert_eq!(
            verify_ed25519(&two_line_note, &key_str_new),
            NoteVerifyOutcome::Valid,
            "T-043-04: new key first, old key second — must verify via first line"
        );
    }

    // T-043-05: two lines, both with wrong key-ids (both different from pinned)
    #[test]
    fn t_043_05_ed25519_two_lines_both_wrong_key_id_returns_invalid() {
        let note_text = "go.sum database tree\n300\nabc=\n";
        let key_name = "sum.golang.org";

        // k_a and k_b are both different from k_pinned.
        let (_, _sk_a, note_a) = build_ed25519_signed_note_named(note_text, key_name);
        let sig_a = extract_sig_line(&note_a).to_string();
        let (_, _sk_b, note_b) = build_ed25519_signed_note_named(note_text, key_name);
        let sig_b = extract_sig_line(&note_b).to_string();

        // Pinned key is a third, independent key.
        let (key_str_pinned, _sk_pinned, _) = build_ed25519_signed_note_named(note_text, key_name);

        let two_line_note = format!("{note_text}\n{sig_a}\n{sig_b}\n");

        match verify_ed25519(&two_line_note, &key_str_pinned) {
            NoteVerifyOutcome::Invalid { reason } => {
                assert!(
                    reason.contains("no signature line found"),
                    "T-043-05: reason should mention 'no signature line found', got: {reason}"
                );
            }
            other => panic!("T-043-05: expected Invalid, got {other:?}"),
        }
    }

    // T-043-06: correct key-id on first line but bad sig bytes; valid second line
    #[test]
    fn t_043_06_ed25519_bad_sig_first_valid_second_verifies() {
        let note_text = "go.sum database tree\n400\nabc=\n";
        let key_name = "sum.golang.org";

        // Build a valid note for the pinned key to extract key_str and key_id.
        let (key_str, _sk, note_valid) = build_ed25519_signed_note_named(note_text, key_name);

        // Parse the valid note to get the correct key_id prefix.
        let parsed_valid = parse(&note_valid).expect("parse valid note");
        let key_id_bytes = parsed_valid.signatures[0].key_id;

        // Construct a bad sig line: same key_name, same key_id, but 64 bytes of
        // garbage for the sig payload.
        let mut bad_payload = key_id_bytes.to_vec();
        bad_payload.extend_from_slice(&[0xffu8; 64]);
        let bad_b64 = base64::engine::general_purpose::STANDARD.encode(&bad_payload);
        let bad_sig_line = format!("\u{2014} {key_name} {bad_b64}");

        // Extract the valid sig line from the correctly-signed note.
        let good_sig_line = extract_sig_line(&note_valid).to_string();

        // Build the two-line note: bad first, good second.
        let two_line_note = format!("{note_text}\n{bad_sig_line}\n{good_sig_line}\n");

        assert_eq!(
            verify_ed25519(&two_line_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-043-06: bad sig first, valid second — must continue and find good sig"
        );
    }

    // T-043-07: wrong key name on all lines
    #[test]
    fn t_043_07_ed25519_wrong_key_name_all_lines_returns_invalid() {
        let note_text = "go.sum database tree\n500\nabc=\n";
        // Note is signed with "other.registry.dev"; verify with "sum.golang.org".
        let (_key_str, _sk, signed_note) =
            build_ed25519_signed_note_named(note_text, "other.registry.dev");

        // Build a key_str with the expected key name.
        let (key_str_sumdb, _sk2, _) = build_ed25519_signed_note_named(note_text, "sum.golang.org");

        match verify_ed25519(&signed_note, &key_str_sumdb) {
            NoteVerifyOutcome::Invalid { reason } => {
                assert!(
                    reason.contains("no signature line found for key 'sum.golang.org'"),
                    "T-043-07: wrong key name — reason should mention key name, got: {reason}"
                );
            }
            other => panic!("T-043-07: expected Invalid, got {other:?}"),
        }
    }

    // T-043-08: regression — go_sumdb single-signature behavior still works
    // (duplicates the existing round-trip test with explicit spec markers)
    #[test]
    fn t_043_08_ed25519_regression_single_sig_paths() {
        let note_text = "go.sum database tree\n12345\nabc\n";

        // Happy path.
        let (key_str, _sk, signed_note) = build_ed25519_signed_note_named(note_text, "test-key");
        assert_eq!(
            verify_ed25519(&signed_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-043-08 happy path"
        );

        // Tampered signature (flip last byte of sig payload).
        let parsed = parse(&signed_note).expect("parse");
        let sig = &parsed.signatures[0];
        let mut tampered_payload = sig.key_id.to_vec();
        tampered_payload.extend_from_slice(&sig.sig_bytes);
        // Flip a byte in the sig portion.
        let last = tampered_payload.len() - 1;
        tampered_payload[last] ^= 0xff;
        let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(&tampered_payload);
        let tampered_note = format!("{note_text}\n\u{2014} test-key {tampered_b64}\n");
        match verify_ed25519(&tampered_note, &key_str) {
            NoteVerifyOutcome::Invalid { .. } => {}
            other => panic!("T-043-08 tampered: expected Invalid, got {other:?}"),
        }

        // Wrong key.
        let (key_str2, _sk2, _) = build_ed25519_signed_note_named(note_text, "test-key");
        match verify_ed25519(&signed_note, &key_str2) {
            NoteVerifyOutcome::Invalid { .. } => {}
            other => panic!("T-043-08 wrong key: expected Invalid, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // T-043-09 through T-043-13: verify_ecdsa_p256 multi-sig iteration tests
    // -----------------------------------------------------------------------

    // T-043-09: single ECDSA signature, correct key, verifies
    #[test]
    fn t_043_09_ecdsa_single_sig_correct_key_verifies() {
        let note_text = "rekor.sigstore.dev - 1\n42\nabc=\n";
        let (pem, _sk, signed_note) =
            build_ecdsa_p256_signed_note_full(note_text, "rekor.sigstore.dev");
        assert_eq!(
            verify_ecdsa_p256(&signed_note, "rekor.sigstore.dev", &pem),
            NoteVerifyOutcome::Valid,
            "T-043-09: single correct ECDSA signature must verify"
        );
    }

    // T-043-10: two lines — old Rekor key first, new Rekor key second; pinned = new
    #[test]
    fn t_043_10_ecdsa_two_lines_old_first_new_second_verifies() {
        let note_text = "rekor.sigstore.dev - 2\n100\nxyz=\n";
        let key_name = "rekor.sigstore.dev";

        let (_, _sk_old, note_old) = build_ecdsa_p256_signed_note_full(note_text, key_name);
        let old_sig_line = extract_sig_line(&note_old).to_string();

        let (pem_new, _sk_new, note_new) = build_ecdsa_p256_signed_note_full(note_text, key_name);
        let new_sig_line = extract_sig_line(&note_new).to_string();

        // Old key first.
        let two_line_note = format!("{note_text}\n{old_sig_line}\n{new_sig_line}\n");

        assert_eq!(
            verify_ecdsa_p256(&two_line_note, key_name, &pem_new),
            NoteVerifyOutcome::Valid,
            "T-043-10: old ECDSA key first, new second — must find pinned key and verify"
        );
    }

    // T-043-11: two ECDSA lines, both with wrong key-ids
    #[test]
    fn t_043_11_ecdsa_two_lines_both_wrong_key_id_returns_invalid() {
        let note_text = "rekor.sigstore.dev - 3\n200\nabc=\n";
        let key_name = "rekor.sigstore.dev";

        let (_, _sk_a, note_a) = build_ecdsa_p256_signed_note_full(note_text, key_name);
        let sig_a = extract_sig_line(&note_a).to_string();
        let (_, _sk_b, note_b) = build_ecdsa_p256_signed_note_full(note_text, key_name);
        let sig_b = extract_sig_line(&note_b).to_string();

        // Pinned key is independent of both sig lines.
        let (pem_pinned, _sk_pinned, _) = build_ecdsa_p256_signed_note_full(note_text, key_name);

        let two_line_note = format!("{note_text}\n{sig_a}\n{sig_b}\n");

        match verify_ecdsa_p256(&two_line_note, key_name, &pem_pinned) {
            NoteVerifyOutcome::Invalid { .. } => {}
            other => panic!("T-043-11: expected Invalid, got {other:?}"),
        }
    }

    // T-043-12: correct key-id, bad DER on first; valid second line
    #[test]
    fn t_043_12_ecdsa_bad_der_first_valid_second_verifies() {
        use p256::pkcs8::EncodePublicKey;
        let note_text = "rekor.sigstore.dev - 4\n300\nabc=\n";
        let key_name = "rekor.sigstore.dev";

        // Build the pinned key.
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pem = verifying_key
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .expect("encode pem");
        let spki_der = pem_to_spki_der(&pem).expect("extract spki");
        let mut hasher = Sha256::new();
        hasher.update(&spki_der);
        let key_id_full = hasher.finalize();
        let key_id = &key_id_full[..4];

        // Build a bad-DER line: same key-id, but `sig_bytes` is not valid DER.
        let mut bad_payload = key_id.to_vec();
        bad_payload.extend_from_slice(&[0xdeu8, 0xad, 0xbe, 0xef]); // garbage DER
        let bad_b64 = base64::engine::general_purpose::STANDARD.encode(&bad_payload);
        let bad_sig_line = format!("\u{2014} {key_name} {bad_b64}");

        // Build a valid sig line.
        let valid_sig: p256::ecdsa::Signature =
            P256Signer::sign(&signing_key, note_text.as_bytes());
        let valid_der = valid_sig.to_der();
        let mut good_payload = key_id.to_vec();
        good_payload.extend_from_slice(valid_der.as_bytes());
        let good_b64 = base64::engine::general_purpose::STANDARD.encode(&good_payload);
        let good_sig_line = format!("\u{2014} {key_name} {good_b64}");

        let two_line_note = format!("{note_text}\n{bad_sig_line}\n{good_sig_line}\n");

        assert_eq!(
            verify_ecdsa_p256(&two_line_note, key_name, &pem),
            NoteVerifyOutcome::Valid,
            "T-043-12: bad DER first, valid second — must continue past DER failure"
        );
    }

    // T-043-13: regression — Rekor ECDSA single-signature behavior still works
    #[test]
    fn t_043_13_ecdsa_regression_single_sig_paths() {
        let note_text = "rekor.sigstore.dev - 5\n999\nabc=\n";
        let key_name = "rekor.sigstore.dev";

        // Happy path.
        let (pem, _sk, signed_note) = build_ecdsa_p256_signed_note_full(note_text, key_name);
        assert_eq!(
            verify_ecdsa_p256(&signed_note, key_name, &pem),
            NoteVerifyOutcome::Valid,
            "T-043-13 happy path"
        );

        // Tampered sig — reuse T-036-09 pattern.
        let tampered: String = signed_note
            .lines()
            .map(|l| {
                if l.starts_with('\u{2014}') {
                    let mut chars: Vec<char> = l.chars().collect();
                    let idx = chars.len() - 2;
                    chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
                    chars.into_iter().collect()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        match verify_ecdsa_p256(&tampered, key_name, &pem) {
            NoteVerifyOutcome::Invalid { .. } => {}
            other => panic!("T-043-13 tampered: expected Invalid, got {other:?}"),
        }

        // Wrong key.
        let (pem2, _sk2, _) = build_ecdsa_p256_signed_note_full(note_text, key_name);
        match verify_ecdsa_p256(&signed_note, key_name, &pem2) {
            NoteVerifyOutcome::Invalid { .. } => {}
            other => panic!("T-043-13 wrong key: expected Invalid, got {other:?}"),
        }
    }
}

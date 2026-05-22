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

    for sig in &parsed.signatures {
        if sig.key_name != key_name {
            continue;
        }
        if sig.key_id != expected_key_id {
            return NoteVerifyOutcome::Invalid {
                reason: format!(
                    "signature key ID {:02x}{:02x}{:02x}{:02x} does not match pinned key ID {:02x}{:02x}{:02x}{:02x}",
                    sig.key_id[0],
                    sig.key_id[1],
                    sig.key_id[2],
                    sig.key_id[3],
                    expected_key_id[0],
                    expected_key_id[1],
                    expected_key_id[2],
                    expected_key_id[3],
                ),
            };
        }
        if sig.sig_bytes.len() != 64 {
            return NoteVerifyOutcome::Invalid {
                reason: format!(
                    "Ed25519 signature payload must be exactly 64 bytes after the key-id, got {}",
                    sig.sig_bytes.len()
                ),
            };
        }
        let sig_arr: [u8; 64] = sig
            .sig_bytes
            .as_slice()
            .try_into()
            .expect("len == 64 by check above");
        let signature = Ed25519Signature::from_bytes(&sig_arr);
        return match Verifier::verify(&verifying_key, parsed.note_text.as_bytes(), &signature) {
            Ok(()) => NoteVerifyOutcome::Valid,
            Err(e) => NoteVerifyOutcome::Invalid {
                reason: format!("Ed25519 signature verification failed: {e}"),
            },
        };
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

    for sig in &parsed.signatures {
        if sig.key_name != expected_key_name {
            continue;
        }
        if sig.key_id != expected_key_id {
            return NoteVerifyOutcome::Invalid {
                reason: format!(
                    "signature key ID {:02x}{:02x}{:02x}{:02x} does not match pinned key ID {:02x}{:02x}{:02x}{:02x}",
                    sig.key_id[0],
                    sig.key_id[1],
                    sig.key_id[2],
                    sig.key_id[3],
                    expected_key_id[0],
                    expected_key_id[1],
                    expected_key_id[2],
                    expected_key_id[3],
                ),
            };
        }
        let signature = match P256Signature::from_der(&sig.sig_bytes) {
            Ok(s) => s,
            Err(e) => {
                return NoteVerifyOutcome::Invalid {
                    reason: format!("malformed ECDSA P-256 DER signature: {e}"),
                };
            }
        };
        return match P256Verifier::verify(&verifying_key, parsed.note_text.as_bytes(), &signature) {
            Ok(()) => NoteVerifyOutcome::Valid,
            Err(e) => NoteVerifyOutcome::Invalid {
                reason: format!("ECDSA P-256 signature verification failed: {e}"),
            },
        };
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
}

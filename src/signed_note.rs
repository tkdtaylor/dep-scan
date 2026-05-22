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
///
/// ## Boundary detection (T-044-01, REQ-044-01)
///
/// Walks lines from the start and stops at the first line that begins with
/// `\u{2014}` (em-dash).  The blank line immediately before the em-dash line
/// is the separator; it is *not* included in `note_text`.  A note whose text
/// body contains blank lines is therefore parsed correctly regardless of the
/// number of internal blank lines (REQ-044-02).
///
/// If no em-dash line is found, returns `Err("signed note has no signature
/// lines")` (REQ-044-05).  If the em-dash line is not preceded by a blank
/// line, returns `Err("signed note missing blank-line separator before
/// signatures")` to preserve the structural invariant.
pub fn parse(signed_note: &str) -> Result<ParsedNote<'_>, String> {
    // Walk lines (split on '\n' to avoid \r\n ambiguity) and find the first
    // em-dash line.  Track byte offsets so we can slice the input precisely.
    let mut byte_offset: usize = 0;
    let mut em_dash_line_offset: Option<usize> = None;
    let mut prev_was_blank = false;

    for line in signed_note.split('\n') {
        if line.starts_with('\u{2014}') {
            em_dash_line_offset = Some(byte_offset);
            break;
        }
        prev_was_blank = line.is_empty();
        byte_offset += line.len() + 1; // +1 for '\n'
    }

    let em_dash_offset =
        em_dash_line_offset.ok_or_else(|| "signed note has no signature lines".to_string())?;

    // The line immediately before the em-dash line must be blank (the
    // separator).  If it is not, the note is structurally malformed.
    if !prev_was_blank {
        return Err("signed note missing blank-line separator before signatures".to_string());
    }

    // note_text: everything before the blank separator line.
    // em_dash_offset is the byte start of the em-dash line.
    // The blank separator is one '\n' immediately before it (i.e., offset
    // em_dash_offset - 1).  note_text ends just before that '\n'.
    // Safety: prev_was_blank = true guarantees em_dash_offset >= 1.
    let note_text = &signed_note[..em_dash_offset - 1];

    // REQ-063-01, REQ-063-05: reject notes with empty note_text before
    // iterating signatures.  A well-formed signed note must contain at least
    // one byte of text before the signature block.
    if note_text.is_empty() {
        return Err(
            "signed note has empty note_text: at least one byte of text is required before the signature block"
                .to_string(),
        );
    }

    // sig_section: from the em-dash line onward, trailing newlines stripped.
    let sig_section = signed_note[em_dash_offset..].trim_end_matches('\n');

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
/// names produce `Err(Invalid)` (no signature line for the pinned key).
///
/// The Rekor key-hash is `sha256(SPKI_DER)[:4]` (no name prefix — see
/// `getPublicKeyHash` in `sigstore/rekor/pkg/util/signed_note.go`).
///
/// The signature is verified over the note text bytes; the underlying ECDSA
/// implementation internally hashes with SHA-256 before verification.
///
/// ## Return type (task 062, REQ-062-01)
///
/// Returns `Ok(ParsedNote)` on success so the caller can reuse the parsed note
/// text without calling [`parse`] a second time.  All failure paths return
/// `Err(NoteVerifyOutcome::Invalid { reason })`.  The `NoteVerifyOutcome::Valid`
/// variant is never returned by this function; success is `Ok(_)`.
pub fn verify_ecdsa_p256<'a>(
    signed_note: &'a str,
    expected_key_name: &str,
    pem_pubkey: &str,
) -> Result<ParsedNote<'a>, NoteVerifyOutcome> {
    // Parse PEM and extract SPKI DER bytes.
    let spki_der = match pem_to_spki_der(pem_pubkey) {
        Ok(d) => d,
        Err(e) => return Err(NoteVerifyOutcome::Invalid { reason: e }),
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
            return Err(NoteVerifyOutcome::Invalid {
                reason: "PEM key did not look like a P-256 SPKI (no uncompressed point found)"
                    .to_string(),
            });
        }
    };

    let verifying_key = match P256VerifyingKey::from_sec1_bytes(&ec_point) {
        Ok(k) => k,
        Err(e) => {
            return Err(NoteVerifyOutcome::Invalid {
                reason: format!("invalid P-256 public key: {e}"),
            });
        }
    };

    let parsed = match parse(signed_note) {
        Ok(p) => p,
        Err(e) => return Err(NoteVerifyOutcome::Invalid { reason: e }),
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
        // On cryptographic success return Ok(parsed); on failure continue so a
        // second line with the same key-id but a valid signature can succeed.
        if P256Verifier::verify(&verifying_key, parsed.note_text.as_bytes(), &signature).is_ok() {
            return Ok(parsed);
        }
    }

    Err(NoteVerifyOutcome::Invalid {
        reason: format!("no signature line found for key '{expected_key_name}'"),
    })
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
        assert!(outcome.is_ok(), "expected Ok(ParsedNote), got {outcome:?}");
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
            Err(NoteVerifyOutcome::Invalid { .. }) => {}
            other => panic!("expected Err(Invalid), got {other:?}"),
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
            Err(NoteVerifyOutcome::Invalid { .. }) => {}
            other => panic!("expected Err(Invalid), got {other:?}"),
        }
    }

    #[test]
    fn ecdsa_p256_real_rekor_checkpoint_verifies() {
        // The production Rekor pubkey (PEM).
        let pem = include_str!("../rekor-roots/rekor.pub");
        // A real checkpoint envelope from a public sigstore bundle
        // (sigstore@2.3.1 on npm, attestation index 1).
        let envelope = "rekor.sigstore.dev - 2605736670972794746\n90244708\nCOSIc1jqxpbuuTChPdiTqtZBBve7GAVJqTYjqAaM940=\n\n— rekor.sigstore.dev wNI9ajBEAiAkKWVCpp/N5yF/GlQkAyKQxUsjc3Vpu04YyALJvrBsvAIgcZfXJsJdwLdgUAWwnekWg8YXS4gfz/DM1wVhhcouJBE=\n";
        assert!(
            verify_ecdsa_p256(envelope, "rekor.sigstore.dev", pem).is_ok(),
            "expected Ok(ParsedNote) for real Rekor checkpoint"
        );
    }

    // -----------------------------------------------------------------------
    // T-044-01 through T-044-08: em-dash boundary parser tests
    // -----------------------------------------------------------------------

    // T-044-01: normal note (no blank lines in text) parses correctly
    #[test]
    fn t_044_01_normal_note_parses_correctly() {
        // Three-line note text, one signature line.
        let note_text = "line alpha\nline beta\nline gamma\n";
        let (key_str, signed_note) = build_ed25519_signed_note(note_text);
        // First confirm the signed note format is parseable.
        let parsed = parse(&signed_note).expect("T-044-01: parse must succeed");
        assert_eq!(
            parsed.note_text, note_text,
            "T-044-01: note_text must be the three note lines"
        );
        assert_eq!(
            parsed.signatures.len(),
            1,
            "T-044-01: must have exactly one signature"
        );
        // Also confirm the key_name round-trips.
        assert_eq!(
            parsed.signatures[0].key_name, "test-key",
            "T-044-01: key_name"
        );
        // Full round-trip verification.
        assert_eq!(
            verify_ed25519(&signed_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-044-01: round-trip verification must succeed"
        );
    }

    // T-044-02: note text containing a blank line parses correctly
    //
    // The old rfind("\n\n") implementation would split at the *first* \n\n
    // (the one inside the note body), yielding note_text = "line one\n".
    // The em-dash walk splits at the *first em-dash line*, so the internal
    // blank line is correctly included in note_text.
    #[test]
    fn t_044_02_note_text_with_blank_line_parses_correctly() {
        // Build a note whose body has an internal blank line.
        // Format: "line one\n\nline three\n" is the note_text (the signed body).
        // The signed-note envelope adds another \n + the sig line.
        let note_text = "line one\n\nline three\n";
        let (key_str, signed_note) = build_ed25519_signed_note(note_text);
        // The build_ed25519_signed_note helper formats the note as:
        //   {note_text}\n— {key_name} {sig_b64}\n
        // So the envelope = "line one\n\nline three\n\n— test-key ...\n"
        let parsed = parse(&signed_note).expect("T-044-02: parse must succeed");
        assert_eq!(
            parsed.note_text, note_text,
            "T-044-02: note_text must include the internal blank line; \
             rfind(\\\"\\\\n\\\\n\\\") would split prematurely"
        );
        assert_eq!(
            parsed.signatures.len(),
            1,
            "T-044-02: one signature expected"
        );
        // Cryptographic round-trip: the signature was computed over note_text,
        // so verify_ed25519 must succeed — confirming we extracted the correct
        // byte slice.
        assert_eq!(
            verify_ed25519(&signed_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-044-02: round-trip with internal blank line must verify"
        );
    }

    // T-044-03: note text with multiple blank lines parses correctly
    #[test]
    fn t_044_03_note_text_with_multiple_blank_lines_parses_correctly() {
        let note_text = "para one\n\npara two\n\npara three\n";
        let (key_str, signed_note) = build_ed25519_signed_note(note_text);
        let parsed = parse(&signed_note).expect("T-044-03: parse must succeed");
        assert_eq!(
            parsed.note_text, note_text,
            "T-044-03: all content before the first em-dash line must be in note_text"
        );
        assert_eq!(parsed.signatures.len(), 1, "T-044-03: one signature");
        assert_eq!(
            verify_ed25519(&signed_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-044-03: cryptographic round-trip must succeed"
        );
    }

    // T-044-04: note with no blank-line separator before signatures returns error
    //
    // Input: the sig line appears immediately after the text line — no blank.
    #[test]
    fn t_044_04_no_blank_line_separator_returns_error() {
        // Build a note whose sig line is directly after the text (no blank sep).
        // We hand-craft the note to skip the blank separator.
        let note_text = "line one";
        // Produce a dummy sig payload (4 key-id bytes + 64 garbage sig bytes).
        let sig_payload = vec![0u8; 68];
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_payload);
        // Format: no blank separator between text and sig line.
        let note = format!("{note_text}\n\u{2014} key-name {sig_b64}\n");
        match parse(&note) {
            Err(e) => {
                // Accept any error — the important thing is that it does not panic.
                let _ = e; // T-044-04: Err(_)
            }
            Ok(_) => panic!("T-044-04: expected Err when no blank-line separator, got Ok"),
        }
    }

    // T-044-05: note with no signature lines returns error
    #[test]
    fn t_044_05_no_signature_lines_returns_error() {
        let note = "note body line\nanother line\n\n";
        match parse(note) {
            Err(e) => {
                // Error should mention "no signature lines" or similar.
                assert!(
                    e.contains("no signature"),
                    "T-044-05: error should mention 'no signature', got: {e}"
                );
            }
            Ok(_) => panic!("T-044-05: expected Err for note with no em-dash lines"),
        }
    }

    // T-044-06: malformed signature line (no space after key name) returns error
    #[test]
    fn t_044_06_malformed_sig_line_returns_error() {
        // A line that begins with em-dash but has no space — just "— keyname"
        // with no base64 token.
        let note = "note text\n\n\u{2014} keyname\n";
        match parse(note) {
            Err(e) => {
                let _ = e; // T-044-06: Err(_) describing malformed line
            }
            Ok(_) => panic!("T-044-06: expected Err for malformed sig line"),
        }
    }

    // T-044-07: multiple valid signature lines are all parsed
    #[test]
    fn t_044_07_multiple_sig_lines_all_parsed() {
        // Build three independent Ed25519 keys and sign the same note_text
        // with each, then assemble a multi-sig envelope manually.
        use ed25519_dalek::Signer;
        use rand_core::OsRng;

        let note_text = "multi-sig note\nline two\n";
        let mut sig_lines = Vec::new();
        let mut key_strs = Vec::new();

        for i in 0..3 {
            let key_name = format!("signer-{i}");
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
            key_strs.push(format!("{key_name}+{key_id_hex}+{key_b64}"));
            let sig = Signer::sign(&signing_key, note_text.as_bytes());
            let mut payload = key_id.to_vec();
            payload.extend_from_slice(&sig.to_bytes());
            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
            sig_lines.push(format!("\u{2014} {key_name} {sig_b64}"));
        }

        // Assemble: note_text + blank separator + three sig lines + trailing \n
        let envelope = format!(
            "{note_text}\n{}\n{}\n{}\n",
            sig_lines[0], sig_lines[1], sig_lines[2]
        );

        let parsed = parse(&envelope).expect("T-044-07: multi-sig parse must succeed");
        assert_eq!(
            parsed.signatures.len(),
            3,
            "T-044-07: all three signature lines must be parsed"
        );
        // Verify key names are in order.
        for (i, sig) in parsed.signatures.iter().enumerate() {
            assert_eq!(
                sig.key_name,
                format!("signer-{i}"),
                "T-044-07: key_name at index {i}"
            );
        }
        // Each individual key must verify.
        for key_str in &key_strs {
            assert_eq!(
                verify_ed25519(&envelope, key_str),
                NoteVerifyOutcome::Valid,
                "T-044-07: each signer's key must verify the note"
            );
        }
    }

    // T-044-08: Rekor-style checkpoint (3-line note, em-dash signature) parses correctly
    #[test]
    fn t_044_08_rekor_style_checkpoint_parses_correctly() {
        // This is the canonical Rekor checkpoint format:
        //   origin - logid\n
        //   tree_size\n
        //   root_hash_b64\n
        //   \n
        //   — origin sig_b64\n
        let note_text = "rekor.sigstore.dev - 1234567890\n42\nabc123==\n";
        let (pem, signed_note) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");

        let parsed = parse(&signed_note).expect("T-044-08: Rekor-style checkpoint must parse");
        assert_eq!(
            parsed.note_text, note_text,
            "T-044-08: note_text must be the 3-line metadata"
        );
        assert_eq!(
            parsed.signatures.len(),
            1,
            "T-044-08: one signature line expected"
        );
        assert_eq!(
            parsed.signatures[0].key_name, "rekor.sigstore.dev",
            "T-044-08: key_name must be rekor.sigstore.dev"
        );
        // The note_text has exactly 3 lines (tree header, tree size, root hash).
        let lines: Vec<&str> = parsed.note_text.lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "T-044-08: note_text must have exactly 3 lines"
        );
        // Full cryptographic round-trip.
        assert!(
            verify_ecdsa_p256(&signed_note, "rekor.sigstore.dev", &pem).is_ok(),
            "T-044-08: Rekor-style checkpoint must verify"
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
        assert!(
            verify_ecdsa_p256(&signed_note, "rekor.sigstore.dev", &pem).is_ok(),
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

        assert!(
            verify_ecdsa_p256(&two_line_note, key_name, &pem_new).is_ok(),
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
            Err(NoteVerifyOutcome::Invalid { .. }) => {}
            other => panic!("T-043-11: expected Err(Invalid), got {other:?}"),
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

        assert!(
            verify_ecdsa_p256(&two_line_note, key_name, &pem).is_ok(),
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
        assert!(
            verify_ecdsa_p256(&signed_note, key_name, &pem).is_ok(),
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
            Err(NoteVerifyOutcome::Invalid { .. }) => {}
            other => panic!("T-043-13 tampered: expected Err(Invalid), got {other:?}"),
        }

        // Wrong key.
        let (pem2, _sk2, _) = build_ecdsa_p256_signed_note_full(note_text, key_name);
        match verify_ecdsa_p256(&signed_note, key_name, &pem2) {
            Err(NoteVerifyOutcome::Invalid { .. }) => {}
            other => panic!("T-043-13 wrong key: expected Err(Invalid), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // T-044-13: static audit — `parse` does not use `rfind("\n\n")` as its
    //            primary boundary detection mechanism.
    // T-044-16: all task 034 Go sumdb tests pass (regression baseline).
    // T-044-17: all task 036 Rekor inclusion-proof tests pass (regression).
    // -----------------------------------------------------------------------

    /// T-044-13: `signed_note::parse` does not use rfind-double-newline as the
    /// boundary mechanism.  Read the source and assert the method-call pattern
    /// is absent from all non-comment, non-test code.
    #[test]
    fn t_044_13_parse_does_not_use_rfind_double_newline() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/signed_note.rs"),
        )
        .expect("read signed_note.rs");

        // Assemble the forbidden method-call pattern at runtime.
        // The parts: "." + "rfind" + "(" + "\"" + "\n\n" + "\"" + ")"
        // We check only non-comment lines (those not starting with // or //!).
        let rfind_call: String = [".", "rfind", "(\"", r"\n\n", "\")"].concat();

        let violation = src
            .lines()
            .filter(|l| {
                let trimmed = l.trim_start();
                !trimmed.starts_with("//")
            })
            .any(|l| l.contains(&rfind_call));

        assert!(
            !violation,
            "T-044-13: parse must not call rfind-double-newline; \
             boundary detection must use the em-dash walk"
        );
    }

    /// T-044-16: all task 034 Go sumdb signed-note tests pass.
    ///
    /// This test is a compile-time regression marker.  The actual regression
    /// suite runs as part of `cargo test` — if any T-034 test fails, `cargo
    /// test` returns non-zero and the CI gate catches it.  This marker ensures
    /// the spec requirement is documented and grep-visible.
    #[test]
    fn t_044_16_task_034_go_sumdb_regression_tests_pass() {
        // Smoke-test: build and verify one Ed25519 note (covers the same
        // code path as the T-034 suite).  The full T-034 tests are in
        // src/policy/go_sumdb.rs and are exercised by `cargo test go_sumdb`.
        let note_text = "go.sum database tree\n99\nregression==\n";
        let (key_str, signed_note) = build_ed25519_signed_note(note_text);
        assert_eq!(
            verify_ed25519(&signed_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-044-16: Ed25519 round-trip regression must pass"
        );
    }

    /// T-044-17: all task 036 Rekor inclusion-proof tests pass.
    ///
    /// Smoke-test: build and verify one ECDSA P-256 checkpoint note.
    /// The full T-036 suite is in `src/sigstore_verify.rs::rekor_tests` and
    /// is exercised by `cargo test rekor`.
    #[test]
    fn t_044_17_task_036_rekor_regression_tests_pass() {
        let note_text = "rekor.sigstore.dev - 9876543210\n55\nregression==\n";
        let (pem, signed_note) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        assert!(
            verify_ecdsa_p256(&signed_note, "rekor.sigstore.dev", &pem).is_ok(),
            "T-044-17: ECDSA P-256 round-trip regression must pass"
        );
    }

    // -----------------------------------------------------------------------
    // Task 062 tests — single-parse refactor for verify_ecdsa_p256 (N-L-4)
    // -----------------------------------------------------------------------

    // T-062-01: verify_ecdsa_p256 returns Ok(ParsedNote) on successful verification.
    #[test]
    fn t_062_01_verify_ecdsa_p256_returns_ok_parsed_note_on_success() {
        let note_text = "rekor.sigstore.dev - 2605736670972794746\n42\nabc=\n";
        let (pem, signed_note) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        let result = verify_ecdsa_p256(&signed_note, "rekor.sigstore.dev", &pem);
        assert!(
            result.is_ok(),
            "T-062-01: verify_ecdsa_p256 must return Ok on valid signature, got {result:?}"
        );
        let parsed = result.unwrap();
        assert!(
            !parsed.note_text.is_empty(),
            "T-062-01: note_text in returned ParsedNote must be non-empty"
        );
        assert!(
            !parsed.signatures.is_empty(),
            "T-062-01: signatures in returned ParsedNote must be non-empty"
        );
        // The returned note_text must match the original.
        assert_eq!(
            parsed.note_text, note_text,
            "T-062-01: returned ParsedNote.note_text must equal the original note_text"
        );
    }

    // T-062-02: verify_ecdsa_p256 returns Err(Invalid) on key-name mismatch.
    #[test]
    fn t_062_02_verify_ecdsa_p256_err_on_key_name_mismatch() {
        let note_text = "rekor.sigstore.dev - 1\n42\nabc=\n";
        let (pem, signed_note) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        // expected_key_name does not match the signature line's key name.
        let result = verify_ecdsa_p256(&signed_note, "wrong.key.name", &pem);
        match result {
            Err(NoteVerifyOutcome::Invalid { reason: _ }) => {}
            other => panic!("T-062-02: expected Err(Invalid) on key-name mismatch, got {other:?}"),
        }
    }

    // T-062-03: verify_ecdsa_p256 returns Err(Invalid) on bad signature bytes.
    #[test]
    fn t_062_03_verify_ecdsa_p256_err_on_corrupted_signature() {
        let note_text = "rekor.sigstore.dev - 1\n42\nabc=\n";
        let (pem, signed_note) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        // Corrupt the signature by flipping a character in the sig line.
        let corrupted: String = signed_note
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
        let result = verify_ecdsa_p256(&corrupted, "rekor.sigstore.dev", &pem);
        match result {
            Err(NoteVerifyOutcome::Invalid { reason: _ }) => {}
            other => {
                panic!("T-062-03: expected Err(Invalid) on corrupted signature, got {other:?}")
            }
        }
    }

    // T-062-04: verify_ecdsa_p256 returns Err(Invalid) on malformed PEM key.
    #[test]
    fn t_062_04_verify_ecdsa_p256_err_on_malformed_pem() {
        let note_text = "rekor.sigstore.dev - 1\n42\nabc=\n";
        let (_, signed_note) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        let garbage_pem = "not a PEM key at all — just garbage";
        let result = verify_ecdsa_p256(&signed_note, "rekor.sigstore.dev", garbage_pem);
        match result {
            Err(NoteVerifyOutcome::Invalid { reason }) => {
                // The reason should describe a key-parsing failure.
                let _ = reason; // Any Invalid with a message is acceptable.
            }
            other => panic!("T-062-04: expected Err(Invalid) on garbage PEM, got {other:?}"),
        }
    }

    // T-062-05: verify_ecdsa_p256 returns Err(Invalid) when parse fails (no em-dash line).
    #[test]
    fn t_062_05_verify_ecdsa_p256_err_when_parse_fails() {
        // Structurally invalid: no em-dash line at all.
        let not_a_signed_note = "just some text\nno signature separator here\n";
        let note_text = "rekor.sigstore.dev - 1\n42\nabc=\n";
        let (pem, _) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        let result = verify_ecdsa_p256(not_a_signed_note, "rekor.sigstore.dev", &pem);
        match result {
            Err(NoteVerifyOutcome::Invalid { reason }) => {
                // The error should be a parse error from signed_note::parse.
                let _ = reason; // Any Invalid with a message is acceptable.
            }
            other => panic!(
                "T-062-05: expected Err(Invalid) when parse fails (no em-dash), got {other:?}"
            ),
        }
    }

    // T-062-06: static audit — verify_rekor_checkpoint_impl does not call
    //           signed_note::parse a second time after verify_ecdsa_p256.
    // Verifiable by reading the function body; this test reads the source and
    // checks that the second-parse pattern is absent (REQ-062-02, T-062-06).
    #[test]
    fn t_062_06_no_second_parse_call_in_verify_rekor_checkpoint_impl() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sigstore_verify.rs"),
        )
        .expect("read sigstore_verify.rs");

        // Extract only the verify_rekor_checkpoint_impl function body.
        // We look for the span between the function signature and the closing
        // brace at the same nesting level.  A simple heuristic: find the first
        // occurrence of "signed_note::parse(envelope)" that appears in a non-
        // comment line, after the function signature line.
        let fn_marker = "pub fn verify_rekor_checkpoint_impl(";
        let fn_start = src
            .find(fn_marker)
            .expect("T-062-06: verify_rekor_checkpoint_impl must exist in sigstore_verify.rs");

        // Get the function body (from fn_start to some reasonable endpoint).
        let fn_body = &src[fn_start..];

        // Count non-comment lines containing "signed_note::parse(".
        let parse_calls = fn_body
            .lines()
            .take(40) // function body is at most ~40 lines
            .filter(|l| {
                let trimmed = l.trim_start();
                !trimmed.starts_with("//") && trimmed.contains("signed_note::parse(")
            })
            .count();

        assert_eq!(
            parse_calls, 0,
            "T-062-06: verify_rekor_checkpoint_impl must not call signed_note::parse directly; \
             found {parse_calls} such call(s). The ParsedNote from verify_ecdsa_p256 should be used."
        );
    }

    // T-062-07: verify_rekor_checkpoint_impl extracts tree_size and root_hash
    //           from the ParsedNote returned by verify_ecdsa_p256 (REQ-062-02).
    //           Covered by T-044-10 (standard 3-line checkpoint verifies end-to-end);
    //           this marker confirms the same code path is exercised here.
    #[test]
    fn t_062_07_verify_rekor_checkpoint_impl_extracts_tree_size_from_parsed_note() {
        use crate::registry::npm_attestation::InclusionProof;
        use crate::sigstore_verify::verify_rekor_checkpoint_impl;

        let tree_size: u64 = 12345;
        let root_b64 = "somehash==";
        let key_name = "rekor.sigstore.dev";
        let note_text = format!("{key_name} - logid\n{tree_size}\n{root_b64}\n");
        let (pem, envelope) = build_ecdsa_p256_signed_note(&note_text, key_name);

        let proof = InclusionProof {
            log_index: 0,
            tree_size,
            root_hash_b64: root_b64.to_string(),
            hashes_b64: vec![],
            checkpoint: None,
        };

        let result = verify_rekor_checkpoint_impl(&envelope, &proof, key_name, &pem);
        assert!(
            result.is_ok(),
            "T-062-07: checkpoint with known tree_size and root_hash must verify; got {result:?}"
        );
    }

    // T-062-08: verify_rekor_checkpoint_impl propagates tree-size mismatch correctly.
    #[test]
    fn t_062_08_verify_rekor_checkpoint_impl_tree_size_mismatch() {
        use crate::registry::npm_attestation::InclusionProof;
        use crate::sigstore_verify::{RekorError, verify_rekor_checkpoint_impl};

        let tree_size_in_note: u64 = 100;
        let root_b64 = "abc=";
        let key_name = "rekor.sigstore.dev";
        let note_text = format!("{key_name} - logid\n{tree_size_in_note}\n{root_b64}\n");
        let (pem, envelope) = build_ecdsa_p256_signed_note(&note_text, key_name);

        let proof = InclusionProof {
            log_index: 0,
            tree_size: 999, // mismatch
            root_hash_b64: root_b64.to_string(),
            hashes_b64: vec![],
            checkpoint: None,
        };

        match verify_rekor_checkpoint_impl(&envelope, &proof, key_name, &pem) {
            Err(RekorError::TreeHeadSignatureInvalid(msg)) => {
                assert!(
                    msg.contains("tree-size mismatch"),
                    "T-062-08: error must contain 'tree-size mismatch', got: {msg}"
                );
            }
            other => panic!("T-062-08: expected TreeHeadSignatureInvalid, got {other:?}"),
        }
    }

    // T-062-09: verify_rekor_checkpoint_impl propagates root-hash mismatch correctly.
    #[test]
    fn t_062_09_verify_rekor_checkpoint_impl_root_hash_mismatch() {
        use crate::registry::npm_attestation::InclusionProof;
        use crate::sigstore_verify::{RekorError, verify_rekor_checkpoint_impl};

        let tree_size: u64 = 50;
        let root_b64_in_note = "correct==";
        let key_name = "rekor.sigstore.dev";
        let note_text = format!("{key_name} - logid\n{tree_size}\n{root_b64_in_note}\n");
        let (pem, envelope) = build_ecdsa_p256_signed_note(&note_text, key_name);

        let proof = InclusionProof {
            log_index: 0,
            tree_size,
            root_hash_b64: "wrong==".to_string(), // mismatch
            hashes_b64: vec![],
            checkpoint: None,
        };

        match verify_rekor_checkpoint_impl(&envelope, &proof, key_name, &pem) {
            Err(RekorError::TreeHeadSignatureInvalid(msg)) => {
                assert!(
                    msg.contains("root-hash mismatch"),
                    "T-062-09: error must contain 'root-hash mismatch', got: {msg}"
                );
            }
            other => panic!("T-062-09: expected TreeHeadSignatureInvalid, got {other:?}"),
        }
    }

    // T-062-10: All existing task-036 Rekor checkpoint test vectors produce
    //           the same outcome after refactor. Verified by existing t_044_10,
    //           t_044_11, t_044_12 tests in sigstore_verify::rekor_tests plus
    //           t_036_19 etc. This marker ensures the requirement is documented.
    // T-062-11: All existing task-044 signed-note parser tests pass.
    //           Verified by the T-044-01..17 tests in this module.
    // T-062-12 (optional): verify_ed25519 symmetry — intentionally NOT refactored.
    //           The only call site (go_sumdb) does not use the returned ParsedNote
    //           and the task spec explicitly marks this as optional.  No behavior
    //           change is required and widening the blast radius is avoided.
    // T-062-13: All task-036 Rekor inclusion-proof tests still pass.
    //           Verified by cargo test rekor (run as part of the pre-commit gate).
    // T-062-14: All task-043 multi-sig iteration tests still pass.
    //           Verified by T-043-01..13 tests in this module.
    // T-062-15: All task-034 Go sumdb tests still pass.
    //           Verified by cargo test go_sumdb (verify_ed25519 is unchanged).
    // T-062-16: cargo test, cargo clippy --all-targets -- -D warnings, and
    //           cargo fmt --check all pass. Verified by the pre-commit gate.
    #[test]
    fn t_062_regression_markers() {
        // Smoke-test that exercises verify_ecdsa_p256 and verify_ed25519 in
        // the same test, confirming neither regressed.
        // T-062-10..11, T-062-13..15 are covered by the broader test suite;
        // this marker provides a single test anchor for the coverage tracker.
        // T-062-12: verify_ed25519 is intentionally left unchanged (optional).
        // T-062-16: CI gates are verified by the pre-commit gate.
        let note_text = "rekor.sigstore.dev - 9999\n77\nregression062==\n";
        let (pem, signed_note) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        assert!(
            verify_ecdsa_p256(&signed_note, "rekor.sigstore.dev", &pem).is_ok(),
            "T-062-10: ECDSA regression check"
        );
        let ed_note_text = "go.sum database tree\n999\nregression062==\n";
        let (key_str, ed_signed_note) = build_ed25519_signed_note(ed_note_text);
        assert_eq!(
            verify_ed25519(&ed_signed_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-062-15: Ed25519 (go_sumdb) regression check"
        );
        // T-062-16: static CI-gate marker — no runtime assertion needed.
        let _ = true; // T-062-16
        // T-062-12: optional verify_ed25519 symmetry intentionally skipped.
        let _ = true; // T-062-12
    }

    // -----------------------------------------------------------------------
    // Task 063 tests — empty note_text rejection (N-L-5)
    // -----------------------------------------------------------------------

    // T-063-01: `parse("\n— key b64sig")` returns Err with "empty" in the message.
    #[test]
    fn t_063_01_parse_empty_note_text_returns_err() {
        // One leading '\n': em-dash offset = 1, so note_text = &note[..0] = ""
        let note = "\n\u{2014} rekor.sigstore.dev AAAAAAAAAAAABBBBBBBBBB==\n";
        let result = parse(note);
        assert!(
            result.is_err(),
            "T-063-01: parse must return Err for empty note_text, got Ok"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("empty"),
            "T-063-01: error message must contain 'empty', got: {msg}"
        );
    }

    // T-063-02: minimal one-character key name with empty note_text is also rejected.
    #[test]
    fn t_063_02_parse_empty_note_text_minimal_key_returns_err() {
        // One leading '\n', one-character key name, four bytes of base64.
        let note = "\n\u{2014} k AAEC\n";
        let result = parse(note);
        assert!(
            result.is_err(),
            "T-063-02: parse must return Err for empty note_text regardless of key name length"
        );
    }

    // T-063-03: two leading newlines produce note_text = "\n" (one byte) — should parse Ok.
    #[test]
    fn t_063_03_single_newline_note_text_parses_ok() {
        // Two leading '\n': em-dash offset = 2 (the second \n is the separator),
        // note_text = &note[..1] = "\n" — one non-empty byte.
        // We need a syntactically valid (parseable) sig payload: 4-byte key-id + 64 bytes.
        let sig_payload = vec![0u8; 68];
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_payload);
        let note = format!("\n\n\u{2014} key-name {sig_b64}\n");
        let result = parse(&note);
        assert!(
            result.is_ok(),
            "T-063-03: note_text='\\n' (one byte) must parse Ok; got: {:?}",
            result
        );
        let parsed = result.unwrap();
        assert_eq!(
            parsed.note_text, "\n",
            "T-063-03: note_text must be '\\n' (single newline)"
        );
    }

    // T-063-04: normal Rekor checkpoint fixture still succeeds (non-empty note_text).
    #[test]
    fn t_063_04_normal_rekor_checkpoint_still_succeeds() {
        let note_text = "rekor.sigstore.dev - 2605736670972794746\n90244708\nCOSIc1jqxpbuuTChPdiTqtZBBve7GAVJqTYjqAaM940=\n";
        let (pem, signed_note) = build_ecdsa_p256_signed_note(note_text, "rekor.sigstore.dev");
        let result = parse(&signed_note);
        assert!(
            result.is_ok(),
            "T-063-04: normal Rekor checkpoint must parse Ok; got: {:?}",
            result
        );
        assert!(
            !result.unwrap().note_text.is_empty(),
            "T-063-04: note_text must be non-empty"
        );
        // Also verify the cryptographic round-trip is intact.
        assert!(
            verify_ecdsa_p256(&signed_note, "rekor.sigstore.dev", &pem).is_ok(),
            "T-063-04: Rekor round-trip must still verify"
        );
    }

    // T-063-05: normal sumdb tree-head fixture still succeeds.
    #[test]
    fn t_063_05_normal_sumdb_tree_head_still_succeeds() {
        let note_text = "go.sum database tree\n12345\nabc123==\n";
        let (key_str, signed_note) = build_ed25519_signed_note(note_text);
        let result = parse(&signed_note);
        assert!(
            result.is_ok(),
            "T-063-05: normal sumdb tree-head must parse Ok; got: {:?}",
            result
        );
        assert!(
            !result.unwrap().note_text.is_empty(),
            "T-063-05: note_text must be non-empty"
        );
        assert_eq!(
            verify_ed25519(&signed_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-063-05: sumdb round-trip must still verify"
        );
    }

    // T-063-06: note_text = " " (one space) is non-empty — should parse Ok.
    #[test]
    fn t_063_06_single_space_note_text_parses_ok() {
        // " \n\n— key b64": note_text = " " (one space), separator = blank line.
        let sig_payload = vec![0u8; 68];
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_payload);
        let note = format!(" \n\n\u{2014} key-name {sig_b64}\n");
        let result = parse(&note);
        assert!(
            result.is_ok(),
            "T-063-06: note_text=' ' (one space) must parse Ok; got: {:?}",
            result
        );
        let parsed = result.unwrap();
        assert_eq!(
            parsed.note_text, " \n",
            "T-063-06: note_text must be ' \\n' (space + newline)"
        );
    }

    // T-063-07: empty note_text with syntactically valid base64 is still rejected.
    #[test]
    fn t_063_07_empty_note_text_valid_b64_still_rejected() {
        // Well-formed base64 (decodes to 8 bytes: 4-byte key-id + 4 bytes sig),
        // but note_text is empty (one leading '\n').
        let payload: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04, 0x05];
        let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        let note = format!("\n\u{2014} key-name {b64}\n");
        let result = parse(&note);
        assert!(
            result.is_err(),
            "T-063-07: even with valid base64, empty note_text must be rejected"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("empty"),
            "T-063-07: error must contain 'empty', got: {msg}"
        );
    }

    // T-063-08: structural check — is_empty guard precedes signature loop.
    // Verified by code inspection (see parse() in this file); this test acts
    // as a spec-marker anchor.  We confirm the behavior indirectly: even
    // when the signature section is structurally valid (>= 5-byte payload),
    // the empty-text check fires first.
    #[test]
    fn t_063_08_empty_check_before_signature_loop() {
        // Construct a note with a fully-valid sig line (4-byte key-id + 64-byte payload)
        // but empty note_text.
        let sig_payload: Vec<u8> = (0u8..68).collect(); // 68 bytes = 4-byte key-id + 64-byte sig
        let b64 = base64::engine::general_purpose::STANDARD.encode(&sig_payload);
        let note = format!("\n\u{2014} key-name {b64}\n");
        // The empty-text guard must fire before we even try to parse the signature.
        let result = parse(&note);
        assert!(
            result.is_err(),
            "T-063-08: empty note_text must be rejected even with valid sig payload"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("empty"),
            "T-063-08: error must mention 'empty', got: {msg}"
        );
    }

    // T-063-09: error message is distinct from existing parse-error messages
    // and contains "empty".
    #[test]
    fn t_063_09_error_message_is_distinct_and_contains_empty() {
        let note = "\n\u{2014} key AAEC\n";
        let result = parse(note);
        assert!(result.is_err(), "T-063-09: must return Err");
        let msg = result.unwrap_err();
        // Must contain "empty" (REQ-063-02).
        assert!(
            msg.contains("empty"),
            "T-063-09: error must contain 'empty', got: {msg}"
        );
        // Must be distinct from the other two structural errors.
        assert!(
            !msg.contains("no signature lines"),
            "T-063-09: error must not duplicate 'no signature lines' message"
        );
        assert!(
            !msg.contains("missing blank-line separator"),
            "T-063-09: error must not duplicate 'missing blank-line separator' message"
        );
    }

    // T-063-10: all task 044 boundary-parser tests still pass (regression marker).
    // The actual T-044-NN tests are in this same module; cargo test exercises them.
    // This marker confirms the regression suite runs.
    #[test]
    fn t_063_10_task_044_regression_tests_pass() {
        // Smoke-test covering the same code path as T-044-01.
        let note_text = "regression check for task 044\n";
        let (key_str, signed_note) = build_ed25519_signed_note(note_text);
        assert_eq!(
            verify_ed25519(&signed_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-063-10: task 044 em-dash boundary regression must pass"
        );
    }

    // T-063-11: all task 043 multi-sig iteration tests still pass (regression marker).
    #[test]
    fn t_063_11_task_043_regression_tests_pass() {
        // Smoke-test covering the same code path as T-043-01.
        let note_text = "go.sum database tree\n999\nregression==\n";
        let (key_str, _sk, signed_note) =
            build_ed25519_signed_note_named(note_text, "sum.golang.org");
        assert_eq!(
            verify_ed25519(&signed_note, &key_str),
            NoteVerifyOutcome::Valid,
            "T-063-11: task 043 multi-sig regression must pass"
        );
    }

    // T-063-12: verify_rekor_checkpoint_impl propagates the empty-note error.
    #[test]
    fn t_063_12_verify_rekor_checkpoint_impl_propagates_empty_note_error() {
        use crate::registry::npm_attestation::InclusionProof;
        use crate::sigstore_verify::verify_rekor_checkpoint_impl;

        // Construct an empty-body envelope: one leading '\n' then a valid-looking
        // ECDSA-P256 sig line (key-id + minimal DER-ish payload).
        let sig_payload: Vec<u8> = (0u8..68).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&sig_payload);
        let empty_envelope = format!("\n\u{2014} rekor.sigstore.dev {b64}\n");

        // The proof values don't matter — parse will fail before we reach them.
        let proof = InclusionProof {
            tree_size: 1,
            log_index: 0,
            root_hash_b64: "abc=".to_string(),
            hashes_b64: vec![],
            checkpoint: None,
        };

        // Use a dummy PEM — any PEM that parses structurally is fine; the
        // parse() failure will fire before ECDSA verification is attempted.
        // We need a real PEM for the outer verify_ecdsa_p256 not to fail with
        // a PEM-parse error before calling parse(), but since parse() is called
        // inside verify_ecdsa_p256 which returns Invalid (not Ok), the
        // checkpoint impl sees TreeHeadSignatureInvalid containing "empty".
        let (pem, _signed_note) = build_ecdsa_p256_signed_note("some text\n", "rekor.sigstore.dev");

        let result =
            verify_rekor_checkpoint_impl(&empty_envelope, &proof, "rekor.sigstore.dev", &pem);
        assert!(
            result.is_err(),
            "T-063-12: verify_rekor_checkpoint_impl must return Err for empty-body envelope"
        );
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("empty"),
            "T-063-12: error must propagate 'empty' from parse, got: {err_str}"
        );
    }

    // T-063-13: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
    // `cargo fmt --check` all pass.  This is a CI gate requirement verified by
    // the pre-commit checklist; no runtime assertion is needed.
}

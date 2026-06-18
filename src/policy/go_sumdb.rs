//! Go checksum database (sum.golang.org) signature verification policy (task 034).
//!
//! ## What this does
//!
//! On every Go module scan the `GoSumDbPolicy` evaluates the Ed25519 signature on the
//! tree head returned by `sum.golang.org/lookup/<module>@<version>`.  The public key
//! is embedded as a build-time constant so that a MITM or compromised sumdb mirror
//! cannot present a plausible forgery.
//!
//! The canonical source of the pinned key is Go's own distribution:
//! `cmd/go/internal/modfetch/sumdb/keys.go` (first shipped in Go 1.13).
//! Key rotation is announced in release notes; users must upgrade dep-scan to
//! pick up a new key.
//!
//! ## Signed-note format (golang.org/x/mod/sumdb/note)
//!
//! A sumdb lookup response has two logical sections separated by a blank line:
//!
//! ```text
//! <module> <version> h1:<base64>
//! <module> <version>/go.mod h1:<base64>
//!
//! go.sum database tree
//! <tree-size>
//! <tree-hash-base64>
//!
//! — <key-name> <sig-base64>
//! ```
//!
//! The signed note verification steps are:
//! 1. Split on `"\n\n"` to separate the hash lines from the signed note block.
//! 2. Within the note block, split on the final `"\n\n"` to separate the note
//!    text from the signature lines.
//! 3. The signature line is: `— <key-name> <sig-base64>` where `<sig-base64>`
//!    is `base64( [4-byte key-id] || [64-byte Ed25519 signature] )`.
//! 4. Verify: `Ed25519.Verify(public_key, note_text, signature[4..])`.
//!
//! The 4-byte key-id is the first 4 bytes of
//! `SHA256(key-name || "\n" || key-bytes)` (Go's `note.keyHash` — no `"hash:1:"`
//! prefix; see task 110), used to identify which key signed the note.  We verify
//! it matches our pinned key before accepting the signature.
//!
//! ## Policy outcomes
//!
//! | Condition                            | `require_go_sumdb = false` | `require_go_sumdb = true` |
//! |--------------------------------------|----------------------------|---------------------------|
//! | 404 (module not in sumdb)            | `Warn`                     | `Block`                   |
//! | Valid signature                      | `Pass`                     | `Pass`                    |
//! | Invalid / tampered signature         | `Block` (unconditional)    | `Block` (unconditional)   |
//! | Malformed response (no tree head)    | `Block` (unconditional)    | `Block` (unconditional)   |
//! | Network error                        | surfaced as scan error     | surfaced as scan error    |
//!
//! `require_go_sumdb = false` never silences a cryptographic failure —
//! only the "not in sumdb" case is configurable.

use std::sync::Arc;

use crate::policy::{Policy, PolicyResult};
use crate::signed_note::{self, NoteVerifyOutcome};
use crate::types::ScanContext;

// ---------------------------------------------------------------------------
// Pinned sum.golang.org Ed25519 public key
// ---------------------------------------------------------------------------

/// The full key string as it appears in Go's distribution.
///
/// Source: `cmd/go/internal/modfetch/key.go` (Go 1.13+):
/// ```go
/// var knownGOSUMDB = map[string]string{
///     "sum.golang.org": "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
/// }
/// ```
/// Format: `<key-name>+<key-id>+<key-base64>` where key-base64 decodes to
/// `[0x01 (Ed25519 algo marker)] || [32-byte Ed25519 public key]` (33 bytes total).
///
/// Key rotation: if Google rotates the sumdb key, a new dep-scan release
/// is required.  Monitor https://go.googlesource.com/go/+/refs/heads/master/src/cmd/go/internal/modfetch/key.go
/// or the Go release notes.
pub const SUMDB_PUBLIC_KEY_STR: &str =
    "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8";

// ---------------------------------------------------------------------------
// SumDbEntry — parsed lookup response
// ---------------------------------------------------------------------------

/// A parsed entry from the Go checksum database lookup endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct SumDbEntry {
    /// `h1:` hash of the module zip (not the go.mod file).
    pub h1_module: String,
    /// `h1:` hash of the go.mod file.
    pub h1_gomod: String,
    /// The complete signed-note block (tree header + signature line).
    pub signed_tree_head: String,
}

// ---------------------------------------------------------------------------
// SumDbVerifier trait — injectable for testing
// ---------------------------------------------------------------------------

/// Outcome of verifying a sumdb signed-note signature.
#[derive(Debug, Clone, PartialEq)]
pub enum SumDbVerifyOutcome {
    /// The signature is valid and was made by the pinned key.
    Valid,
    /// The signature is invalid, malformed, or from the wrong key.
    Invalid { reason: String },
}

/// Trait for verifying a sumdb signed-note against a pinned key.
///
/// The real implementation (`RealSumDbVerifier`) uses `ed25519-dalek`.
/// Tests inject a `MockSumDbVerifier` that returns a predetermined outcome.
pub trait SumDbVerifier: Send + Sync {
    /// Verify the Ed25519 signature on `signed_note`.
    ///
    /// `signed_note` is the complete block returned after the blank-line
    /// separator in the sumdb lookup response.
    fn verify(&self, signed_note: &str) -> SumDbVerifyOutcome;
}

// ---------------------------------------------------------------------------
// Real verifier — Ed25519 with pinned key
// ---------------------------------------------------------------------------

/// Real sumdb verifier using `ed25519-dalek` and the pinned sum.golang.org key.
pub struct RealSumDbVerifier;

impl SumDbVerifier for RealSumDbVerifier {
    fn verify(&self, signed_note: &str) -> SumDbVerifyOutcome {
        verify_signed_note(signed_note, SUMDB_PUBLIC_KEY_STR)
    }
}

/// Verify a signed note against a key string (name+id+base64).
///
/// Extracted as a free function so that tests can supply different key strings
/// while exercising the same verification path.
///
/// Internally delegates to the shared [`crate::signed_note::verify_ed25519`]
/// primitive (task 036 extracted the note parsing + Ed25519 verifier out of
/// this module so Rekor's signed-checkpoint code can share the parser).
pub fn verify_signed_note(signed_note_str: &str, key_str: &str) -> SumDbVerifyOutcome {
    match signed_note::verify_ed25519(signed_note_str, key_str) {
        NoteVerifyOutcome::Valid => SumDbVerifyOutcome::Valid,
        NoteVerifyOutcome::Invalid { reason } => SumDbVerifyOutcome::Invalid { reason },
    }
}

// ---------------------------------------------------------------------------
// Lookup response parser
// ---------------------------------------------------------------------------

/// Parse a sumdb lookup response body into a `SumDbEntry`.
///
/// The expected format is:
/// ```text
/// <module> <version> h1:<base64>
/// <module> <version>/go.mod h1:<base64>
///
/// go.sum database tree
/// <size>
/// <tree-hash>
///
/// — <key-id> <signature-base64>
/// ```
///
/// Returns `Ok(None)` on 404 (not-in-sumdb).
/// Returns `Err(...)` if the response is malformed or missing the signed tree head.
pub fn parse_lookup_response(
    status: u16,
    body: &str,
    module: &str,
    version: &str,
) -> Result<Option<SumDbEntry>, String> {
    if status == 404 {
        return Ok(None);
    }

    if status != 200 {
        return Err(format!("sumdb returned HTTP {status}"));
    }

    // The response has two sections separated by "\n\n":
    // 1. The hash lines
    // 2. The signed note (tree head + signature)
    let split_pos = match body.find("\n\n") {
        Some(pos) => pos,
        None => {
            return Err(
                "malformed sumdb response: missing blank line separating hashes from signed note"
                    .to_string(),
            );
        }
    };

    let hash_section = &body[..split_pos];
    let signed_tree_head = body[split_pos + 2..].to_string();

    if signed_tree_head.trim().is_empty() {
        return Err("malformed sumdb response: signed tree head is empty".to_string());
    }

    // Check that the signed note starts with "go.sum database tree"
    if !signed_tree_head
        .trim_start()
        .starts_with("go.sum database tree")
    {
        return Err(format!(
            "malformed sumdb response: signed note does not start with 'go.sum database tree', got: {:?}",
            &signed_tree_head[..signed_tree_head.len().min(60)]
        ));
    }

    // Parse the hash section: find the module hash and go.mod hash.
    let mut h1_module: Option<String> = None;
    let mut h1_gomod: Option<String> = None;

    for line in hash_section.lines() {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() != 3 {
            continue;
        }
        let line_module = parts[0];
        let line_version = parts[1];
        let line_hash = parts[2];

        if !line_hash.starts_with("h1:") {
            continue;
        }

        // Check for module/version mismatch (defensive against confused-deputy bugs)
        if line_module != module {
            return Err(format!(
                "sumdb response module mismatch: requested '{module}', got '{line_module}'"
            ));
        }

        if line_version == version {
            h1_module = Some(line_hash.to_string());
        } else if line_version == format!("{version}/go.mod") {
            h1_gomod = Some(line_hash.to_string());
        } else {
            // Version in response doesn't match what we requested
            return Err(format!(
                "sumdb response version mismatch: requested '{version}', got '{line_version}'"
            ));
        }
    }

    let h1_module = match h1_module {
        Some(h) => h,
        None => {
            return Err(format!(
                "sumdb response is missing the module hash line for '{module} {version}'"
            ));
        }
    };

    let h1_gomod = match h1_gomod {
        Some(h) => h,
        None => {
            return Err(format!(
                "sumdb response is missing the go.mod hash line for '{module} {version}/go.mod'"
            ));
        }
    };

    Ok(Some(SumDbEntry {
        h1_module,
        h1_gomod,
        signed_tree_head,
    }))
}

// ---------------------------------------------------------------------------
// GoSumDbPolicy
// ---------------------------------------------------------------------------

/// Policy name constant used in output and test assertions.
pub const POLICY_NAME: &str = "go_sumdb";

/// Go checksum database signature verification policy.
///
/// For every Go module scan, verifies the Ed25519 signature on the tree head
/// returned by `sum.golang.org/lookup/<module>@<version>`.  The sumdb public
/// key is pinned at compile time.
///
/// ## Fields
///
/// - `require_go_sumdb`: when `true`, a 404 from the sumdb (module not listed)
///   escalates from `Warn` to `Block`.  Invalid signatures are always `Block`.
/// - `verifier`: injectable for testing.  In production, use `RealSumDbVerifier`.
pub struct GoSumDbPolicy {
    /// When `true`, "not in sumdb" (404) escalates to `Block`.
    pub require_go_sumdb: bool,
    /// The sumdb verifier to use.  Injected for testability.
    pub verifier: Arc<dyn SumDbVerifier>,
}

impl GoSumDbPolicy {
    /// Create a new policy with the given configuration and verifier.
    pub fn new(require_go_sumdb: bool, verifier: Arc<dyn SumDbVerifier>) -> Self {
        Self {
            require_go_sumdb,
            verifier,
        }
    }
}

impl Policy for GoSumDbPolicy {
    fn name(&self) -> &str {
        POLICY_NAME
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        // Non-Go packages: skip (ScanContext.go_sumdb_entry will be None)
        let sumdb_result = match &ctx.go_sumdb_result {
            None => return PolicyResult::Pass,
            Some(r) => r,
        };

        let pkg = &ctx.metadata.name;

        match sumdb_result {
            GoSumDbResult::NotInSumDb => {
                let msg = format!(
                    "go_sumdb: module '{pkg}' is not in the Go checksum database — \
                     likely private or excluded from sum.golang.org"
                );
                if self.require_go_sumdb {
                    PolicyResult::Block(msg)
                } else {
                    PolicyResult::Warn(msg)
                }
            }
            GoSumDbResult::NetworkError(e) => {
                // Network errors surface as Block (fail-closed), same as task 030.
                PolicyResult::Block(format!(
                    "go_sumdb: network error fetching sumdb entry for '{pkg}': {e}"
                ))
            }
            GoSumDbResult::ParseError(e) => {
                // Malformed responses are treated as invalid signature (Block unconditional).
                PolicyResult::Block(format!(
                    "go_sumdb: malformed sumdb response for '{pkg}': {e}"
                ))
            }
            GoSumDbResult::Entry(entry) => {
                // Verify the signed tree head.
                match self.verifier.verify(&entry.signed_tree_head) {
                    SumDbVerifyOutcome::Valid => PolicyResult::Pass,
                    SumDbVerifyOutcome::Invalid { reason } => PolicyResult::Block(format!(
                        "go_sumdb: sumdb signature verification failed for '{pkg}': {reason}"
                    )),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GoSumDbResult — enrichment field in ScanContext
// ---------------------------------------------------------------------------

/// The result of fetching and parsing a sumdb lookup response.
///
/// Stored in `ScanContext.go_sumdb_result`.
#[derive(Debug, Clone)]
pub enum GoSumDbResult {
    /// 404 — module not listed in the checksum database.
    NotInSumDb,
    /// Network error during fetch.
    NetworkError(String),
    /// HTTP 200 but the response body was malformed (missing tree head, etc.).
    ParseError(String),
    /// Successfully parsed sumdb entry — signature must still be verified.
    Entry(SumDbEntry),
}

// ---------------------------------------------------------------------------
// Mock verifier for tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod mock {
    use super::{SumDbVerifier, SumDbVerifyOutcome};

    /// A mock verifier that always returns the same outcome.
    pub struct MockSumDbVerifier {
        outcome: SumDbVerifyOutcome,
    }

    impl MockSumDbVerifier {
        /// Create a verifier that always succeeds.
        pub fn always_valid() -> Self {
            Self {
                outcome: SumDbVerifyOutcome::Valid,
            }
        }

        /// Create a verifier that always fails with the given reason.
        pub fn always_invalid(reason: &str) -> Self {
            Self {
                outcome: SumDbVerifyOutcome::Invalid {
                    reason: reason.to_string(),
                },
            }
        }
    }

    impl SumDbVerifier for MockSumDbVerifier {
        fn verify(&self, _signed_note: &str) -> SumDbVerifyOutcome {
            self.outcome.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::mock::MockSumDbVerifier;
    use super::*;
    use crate::types::{PackageMetadata, ScanContext};

    // ── Fixtures ─────────────────────────────────────────────────────────────

    fn make_ctx_with_result(pkg_name: &str, result: Option<GoSumDbResult>) -> ScanContext {
        let meta = PackageMetadata {
            name: pkg_name.to_string(),
            version: "v1.2.3".to_string(),
            description: None,
            published_at: None,
            maintainers: vec![],
            downloads: None,
            repository_url: None,
            content_hash: None,
        };
        let mut ctx = ScanContext::from_metadata(meta);
        ctx.go_sumdb_result = result;
        ctx
    }

    fn make_entry(h1_module: &str, h1_gomod: &str) -> SumDbEntry {
        SumDbEntry {
            h1_module: h1_module.to_string(),
            h1_gomod: h1_gomod.to_string(),
            signed_tree_head: "go.sum database tree\n12345\nabc123\n\n— sum.golang.org AAAA\n"
                .to_string(),
        }
    }

    // ── T-034-01: Parse well-formed lookup response ───────────────────────────

    #[test]
    fn t034_01_parse_well_formed_lookup_response() {
        // T-034-01
        let body = concat!(
            "github.com/foo/bar v1.2.3 h1:aaaa\n",
            "github.com/foo/bar v1.2.3/go.mod h1:bbbb\n",
            "\n",
            "go.sum database tree\n",
            "12345\n",
            "c29zZWtyb3BlcnR5\n",
            "\n",
            "\u{2014} sum.golang.org AAAA\n",
        );
        let result = parse_lookup_response(200, body, "github.com/foo/bar", "v1.2.3");
        assert!(result.is_ok(), "T-034-01: expected Ok, got {:?}", result);
        let entry = result.unwrap();
        assert!(entry.is_some(), "T-034-01: expected Some(entry), got None");
        let entry = entry.unwrap();
        assert_eq!(
            entry.h1_module, "h1:aaaa",
            "T-034-01: h1_module should be 'h1:aaaa'"
        );
        assert_eq!(
            entry.h1_gomod, "h1:bbbb",
            "T-034-01: h1_gomod should be 'h1:bbbb'"
        );
        assert!(
            entry.signed_tree_head.contains("go.sum database tree"),
            "T-034-01: signed_tree_head should contain the tree header"
        );
    }

    // ── T-034-02: 404 returns Ok(None) ────────────────────────────────────────

    #[test]
    fn t034_02_404_returns_ok_none() {
        // T-034-02
        let result = parse_lookup_response(404, "", "github.com/foo/bar", "v1.2.3");
        assert!(result.is_ok(), "T-034-02: expected Ok, got {:?}", result);
        assert!(
            result.unwrap().is_none(),
            "T-034-02: 404 should return Ok(None)"
        );
    }

    // ── T-034-03: 500 returns Err ──────────────────────────────────────────────

    #[test]
    fn t034_03_500_returns_err() {
        // T-034-03
        let result =
            parse_lookup_response(500, "Internal Server Error", "github.com/foo/bar", "v1.2.3");
        assert!(
            result.is_err(),
            "T-034-03: expected Err for 500, got {:?}",
            result
        );
    }

    // ── T-034-04: Malformed body (missing signed-note) returns Err ────────────

    #[test]
    fn t034_04_malformed_body_missing_signed_note_returns_err() {
        // T-034-04: body has only the two h1 lines, no signed note
        let body = concat!(
            "github.com/foo/bar v1.2.3 h1:aaaa\n",
            "github.com/foo/bar v1.2.3/go.mod h1:bbbb\n",
        );
        let result = parse_lookup_response(200, body, "github.com/foo/bar", "v1.2.3");
        assert!(
            result.is_err(),
            "T-034-04: malformed body missing signed note should return Err, got {:?}",
            result
        );
    }

    // ── T-034-05: Module/version mismatch returns Err ────────────────────────

    #[test]
    fn t034_05_module_version_mismatch_returns_err() {
        // T-034-05: response claims v9.9.9 but we requested v1.2.3
        let body = concat!(
            "github.com/foo/bar v9.9.9 h1:xxxx\n",
            "github.com/foo/bar v9.9.9/go.mod h1:yyyy\n",
            "\n",
            "go.sum database tree\n",
            "99999\n",
            "aaaa\n",
            "\n",
            "\u{2014} sum.golang.org BBBB\n",
        );
        let result = parse_lookup_response(200, body, "github.com/foo/bar", "v1.2.3");
        assert!(
            result.is_err(),
            "T-034-05: version mismatch should return Err, got {:?}",
            result
        );
    }

    // ── T-034-06/07/08: Ed25519 verification ──────────────────────────────────

    // To test Ed25519 verification with a real key, we generate a test keypair.
    // T-034-06, T-034-07, T-034-08 require a real signed note.
    // We use ed25519-dalek to sign the note in the test.

    // TC-110-05: this synthetic-note helper builds its key-id with the CORRECTED
    // Go note.keyHash derivation (no "hash:1:" prefix — see task 110). Before the
    // fix it shared the bug with the verifier, so the negative tests (t034_07/08)
    // passed for the wrong reason; they now fail because of a genuinely-absent
    // matching signature, not a self-consistent prefix.
    fn generate_test_key_and_signed_note(note_text: &str) -> (String, String) {
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        use rand_core::OsRng;
        use sha2::{Digest, Sha256};

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Build key bytes: 0x01 || public_key_bytes
        let mut key_bytes = vec![0x01u8];
        key_bytes.extend_from_slice(verifying_key.as_bytes());

        // Compute key ID per Go note.keyHash: SHA256("test-key" || "\n" || key_bytes)[..4]
        // (no "hash:1:" prefix — see task 110).
        let key_name = "test-key";
        let mut hasher = Sha256::new();
        hasher.update(key_name.as_bytes());
        hasher.update(b"\n");
        hasher.update(&key_bytes);
        let hash = hasher.finalize();
        let key_id = &hash[..4];
        let key_id_hex = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            key_id[0], key_id[1], key_id[2], key_id[3]
        );

        // key_str: "<name>+<id-hex>+<key-base64>"
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&key_bytes);
        let key_str = format!("{key_name}+{key_id_hex}+{key_b64}");

        // Sign the note text
        let sig = signing_key.sign(note_text.as_bytes());
        let sig_bytes = sig.to_bytes();

        // Build signature payload: [key_id (4 bytes)] || [sig (64 bytes)]
        let mut sig_payload = key_id.to_vec();
        sig_payload.extend_from_slice(&sig_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_payload);

        // Build signed note: note_text + "\n" + "\u{2014} <name> <sig_b64>" + "\n"
        let signed_note = format!("{note_text}\n\u{2014} {key_name} {sig_b64}\n");

        (key_str, signed_note)
    }

    #[test]
    fn t034_06_valid_signature_against_pinned_key_accepts() {
        // T-034-06
        let note_text = "go.sum database tree\n12345\nc29zZWtyb3BlcnR5\n";
        let (key_str, signed_note) = generate_test_key_and_signed_note(note_text);

        let outcome = verify_signed_note(&signed_note, &key_str);
        assert_eq!(
            outcome,
            SumDbVerifyOutcome::Valid,
            "T-034-06: valid signature should be accepted, got {:?}",
            outcome
        );
    }

    // ── TC-110-03: legitimate module passes through the policy (real fixture) ──

    #[test]
    fn tc_110_03_real_module_passes_policy_with_real_verifier() {
        // Genuine recorded sum.golang.org lookup response for
        // github.com/google/uuid@v1.6.0 (real Ed25519 signature). Parse it into a
        // SumDbEntry and run it through GoSumDbPolicy with the REAL verifier
        // (pinned sum.golang.org key) — must Pass under the corrected derivation.
        let body = include_str!("../../tests/fixtures/go_sumdb_real/uuid_v1.6.0_lookup.txt");
        let entry = parse_lookup_response(200, body, "github.com/google/uuid", "v1.6.0")
            .expect("TC-110-03: real fixture must parse")
            .expect("TC-110-03: real fixture is an entry, not a 404");

        let policy = GoSumDbPolicy::new(false, Arc::new(RealSumDbVerifier));
        let ctx = make_ctx_with_result("github.com/google/uuid", Some(GoSumDbResult::Entry(entry)));
        let result = policy.evaluate(&ctx);
        assert_eq!(
            result,
            PolicyResult::Pass,
            "TC-110-03: a legitimate module's real signed tree head must Pass; got {result:?}"
        );
    }

    #[test]
    fn t034_07_tampered_signature_returns_err() {
        // T-034-07: flip one byte of the signature
        let note_text = "go.sum database tree\n12345\nc29zZWtyb3BlcnR5\n";
        let (key_str, signed_note) = generate_test_key_and_signed_note(note_text);

        // Tamper: flip the last character of the base64 signature on the sig line
        let tampered = {
            let mut lines: Vec<String> = signed_note.lines().map(|l| l.to_string()).collect();
            for line in &mut lines {
                if line.starts_with('\u{2014}') {
                    // Flip the last character of the base64-encoded signature
                    let last = line.pop().unwrap_or('A');
                    let replacement = if last == 'A' { 'B' } else { 'A' };
                    line.push(replacement);
                }
            }
            lines.join("\n") + "\n"
        };

        let outcome = verify_signed_note(&tampered, &key_str);
        assert!(
            matches!(outcome, SumDbVerifyOutcome::Invalid { .. }),
            "T-034-07: tampered signature should fail, got {:?}",
            outcome
        );
    }

    #[test]
    fn t034_08_signature_from_different_key_returns_err() {
        // T-034-08: sign with key A, verify with key B
        let note_text = "go.sum database tree\n12345\nc29zZWtyb3BlcnR5\n";
        let (key_str_a, _signed_note_a) = generate_test_key_and_signed_note(note_text);
        let (_key_str_b, signed_note_b) = generate_test_key_and_signed_note(note_text);

        // Try to verify note_b using key_a — the key name won't match
        let outcome = verify_signed_note(&signed_note_b, &key_str_a);
        assert!(
            matches!(outcome, SumDbVerifyOutcome::Invalid { .. }),
            "T-034-08: signature from different key should fail, got {:?}",
            outcome
        );
    }

    // ── T-034-09: Public key is hardcoded ─────────────────────────────────────

    /// The expected sumdb key name, for use in T-034-09 assertion.
    const EXPECTED_KEY_NAME: &str = "sum.golang.org";

    #[test]
    fn t034_09_public_key_is_hardcoded() {
        use base64::Engine as _;
        use ed25519_dalek::VerifyingKey;
        // T-034-09: verify SUMDB_PUBLIC_KEY_STR is a const (compile-time check)
        // and that it contains the expected key name.
        assert!(
            SUMDB_PUBLIC_KEY_STR.starts_with(EXPECTED_KEY_NAME),
            "T-034-09: pinned key should start with '{}', got '{}'",
            EXPECTED_KEY_NAME,
            SUMDB_PUBLIC_KEY_STR
        );
        // Verify the key can be decoded without error (structural check)
        let parts: Vec<&str> = SUMDB_PUBLIC_KEY_STR.splitn(3, '+').collect();
        assert_eq!(
            parts.len(),
            3,
            "T-034-09: key string should have 3 '+'-separated fields"
        );
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(parts[2])
            .unwrap();
        assert_eq!(
            key_bytes.len(),
            33,
            "T-034-09: decoded key should be 33 bytes"
        );
        assert_eq!(
            key_bytes[0], 0x01,
            "T-034-09: first byte should be 0x01 (Ed25519 marker)"
        );
        // Must be a valid Ed25519 key
        let vk = VerifyingKey::from_bytes(key_bytes[1..33].try_into().unwrap());
        assert!(
            vk.is_ok(),
            "T-034-09: pinned key must be a valid Ed25519 key"
        );
    }

    // ── T-034-10: Valid signature + h1 present ⇒ Pass ─────────────────────────

    #[test]
    fn t034_10_valid_signature_h1_present_pass() {
        // T-034-10
        let verifier = Arc::new(MockSumDbVerifier::always_valid());
        let policy = GoSumDbPolicy::new(false, verifier);
        let entry = make_entry("h1:aaaa", "h1:bbbb");
        let ctx = make_ctx_with_result("github.com/foo/bar", Some(GoSumDbResult::Entry(entry)));
        let result = policy.evaluate(&ctx);
        assert_eq!(
            result,
            PolicyResult::Pass,
            "T-034-10: valid entry should produce Pass, got {:?}",
            result
        );
    }

    // ── T-034-11: 404 + require=false ⇒ Warn ─────────────────────────────────

    #[test]
    fn t034_11_not_in_sumdb_require_false_warns() {
        // T-034-11
        let verifier = Arc::new(MockSumDbVerifier::always_valid());
        let policy = GoSumDbPolicy::new(false, verifier);
        let ctx = make_ctx_with_result(
            "github.com/foo/private-mod",
            Some(GoSumDbResult::NotInSumDb),
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Warn(_)),
            "T-034-11: NotInSumDb + require=false should Warn, got {:?}",
            result
        );
        if let PolicyResult::Warn(msg) = &result {
            assert!(
                msg.contains("not in the Go checksum database"),
                "T-034-11: warn message should mention 'not in the Go checksum database', got: {msg}"
            );
        }
    }

    // ── T-034-12: 404 + require=true ⇒ Block ──────────────────────────────────

    #[test]
    fn t034_12_not_in_sumdb_require_true_blocks() {
        // T-034-12
        let verifier = Arc::new(MockSumDbVerifier::always_valid());
        let policy = GoSumDbPolicy::new(true, verifier);
        let ctx = make_ctx_with_result(
            "github.com/foo/private-mod",
            Some(GoSumDbResult::NotInSumDb),
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-034-12: NotInSumDb + require=true should Block, got {:?}",
            result
        );
    }

    // ── T-034-13: Invalid signature ⇒ Block (unconditional) ───────────────────

    #[test]
    fn t034_13_invalid_signature_blocks_unconditionally() {
        // T-034-13: require=false should NOT silence an invalid signature
        let verifier = Arc::new(MockSumDbVerifier::always_invalid("tampered"));
        let policy = GoSumDbPolicy::new(false, verifier); // require=false does NOT help
        let entry = make_entry("h1:aaaa", "h1:bbbb");
        let ctx = make_ctx_with_result("github.com/foo/bar", Some(GoSumDbResult::Entry(entry)));
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-034-13: invalid signature must Block unconditionally (require=false), got {:?}",
            result
        );
    }

    // ── T-034-14: Malformed body ⇒ Block (unconditional) ──────────────────────

    #[test]
    fn t034_14_malformed_body_blocks_unconditionally() {
        // T-034-14: require=false does NOT silence a malformed response
        let verifier = Arc::new(MockSumDbVerifier::always_valid());
        let policy = GoSumDbPolicy::new(false, verifier);
        let ctx = make_ctx_with_result(
            "github.com/foo/bar",
            Some(GoSumDbResult::ParseError("missing tree head".to_string())),
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-034-14: malformed response must Block unconditionally, got {:?}",
            result
        );
    }

    // ── T-034-15: GOSUMDB=off env var is ignored ─────────────────────────────

    #[test]
    fn t034_15_gosumdb_env_var_is_ignored() {
        // T-034-15: set GOSUMDB=off and confirm the policy still runs
        // (Static check: GOSUMDB is not read in this module.)
        // Dynamic check: set it, evaluate, confirm result is from policy logic not env.
        unsafe {
            std::env::set_var("GOSUMDB", "off");
        }
        let verifier = Arc::new(MockSumDbVerifier::always_valid());
        let policy = GoSumDbPolicy::new(false, verifier);
        let entry = make_entry("h1:aaaa", "h1:bbbb");
        let ctx = make_ctx_with_result("github.com/foo/bar", Some(GoSumDbResult::Entry(entry)));
        let result = policy.evaluate(&ctx);
        // If GOSUMDB=off were honored, we'd get Pass without calling the verifier.
        // Since MockSumDbVerifier::always_valid() returns Valid, Pass is the expected result.
        // But the key check is that the verifier WAS called, which we can verify by
        // using always_invalid and confirming Block is returned.
        assert_eq!(
            result,
            PolicyResult::Pass,
            "T-034-15: policy should ignore GOSUMDB env var, got {:?}",
            result
        );

        // Also confirm with always_invalid: policy blocks even with GOSUMDB=off
        let verifier2 = Arc::new(MockSumDbVerifier::always_invalid("test"));
        let policy2 = GoSumDbPolicy::new(false, verifier2);
        let entry2 = make_entry("h1:aaaa", "h1:bbbb");
        let ctx2 = make_ctx_with_result("github.com/foo/bar", Some(GoSumDbResult::Entry(entry2)));
        let result2 = policy2.evaluate(&ctx2);
        assert!(
            matches!(result2, PolicyResult::Block(_)),
            "T-034-15: GOSUMDB=off must not silence Block from invalid signature, got {:?}",
            result2
        );

        unsafe {
            std::env::remove_var("GOSUMDB");
        }
    }

    // ── T-034-16: Network error ⇒ scan error ──────────────────────────────────

    #[test]
    fn t034_16_network_error_surfaces_as_block() {
        // T-034-16: network errors are fail-closed (Block)
        let verifier = Arc::new(MockSumDbVerifier::always_valid());
        let policy = GoSumDbPolicy::new(false, verifier);
        let ctx = make_ctx_with_result(
            "github.com/foo/bar",
            Some(GoSumDbResult::NetworkError(
                "connection refused".to_string(),
            )),
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-034-16: network error should Block (fail-closed), got {:?}",
            result
        );
    }

    // TC-110-06: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
    // `cargo fmt --check` all pass. This is a CI/pre-commit gate requirement
    // verified by the build pipeline; no runtime assertion is needed here.
}

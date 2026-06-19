// SPDX-License-Identifier: Apache-2.0
//! PyPI provenance attestation policy (task 033 — PEP 740).
//!
//! Evaluates PyPI packages against their sigstore provenance attestations
//! published via PEP 740.  When an attestation is present, verifies the DSSE
//! bundle signature and compares the SLSA subject digest against the registry-
//! published `digests.sha256` captured in task 029.
//!
//! ## Key difference from npm provenance (task 032)
//!
//! PyPI uses `sha256` for the subject digest, whereas npm uses `sha512`.
//! The `verify_dsse_bundle` helper is algorithm-agnostic; we call it with
//! `"sha256"` here.
//!
//! ## Policy outcomes
//!
//! | Condition | `require_pypi_provenance = false` | `require_pypi_provenance = true` |
//! |-----------|-----------------------------------|----------------------------------|
//! | No attestation | `Warn` | `Block` |
//! | Attestation fetch error | `Block` (fail-closed) | `Block` |
//! | Valid attestation | `Pass` | `Pass` |
//! | Invalid attestation | `Block` | `Block` |
//!
//! "Invalid" attestations are always `Block` regardless of config — this covers
//! subject digest mismatch and broken signature/cert chain.

use std::sync::Arc;

use crate::policy::{Policy, PolicyResult};
use crate::registry::npm_attestation::AttestationBundle;
use crate::sigstore_verify::{SigstoreVerifier, VerificationOutcome};
use crate::types::ScanContext;

/// Policy name constant used in output and test assertions.
pub const POLICY_NAME: &str = "pypi_provenance";

/// PyPI provenance attestation policy.
///
/// Checks that PyPI packages have PEP 740 sigstore provenance attestations and
/// that those attestations are cryptographically valid and match the registry-
/// served content hash (sha256).
pub struct PyPiProvenancePolicy {
    /// When `true`, a missing attestation becomes `Block` instead of `Warn`.
    pub require_pypi_provenance: bool,
    /// The sigstore verifier to use. Injected for testability.
    pub verifier: Arc<dyn SigstoreVerifier>,
}

impl PyPiProvenancePolicy {
    /// Create a new policy with the given configuration and verifier.
    pub fn new(require_pypi_provenance: bool, verifier: Arc<dyn SigstoreVerifier>) -> Self {
        Self {
            require_pypi_provenance,
            verifier,
        }
    }
}

impl Policy for PyPiProvenancePolicy {
    fn name(&self) -> &str {
        POLICY_NAME
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        let pkg = &ctx.metadata.name;

        // Surface any network/parse error from the provenance fetch (fail-closed).
        if let Some(ref err) = ctx.pypi_provenance_fetch_error {
            return PolicyResult::Block(format!(
                "pypi_provenance: failed to fetch provenance attestation for '{pkg}': {err}"
            ));
        }

        let attestation = match &ctx.pypi_attestation {
            // Policy was not queried (non-PyPI package or policy disabled at call site).
            None => return PolicyResult::Pass,
            Some(a) => a,
        };

        // No attestation published.
        let bundle = match attestation {
            None => {
                let msg = format!(
                    "pypi_provenance: no provenance attestation published for '{pkg}' — \
                     the PyPI registry is the sole source of integrity for this package"
                );
                return if self.require_pypi_provenance {
                    PolicyResult::Block(msg)
                } else {
                    PolicyResult::Warn(msg)
                };
            }
            Some(b) => b,
        };

        // Extract the expected sha256 digest from the package metadata.
        // Format is `sha256:<hex>` for PyPI.
        let (expected_algo, expected_hex) = match &ctx.metadata.content_hash {
            Some(h) => match h.split_once(':') {
                Some((algo, hex)) => (algo.to_string(), hex.to_string()),
                None => {
                    return PolicyResult::Block(format!(
                        "pypi_provenance: content_hash for '{pkg}' has unexpected format \
                         (expected 'sha256:<hex>', got '{h}')"
                    ));
                }
            },
            None => {
                // No content hash available — cannot compare against SLSA predicate.
                let msg = format!(
                    "pypi_provenance: no content hash available for '{pkg}'; \
                     cannot verify attestation subject digest"
                );
                return if self.require_pypi_provenance {
                    PolicyResult::Block(msg)
                } else {
                    PolicyResult::Warn(msg)
                };
            }
        };

        // Verify the bundle using the shared sigstore helper.
        // PyPI uses sha256, not sha512 — this is the key difference from task 032.
        match self.verifier.verify(bundle, &expected_algo, &expected_hex) {
            VerificationOutcome::Valid {
                subject_identity: _,
            } => {
                // Return Pass.  The subject identity is extracted separately by
                // `extract_pypi_provenance_identity` in main.rs for persistence
                // to the cache.
                PolicyResult::Pass
            }
            VerificationOutcome::Invalid { reason } => PolicyResult::Block(format!(
                "pypi_provenance: attestation bundle failed for '{pkg}': {reason}"
            )),
        }
    }
}

/// Evaluate the attestation bundle and return the subject identity if valid.
///
/// This is a separate helper called by `main.rs` to extract the identity
/// for persisting to `scanned_packages.provenance_identity`, since the
/// `Policy::evaluate` interface cannot return metadata alongside `Pass`.
pub fn extract_pypi_provenance_identity(
    bundle: &AttestationBundle,
    expected_algo: &str,
    expected_hex: &str,
    verifier: &dyn SigstoreVerifier,
) -> Option<String> {
    if let VerificationOutcome::Valid { subject_identity } =
        verifier.verify(bundle, expected_algo, expected_hex)
    {
        Some(subject_identity)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::npm_attestation::{
        AttestationBundle, DsseEnvelope, DsseSignature, VerificationMaterial,
    };
    use crate::sigstore_verify::mock::MockVerifier;
    use crate::types::PackageMetadata;

    fn make_bundle() -> AttestationBundle {
        AttestationBundle {
            predicate_type: "https://docs.pypi.org/attestations/publish/v1".to_string(),
            dsse_envelope: DsseEnvelope {
                payload_b64: "e30K".to_string(), // base64("{}")
                payload_type: "application/vnd.in-toto+json".to_string(),
                signatures: vec![DsseSignature {
                    sig_b64: "MEYCIQCY+TSB151Y=".to_string(),
                    keyid: String::new(),
                }],
            },
            verification_material: VerificationMaterial::X509CertChain(vec!["MIIB...".to_string()]),
            tlog_entries: vec![],
        }
    }

    fn make_context(
        pkg_name: &str,
        content_hash: Option<String>,
        attestation: Option<Option<AttestationBundle>>,
        fetch_error: Option<String>,
    ) -> ScanContext {
        let meta = PackageMetadata {
            name: pkg_name.to_string(),
            version: "1.0.0".to_string(),
            description: None,
            published_at: None,
            maintainers: vec![],
            downloads: None,
            repository_url: None,
            content_hash,
        };
        let mut ctx = ScanContext::from_metadata(meta);
        ctx.pypi_attestation = attestation;
        ctx.pypi_provenance_fetch_error = fetch_error;
        ctx
    }

    // T-033-09: No attestation + require=false ⇒ Warn
    #[test]
    fn no_attestation_require_false_warns() {
        let verifier = Arc::new(MockVerifier::always_valid(
            "https://github.com/psf/requests/...",
        ));
        let policy = PyPiProvenancePolicy::new(false, verifier);
        let ctx = make_context(
            "requests",
            Some("sha256:abcdef".to_string()),
            Some(None), // Some(None) = "attestation queried, none published"
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Warn(_)),
            "T-033-09: expected Warn, got {:?}",
            result
        );
        if let PolicyResult::Warn(msg) = &result {
            assert!(
                msg.contains("requests"),
                "T-033-09: message should name the package, got: {msg}"
            );
        }
    }

    // T-033-10: No attestation + require=true ⇒ Block
    #[test]
    fn no_attestation_require_true_blocks() {
        let verifier = Arc::new(MockVerifier::always_valid(
            "https://github.com/psf/requests/...",
        ));
        let policy = PyPiProvenancePolicy::new(true, verifier);
        let ctx = make_context(
            "requests",
            Some("sha256:abcdef".to_string()),
            Some(None),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-033-10: expected Block, got {:?}",
            result
        );
        if let PolicyResult::Block(msg) = &result {
            assert!(
                msg.contains("requests"),
                "T-033-10: message should name the package, got: {msg}"
            );
        }
    }

    // T-033-11: Valid attestation matching digests.sha256 ⇒ Pass with identity
    #[test]
    fn valid_attestation_matching_sha256_passes() {
        let identity =
            "https://github.com/psf/requests/.github/workflows/release.yml@refs/tags/v2.31.0";
        let verifier = Arc::new(MockVerifier::always_valid(identity));
        let policy = PyPiProvenancePolicy::new(false, verifier);
        let ctx = make_context(
            "requests",
            Some("sha256:abcdef1234567890".to_string()),
            Some(Some(make_bundle())),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert_eq!(
            result,
            PolicyResult::Pass,
            "T-033-11: expected Pass for valid attestation"
        );
    }

    // T-033-12: Attestation subject digest mismatches digests.sha256 ⇒ Block
    #[test]
    fn subject_digest_mismatch_blocks() {
        let verifier = Arc::new(MockVerifier::always_invalid(
            "subject digest mismatch: attestation has sha256:bbbb, registry served sha256:aaaa",
        ));
        let policy = PyPiProvenancePolicy::new(false, verifier);
        let ctx = make_context(
            "requests",
            Some("sha256:aaaa".to_string()),
            Some(Some(make_bundle())),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-033-12: expected Block for digest mismatch"
        );
        if let PolicyResult::Block(msg) = &result {
            assert!(
                msg.contains("subject digest mismatch"),
                "T-033-12: block message must name 'subject digest mismatch', got: {msg}"
            );
        }
    }

    // T-033-13: Tampered bundle ⇒ Block
    #[test]
    fn tampered_bundle_blocks() {
        let verifier = Arc::new(MockVerifier::always_invalid(
            "signature verification failed",
        ));
        let policy = PyPiProvenancePolicy::new(false, verifier);
        let ctx = make_context(
            "requests",
            Some("sha256:abcdef".to_string()),
            Some(Some(make_bundle())),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-033-13: expected Block for tampered bundle"
        );
    }

    // T-033-14: Broken Fulcio chain ⇒ Block
    #[test]
    fn broken_cert_chain_blocks() {
        let verifier = Arc::new(MockVerifier::always_invalid(
            "certificate is missing the Fulcio OIDC issuer extension",
        ));
        let policy = PyPiProvenancePolicy::new(false, verifier);
        let ctx = make_context(
            "requests",
            Some("sha256:abcdef".to_string()),
            Some(Some(make_bundle())),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-033-14: expected Block for broken Fulcio chain"
        );
    }

    // T-033-15: require=true never downgrades Block
    #[test]
    fn require_true_never_downgrades_block() {
        // A digest mismatch is already Block — require=true must not change that.
        let verifier = Arc::new(MockVerifier::always_invalid(
            "subject digest mismatch: attestation has sha256:bbbb, registry served sha256:aaaa",
        ));
        let policy = PyPiProvenancePolicy::new(true, verifier); // require = true
        let ctx = make_context(
            "requests",
            Some("sha256:aaaa".to_string()),
            Some(Some(make_bundle())),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-033-15: Block must remain Block even with require_pypi_provenance=true"
        );
        if let PolicyResult::Block(msg) = &result {
            assert!(
                msg.contains("subject digest mismatch"),
                "T-033-15: block message must be about the mismatch, got: {msg}"
            );
        }
    }

    // T-033-16: pypi_provenance policy uses sha256 (not sha512)
    //
    // Static check: the policy calls verify with "sha256", not "sha512".
    // We verify this by checking that the content_hash `sha256:abcdef` is
    // correctly split and the "sha256" part is passed to the verifier.
    // The MockVerifier checks the algo parameter is correct in the identity it receives.
    #[test]
    fn policy_uses_sha256_not_sha512() {
        use std::sync::{Arc, Mutex};

        struct DigitCapturingVerifier {
            captured_algo: Mutex<Option<String>>,
        }

        impl SigstoreVerifier for DigitCapturingVerifier {
            fn verify(
                &self,
                _bundle: &AttestationBundle,
                expected_digest_algo: &str,
                _expected_digest_hex: &str,
            ) -> VerificationOutcome {
                *self.captured_algo.lock().unwrap() = Some(expected_digest_algo.to_string());
                VerificationOutcome::Valid {
                    subject_identity: String::new(),
                }
            }
        }

        let verifier = Arc::new(DigitCapturingVerifier {
            captured_algo: Mutex::new(None),
        });
        let verifier_clone = Arc::clone(&verifier);
        let policy = PyPiProvenancePolicy::new(false, verifier);
        let ctx = make_context(
            "requests",
            Some("sha256:abcdef1234567890".to_string()),
            Some(Some(make_bundle())),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert_eq!(result, PolicyResult::Pass, "T-033-16: expected Pass");
        let captured = verifier_clone.captured_algo.lock().unwrap().clone();
        assert_eq!(
            captured,
            Some("sha256".to_string()),
            "T-033-16: pypi_provenance must call verifier with 'sha256', not 'sha512'; got: {:?}",
            captured
        );
    }

    // Fetch error surfaces as Block (fail-closed)
    #[test]
    fn fetch_error_surfaces_as_block() {
        let verifier = Arc::new(MockVerifier::always_valid("https://github.com/..."));
        let policy = PyPiProvenancePolicy::new(false, verifier);
        let ctx = make_context(
            "requests",
            Some("sha256:abcdef".to_string()),
            Some(None), // attestation = None (not queried separately — error path uses fetch_error)
            Some("network error: connection refused".to_string()),
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "fetch error must produce Block (fail-closed)"
        );
    }

    // Non-PyPI package (pypi_attestation = None) returns Pass
    #[test]
    fn non_pypi_package_returns_pass() {
        let verifier = Arc::new(MockVerifier::always_valid("https://github.com/..."));
        let policy = PyPiProvenancePolicy::new(true, verifier);
        let ctx = make_context(
            "lodash",
            Some("sha512:aaaa".to_string()),
            None, // None = "policy not queried"
            None,
        );
        let result = policy.evaluate(&ctx);
        assert_eq!(
            result,
            PolicyResult::Pass,
            "non-PyPI package must return Pass (policy not queried)"
        );
    }
}

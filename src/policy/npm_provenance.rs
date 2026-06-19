// SPDX-License-Identifier: Apache-2.0
//! npm provenance attestation policy (task 032).
//!
//! Evaluates npm packages against their sigstore provenance attestations.
//! When attestations are present, verifies the DSSE bundle signature and
//! compares the SLSA subject digest against the registry-published
//! `dist.integrity` hash captured in task 029.
//!
//! ## Policy outcomes
//!
//! | Condition | `require_npm_provenance = false` | `require_npm_provenance = true` |
//! |-----------|----------------------------------|----------------------------------|
//! | No attestations | `Warn` | `Block` |
//! | Attestation fetch error | Surfaces as `Block` (fail-closed) | `Block` |
//! | Any valid attestation | `Pass` | `Pass` |
//! | All attestations invalid | `Block` | `Block` |
//!
//! "Invalid" attestations are always `Block` regardless of config — this covers
//! subject digest mismatch (the registry and the attestation disagree about which
//! bytes this version represents) and broken signature/cert chain.

use std::sync::Arc;

use crate::policy::{Policy, PolicyResult};
use crate::registry::npm_attestation::AttestationBundle;
use crate::sigstore_verify::{SigstoreVerifier, VerificationOutcome};
use crate::types::ScanContext;

/// Policy name constant used in output and test assertions.
pub const POLICY_NAME: &str = "npm_provenance";

/// npm provenance attestation policy.
///
/// Checks that npm packages have sigstore provenance attestations and that
/// those attestations are cryptographically valid and match the registry-served
/// content hash.
pub struct NpmProvenancePolicy {
    /// When `true`, a missing attestation becomes `Block` instead of `Warn`.
    pub require_npm_provenance: bool,
    /// The sigstore verifier to use.  Injected for testability.
    pub verifier: Arc<dyn SigstoreVerifier>,
}

impl NpmProvenancePolicy {
    /// Create a new policy with the given configuration and verifier.
    pub fn new(require_npm_provenance: bool, verifier: Arc<dyn SigstoreVerifier>) -> Self {
        Self {
            require_npm_provenance,
            verifier,
        }
    }
}

impl Policy for NpmProvenancePolicy {
    fn name(&self) -> &str {
        POLICY_NAME
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        let pkg = &ctx.metadata.name;

        // Surface any network/parse error from the attestation fetch (fail-closed).
        if let Some(ref err) = ctx.npm_attestation_fetch_error {
            return PolicyResult::Block(format!(
                "npm_provenance: failed to fetch attestations for '{pkg}': {err}"
            ));
        }

        let attestations = match &ctx.npm_attestations {
            // Policy was not queried (non-npm package or policy disabled at call site).
            None => return PolicyResult::Pass,
            Some(a) => a,
        };

        // No attestations published (404 from the endpoint).
        if attestations.is_empty() {
            let msg = format!(
                "npm_provenance: no provenance attestation published for '{pkg}' — \
                 the npm registry is the sole source of integrity for this package"
            );
            return if self.require_npm_provenance {
                PolicyResult::Block(msg)
            } else {
                PolicyResult::Warn(msg)
            };
        }

        // Extract the expected digest from the package metadata.
        // Format is `<algo>:<hex>` (e.g. `sha512:abcdef...`).
        let (expected_algo, expected_hex) = match &ctx.metadata.content_hash {
            Some(h) => match h.split_once(':') {
                Some((algo, hex)) => (algo.to_string(), hex.to_string()),
                None => {
                    return PolicyResult::Block(format!(
                        "npm_provenance: content_hash for '{pkg}' has unexpected format \
                         (expected '<algo>:<hex>', got '{h}')"
                    ));
                }
            },
            None => {
                // No content hash available — cannot compare against SLSA predicate.
                let msg = format!(
                    "npm_provenance: no content hash available for '{pkg}'; \
                     cannot verify attestation subject digest"
                );
                return if self.require_npm_provenance {
                    PolicyResult::Block(msg)
                } else {
                    PolicyResult::Warn(msg)
                };
            }
        };

        // Try each bundle in order; any one valid bundle is sufficient (T-032-11).
        let mut failure_reasons: Vec<String> = Vec::new();

        for bundle in attestations {
            match self.verifier.verify(bundle, &expected_algo, &expected_hex) {
                VerificationOutcome::Valid {
                    subject_identity: _,
                } => {
                    // Return Pass.  The subject identity is extracted separately by
                    // `extract_provenance_identity` in main.rs for persistence to the
                    // cache, because the Policy trait's `evaluate` has no "pass with data"
                    // variant.
                    return PolicyResult::Pass;
                }
                VerificationOutcome::Invalid { reason } => {
                    failure_reasons.push(reason);
                }
            }
        }

        // All bundles failed — Block with all reasons (T-032-12).
        let combined = failure_reasons.join("; ");
        PolicyResult::Block(format!(
            "npm_provenance: all attestation bundles failed for '{pkg}': {combined}"
        ))
    }
}

/// Evaluate all attestation bundles and return the subject identity from the
/// first valid one.
///
/// This is a separate helper called by `main.rs` to extract the identity
/// for persisting to `scanned_packages.provenance_identity`, since the
/// `Policy::evaluate` interface cannot return metadata alongside `Pass`.
pub fn extract_provenance_identity(
    bundles: &[AttestationBundle],
    expected_algo: &str,
    expected_hex: &str,
    verifier: &dyn SigstoreVerifier,
) -> Option<String> {
    for bundle in bundles {
        if let VerificationOutcome::Valid { subject_identity } =
            verifier.verify(bundle, expected_algo, expected_hex)
        {
            return Some(subject_identity);
        }
    }
    None
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

    fn make_bundle(predicate_type: &str) -> AttestationBundle {
        AttestationBundle {
            predicate_type: predicate_type.to_string(),
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

    fn make_context_with_attestations(
        pkg_name: &str,
        content_hash: Option<String>,
        attestations: Option<Vec<AttestationBundle>>,
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
        ctx.npm_attestations = attestations;
        ctx.npm_attestation_fetch_error = fetch_error;
        ctx
    }

    // T-032-05: No attestations + require=false ⇒ Warn
    #[test]
    fn no_attestations_require_false_warns() {
        let verifier = Arc::new(MockVerifier::always_valid("https://github.com/..."));
        let policy = NpmProvenancePolicy::new(false, verifier);
        let ctx = make_context_with_attestations(
            "obscure-pkg",
            Some("sha512:aaaa".to_string()),
            Some(vec![]),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Warn(_)),
            "T-032-05: expected Warn, got {:?}",
            result
        );
        if let PolicyResult::Warn(msg) = &result {
            assert!(
                msg.contains("obscure-pkg"),
                "T-032-05: message should name the package, got: {msg}"
            );
        }
    }

    // T-032-06: No attestations + require=true ⇒ Block
    #[test]
    fn no_attestations_require_true_blocks() {
        let verifier = Arc::new(MockVerifier::always_valid("https://github.com/..."));
        let policy = NpmProvenancePolicy::new(true, verifier);
        let ctx = make_context_with_attestations(
            "obscure-pkg",
            Some("sha512:aaaa".to_string()),
            Some(vec![]),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-032-06: expected Block, got {:?}",
            result
        );
        if let PolicyResult::Block(msg) = &result {
            assert!(
                msg.contains("obscure-pkg"),
                "T-032-06: message should name the package, got: {msg}"
            );
        }
    }

    // T-032-07: Valid attestation matching dist.integrity ⇒ Pass
    #[test]
    fn valid_attestation_matching_digest_passes() {
        let identity =
            "https://github.com/lodash/lodash/.github/workflows/release.yml@refs/tags/v4.17.21";
        let verifier = Arc::new(MockVerifier::always_valid(identity));
        let policy = NpmProvenancePolicy::new(false, verifier);
        let ctx = make_context_with_attestations(
            "lodash",
            Some("sha512:aaaabbbb".to_string()),
            Some(vec![make_bundle("https://slsa.dev/provenance/v1")]),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert_eq!(
            result,
            PolicyResult::Pass,
            "T-032-07: expected Pass for valid attestation"
        );
    }

    // T-032-08: Subject digest mismatch ⇒ Block with "subject digest mismatch"
    #[test]
    fn subject_digest_mismatch_blocks() {
        let verifier = Arc::new(MockVerifier::always_invalid(
            "subject digest mismatch: attestation has sha512:bbbb, registry served sha512:aaaa",
        ));
        let policy = NpmProvenancePolicy::new(false, verifier);
        let ctx = make_context_with_attestations(
            "evil-pkg",
            Some("sha512:aaaa".to_string()),
            Some(vec![make_bundle("https://slsa.dev/provenance/v1")]),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-032-08: expected Block for digest mismatch"
        );
        if let PolicyResult::Block(msg) = &result {
            assert!(
                msg.contains("subject digest mismatch"),
                "T-032-08: block message must specifically name 'subject digest mismatch', got: {msg}"
            );
        }
    }

    // T-032-09: Tampered sigstore bundle ⇒ Block
    #[test]
    fn tampered_bundle_blocks() {
        let verifier = Arc::new(MockVerifier::always_invalid(
            "signature verification failed",
        ));
        let policy = NpmProvenancePolicy::new(false, verifier);
        let ctx = make_context_with_attestations(
            "pkg",
            Some("sha512:aaaa".to_string()),
            Some(vec![make_bundle("https://slsa.dev/provenance/v1")]),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-032-09: expected Block for tampered bundle"
        );
    }

    // T-032-10: Broken Fulcio cert chain ⇒ Block
    #[test]
    fn broken_cert_chain_blocks() {
        let verifier = Arc::new(MockVerifier::always_invalid(
            "certificate is missing the Fulcio OIDC issuer extension",
        ));
        let policy = NpmProvenancePolicy::new(false, verifier);
        let ctx = make_context_with_attestations(
            "pkg",
            Some("sha512:aaaa".to_string()),
            Some(vec![make_bundle("https://slsa.dev/provenance/v1")]),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-032-10: expected Block for broken cert chain"
        );
    }

    // T-032-11: Multiple attestations — any one valid is sufficient
    #[test]
    fn multiple_attestations_any_valid_passes() {
        use crate::registry::npm_attestation::AttestationBundle;
        use std::sync::{Arc, Mutex};

        // A verifier that fails on the first call and succeeds on the second.
        struct FirstFailThenSucceed {
            call_count: Mutex<usize>,
            identity: String,
        }

        impl SigstoreVerifier for FirstFailThenSucceed {
            fn verify(
                &self,
                _bundle: &AttestationBundle,
                _algo: &str,
                _hex: &str,
            ) -> VerificationOutcome {
                let mut count = self.call_count.lock().unwrap();
                *count += 1;
                if *count == 1 {
                    VerificationOutcome::Invalid {
                        reason: "first bundle: subject digest mismatch".to_string(),
                    }
                } else {
                    VerificationOutcome::Valid {
                        subject_identity: self.identity.clone(),
                    }
                }
            }
        }

        let verifier = Arc::new(FirstFailThenSucceed {
            call_count: Mutex::new(0),
            identity: "https://github.com/actions/valid-workflow@refs/tags/v1".to_string(),
        });
        let policy = NpmProvenancePolicy::new(false, verifier);
        let ctx = make_context_with_attestations(
            "multi-pkg",
            Some("sha512:aaaa".to_string()),
            Some(vec![
                make_bundle("https://slsa.dev/provenance/v1"),
                make_bundle("https://slsa.dev/provenance/v1"),
            ]),
            None,
        );

        let result = policy.evaluate(&ctx);
        assert_eq!(
            result,
            PolicyResult::Pass,
            "T-032-11: expected Pass when second bundle is valid"
        );
    }

    // T-032-12: Multiple attestations — all invalid ⇒ Block naming both failures
    #[test]
    fn multiple_attestations_all_invalid_blocks() {
        use std::sync::{Arc, Mutex};

        struct TwoDifferentFailures {
            call_count: Mutex<usize>,
        }

        impl SigstoreVerifier for TwoDifferentFailures {
            fn verify(
                &self,
                _bundle: &AttestationBundle,
                _algo: &str,
                _hex: &str,
            ) -> VerificationOutcome {
                let mut count = self.call_count.lock().unwrap();
                *count += 1;
                if *count == 1 {
                    VerificationOutcome::Invalid {
                        reason: "signature verification failed".to_string(),
                    }
                } else {
                    VerificationOutcome::Invalid {
                        reason: "subject digest mismatch: sha512:bad != sha512:good".to_string(),
                    }
                }
            }
        }

        let verifier = Arc::new(TwoDifferentFailures {
            call_count: Mutex::new(0),
        });
        let policy = NpmProvenancePolicy::new(false, verifier);
        let ctx = make_context_with_attestations(
            "bad-pkg",
            Some("sha512:good".to_string()),
            Some(vec![
                make_bundle("https://slsa.dev/provenance/v1"),
                make_bundle("https://slsa.dev/provenance/v1"),
            ]),
            None,
        );

        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-032-12: expected Block when all bundles fail"
        );
        if let PolicyResult::Block(msg) = &result {
            assert!(
                msg.contains("signature verification failed"),
                "T-032-12: block message must include first failure, got: {msg}"
            );
            assert!(
                msg.contains("subject digest mismatch"),
                "T-032-12: block message must include second failure, got: {msg}"
            );
        }
    }

    // T-032-13: require=true escalates Warn paths but never downgrades Block
    #[test]
    fn require_true_never_downgrades_block() {
        // A digest mismatch is already Block — require=true must not change that.
        let verifier = Arc::new(MockVerifier::always_invalid(
            "subject digest mismatch: attestation has sha512:bbbb, registry served sha512:aaaa",
        ));
        let policy = NpmProvenancePolicy::new(true, verifier); // require = true
        let ctx = make_context_with_attestations(
            "pkg",
            Some("sha512:aaaa".to_string()),
            Some(vec![make_bundle("https://slsa.dev/provenance/v1")]),
            None,
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "T-032-13: Block must remain Block even with require_npm_provenance=true"
        );
        if let PolicyResult::Block(msg) = &result {
            assert!(
                msg.contains("subject digest mismatch"),
                "T-032-13: block message must be about the mismatch, got: {msg}"
            );
        }
    }
}

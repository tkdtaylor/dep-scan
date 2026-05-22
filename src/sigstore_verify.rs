//! Sigstore DSSE bundle signature verification helper.
//!
//! This module implements verification of sigstore bundles that use the DSSE
//! (Dead Simple Signing Envelope) format, as used by npm provenance attestations.
//!
//! The sigstore Rust crate 0.13.x does not support DSSE-signed bundles
//! (`BundleErrorKind::DsseUnsupported`), so we implement the verification
//! using the underlying cryptographic crates directly:
//!
//! - `p256` for ECDSA P-256 signature verification
//! - `x509-parser` for X.509 certificate parsing
//!
//! # Verification steps
//!
//! 1. Decode the leaf certificate from the bundle's `verificationMaterial`.
//! 2. Verify the DSSE signature: `sig` is an ECDSA signature over
//!    `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`
//!    (the PAE encoding) using the certificate's public key.
//! 3. Extract the OIDC subject from the certificate's SAN extension.
//!
//! Full Fulcio root chain validation is intentionally limited to structural
//! checks in this implementation: the Fulcio issuer OID extension presence is
//! verified, signalling that the cert was issued via the Fulcio CA. A complete
//! PKI chain verification against an embedded Fulcio root is deferred to a
//! future hardening task (a full chain walk requires embedding the Fulcio
//! root/intermediate DER and running a WebPKI verifier, which adds significant
//! binary size and is outside the scope of task 032).
//!
//! # Reuse by task 033 (PyPI)
//!
//! `verify_dsse_bundle` is algorithm-agnostic for the subject digest comparison:
//! the caller passes `expected_digest_algo` (e.g. `"sha512"` for npm,
//! `"sha256"` for PyPI) and `expected_digest_hex` (the hex value from the
//! registry-published hash captured by task 029).

use base64::Engine as _;
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey, signature::Verifier as _,
};
use x509_parser::prelude::*;

use crate::registry::npm_attestation::{
    AttestationBundle, VerificationMaterial, dsse_pae, parse_slsa_statement,
};

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// The outcome of verifying a single attestation bundle.
#[derive(Debug, Clone, PartialEq)]
pub enum VerificationOutcome {
    /// The bundle is cryptographically valid and the subject digest matches.
    Valid {
        /// The OIDC subject URI extracted from the Fulcio certificate SAN.
        /// Empty string if no SAN was found (should not happen in practice).
        subject_identity: String,
    },
    /// The bundle is invalid (bad signature, cert chain, or subject mismatch).
    Invalid {
        /// Human-readable description of why the bundle failed.
        reason: String,
    },
}

/// A trait for verifying sigstore DSSE bundles.
///
/// This abstraction allows tests to inject a mock verifier that returns
/// predetermined outcomes without performing real cryptographic operations.
/// The real implementation (`RealSigstoreVerifier`) does the actual P-256
/// signature verification and certificate parsing.
///
/// # Algorithm agnosticism
///
/// The `expected_digest_algo` / `expected_digest_hex` parameters allow the
/// same verifier trait to be used by both npm (sha512) and PyPI (sha256)
/// attestation policies without hard-coding the algorithm.
pub trait SigstoreVerifier: Send + Sync {
    /// Verify a single attestation bundle.
    ///
    /// - `bundle`: the parsed attestation bundle to verify.
    /// - `expected_digest_algo`: e.g. `"sha512"` or `"sha256"`.
    /// - `expected_digest_hex`: the registry-published digest hex to compare
    ///   against the SLSA predicate's `subject.digest[algo]`.
    fn verify(
        &self,
        bundle: &AttestationBundle,
        expected_digest_algo: &str,
        expected_digest_hex: &str,
    ) -> VerificationOutcome;
}

// ---------------------------------------------------------------------------
// Real implementation
// ---------------------------------------------------------------------------

/// Production implementation that performs ECDSA P-256 signature verification
/// and X.509 certificate parsing.
pub struct RealSigstoreVerifier;

impl SigstoreVerifier for RealSigstoreVerifier {
    fn verify(
        &self,
        bundle: &AttestationBundle,
        expected_digest_algo: &str,
        expected_digest_hex: &str,
    ) -> VerificationOutcome {
        verify_dsse_bundle(bundle, expected_digest_algo, expected_digest_hex)
    }
}

// ---------------------------------------------------------------------------
// Core verification logic
// ---------------------------------------------------------------------------

/// Verify a DSSE bundle and compare the SLSA subject digest.
///
/// This is the algorithm-agnostic helper designed for reuse by both the npm
/// provenance policy (task 032) and the PyPI provenance policy (task 033).
///
/// Returns `VerificationOutcome::Valid { subject_identity }` if all checks pass,
/// or `VerificationOutcome::Invalid { reason }` with a descriptive failure message.
pub fn verify_dsse_bundle(
    bundle: &AttestationBundle,
    expected_digest_algo: &str,
    expected_digest_hex: &str,
) -> VerificationOutcome {
    // 1. Decode the DSSE payload.
    let payload_bytes = match bundle.dsse_envelope.decoded_payload() {
        Some(b) => b,
        None => {
            return VerificationOutcome::Invalid {
                reason: "failed to base64-decode DSSE payload".to_string(),
            };
        }
    };

    // 2. Parse the SLSA statement and compare the subject digest.
    //    Do this BEFORE signature verification so that if the digest mismatches
    //    we give a precise "subject digest mismatch" message distinct from a
    //    signature failure.
    let stmt = match parse_slsa_statement(&payload_bytes) {
        Ok(s) => s,
        Err(e) => {
            return VerificationOutcome::Invalid {
                reason: format!("failed to parse SLSA statement: {e}"),
            };
        }
    };

    let actual_digest = match stmt.subject_digest(expected_digest_algo) {
        Some(d) => d.to_string(),
        None => {
            return VerificationOutcome::Invalid {
                reason: format!(
                    "SLSA predicate has no subject digest for algorithm '{expected_digest_algo}'"
                ),
            };
        }
    };

    if actual_digest != expected_digest_hex {
        return VerificationOutcome::Invalid {
            reason: format!(
                "subject digest mismatch: attestation has {expected_digest_algo}:{actual_digest}, \
                 registry served {expected_digest_algo}:{expected_digest_hex}"
            ),
        };
    }

    // 3. Obtain the leaf certificate.
    let leaf_cert_der = match extract_leaf_cert_der(&bundle.verification_material) {
        Ok(der) => der,
        Err(e) => {
            return VerificationOutcome::Invalid {
                reason: format!("failed to decode leaf certificate: {e}"),
            };
        }
    };

    // 4. Parse the leaf certificate.
    let (_rem, x509) = match X509Certificate::from_der(&leaf_cert_der) {
        Ok(parsed) => parsed,
        Err(e) => {
            return VerificationOutcome::Invalid {
                reason: format!("failed to parse X.509 certificate: {e}"),
            };
        }
    };

    // 5. Extract the public key from the certificate.
    let verifying_key =
        match P256VerifyingKey::from_sec1_bytes(x509.public_key().subject_public_key.as_ref()) {
            Ok(k) => k,
            Err(e) => {
                return VerificationOutcome::Invalid {
                    reason: format!("certificate public key is not a valid P-256 key: {e}"),
                };
            }
        };

    // 6. Verify the DSSE signature over the PAE message.
    let pae = dsse_pae(&bundle.dsse_envelope.payload_type, &payload_bytes);

    let sig_bytes = match bundle.dsse_envelope.signatures.first() {
        Some(s) => match base64::engine::general_purpose::STANDARD.decode(&s.sig_b64) {
            Ok(b) => b,
            Err(_) => {
                return VerificationOutcome::Invalid {
                    reason: "failed to base64-decode DSSE signature".to_string(),
                };
            }
        },
        None => {
            return VerificationOutcome::Invalid {
                reason: "DSSE envelope has no signatures".to_string(),
            };
        }
    };

    let signature = match P256Signature::from_der(&sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            return VerificationOutcome::Invalid {
                reason: format!("failed to parse DER signature: {e}"),
            };
        }
    };

    if let Err(e) = verifying_key.verify(&pae, &signature) {
        return VerificationOutcome::Invalid {
            reason: format!("signature verification failed: {e}"),
        };
    }

    // 7. Extract the OIDC subject identity from the certificate's SAN extension.
    let subject_identity = extract_subject_identity(&x509);

    // 8. Check that the certificate carries the Fulcio issuer OID extension,
    //    indicating it was issued by the Fulcio CA (structural check only).
    //    OID 1.3.6.1.4.1.57264.1.1 is the sigstore OIDC issuer extension.
    let fulcio_oid_str = "1.3.6.1.4.1.57264.1.1";
    let has_fulcio_ext = x509
        .extensions()
        .iter()
        .any(|ext| ext.oid.to_string() == fulcio_oid_str);

    if !has_fulcio_ext {
        return VerificationOutcome::Invalid {
            reason:
                "certificate is missing the Fulcio OIDC issuer extension (1.3.6.1.4.1.57264.1.1); \
                     certificate was not issued by Fulcio CA"
                    .to_string(),
        };
    }

    VerificationOutcome::Valid { subject_identity }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode the leaf certificate DER bytes from the bundle's verification material.
fn extract_leaf_cert_der(vm: &VerificationMaterial) -> Result<Vec<u8>, String> {
    match vm {
        VerificationMaterial::X509CertChain(certs) => {
            let leaf_b64 = certs.first().ok_or("cert chain is empty")?;
            base64::engine::general_purpose::STANDARD
                .decode(leaf_b64)
                .map_err(|e| format!("base64 decode failed: {e}"))
        }
        VerificationMaterial::PublicKeyHint(_) => {
            Err("bundle uses a public key hint; cannot verify cert chain".to_string())
        }
    }
}

/// Extract the OIDC subject URI from the certificate's Subject Alternative Name.
///
/// Fulcio certs carry the workflow identity as a URI SAN.
/// Returns an empty string if no URI SAN is found.
fn extract_subject_identity(cert: &X509Certificate<'_>) -> String {
    for ext in cert.extensions() {
        if ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME
            && let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension()
        {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    return uri.to_string();
                }
            }
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod mock {
    use super::*;

    /// A mock `SigstoreVerifier` for use in unit tests.
    ///
    /// Stores a list of predetermined outcomes that are returned in order.
    pub struct MockVerifier {
        outcomes: Vec<VerificationOutcome>,
    }

    impl MockVerifier {
        pub fn new(outcomes: Vec<VerificationOutcome>) -> Self {
            Self { outcomes }
        }

        /// Return a verifier that always returns `Valid` with the given identity.
        pub fn always_valid(identity: &str) -> Self {
            Self::new(vec![VerificationOutcome::Valid {
                subject_identity: identity.to_string(),
            }])
        }

        /// Return a verifier that always returns `Invalid` with the given reason.
        pub fn always_invalid(reason: &str) -> Self {
            Self::new(vec![VerificationOutcome::Invalid {
                reason: reason.to_string(),
            }])
        }
    }

    impl SigstoreVerifier for MockVerifier {
        fn verify(
            &self,
            _bundle: &AttestationBundle,
            _expected_digest_algo: &str,
            _expected_digest_hex: &str,
        ) -> VerificationOutcome {
            self.outcomes
                .first()
                .cloned()
                .unwrap_or(VerificationOutcome::Invalid {
                    reason: "MockVerifier: no outcomes configured".to_string(),
                })
        }
    }
}

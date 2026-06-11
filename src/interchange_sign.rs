//! DSSE envelope signing for downstream-bound interchange output (task 086).
//!
//! ADR 006 Q4 + Q8 resolve that dep-scan signs the machine-readable
//! interchange formats (`--format osv` / `cyclonedx` / `spdx` / `vex`) in a
//! DSSE (Dead Simple Signing Envelope) so a downstream consumer can verify the
//! report was produced by a trusted dep-scan identity and was not tampered
//! with in transit.  Signing is applied **once per run** over the entire
//! rendered result set — never per-package — and is the inverse of the DSSE
//! verification machinery in [`crate::sigstore_verify`].
//!
//! The default `native` table and the `--format json` array are **never**
//! signed: signing those paths would add latency to the primary local-developer
//! scan loop, which is a hard performance constraint (ADR 006 Q8).  This module
//! is only reachable from the interchange-format branch of the output dispatch
//! in `run_check`.
//!
//! ## PAE encoding
//!
//! The signature is computed over the DSSE Pre-Authentication Encoding (PAE):
//!
//! ```text
//! DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>
//! ```
//!
//! where the lengths are ASCII-decimal byte counts, space-separated.  We reuse
//! the canonical [`crate::registry::npm_attestation::dsse_pae`] helper so the
//! signing side and the verification side share one encoder — there is no risk
//! of the two drifting apart.
//!
//! ## Signing identity
//!
//! The signing *identity* (keyless sigstore vs. operator-provisioned offline
//! key) is task 087.  This module defines the [`InterchangeSigner`] trait and a
//! test-only Ed25519 implementation so the envelope construction and the
//! signature round-trip can be exercised without network access or a
//! production key.
//!
//! ## Spec marker coverage
//! T-086-01 .. T-086-08 (envelope structure + crypto round-trip),
//! T-086-15 (one signature per run), T-086-17 (signing failure is fatal),
//! T-086-18 (`--allow-unsigned` raw payload + marker).

use anyhow::{Result, anyhow};
use base64::Engine as _;
use serde_json::json;

use crate::cli::OutputFormat;
use crate::registry::npm_attestation::dsse_pae;

/// JSON key whose presence marks a payload as explicitly unsigned.
///
/// When `--allow-unsigned` is set the interchange payload is emitted raw (no
/// DSSE envelope).  A consumer applying policy needs a deterministic way to
/// distinguish "this is an unsigned report" from "this is a signed envelope I
/// failed to recognise".  `sign_interchange` never emits this marker; only
/// [`mark_unsigned`] does, and a DSSE envelope never contains it.
pub const UNSIGNED_MARKER_KEY: &str = "_dep_scan_unsigned";

/// A minimal signing abstraction over the DSSE PAE bytes.
///
/// The production implementation (sigstore keyless + offline pinned key) is
/// provided by task 087.  Tests use [`StaticEd25519Signer`].
///
/// `sign` returns the raw signature bytes plus a `keyid` string that is
/// embedded verbatim in the envelope's `signatures[].keyid` field so a verifier
/// can select the correct public key.
pub trait InterchangeSigner {
    /// Sign the DSSE PAE bytes, returning `(sig_bytes, keyid)`.
    fn sign(&self, pae: &[u8]) -> Result<(Vec<u8>, String)>;
}

/// Return the IANA-style media type used as the DSSE `payloadType` for a given
/// interchange output format.
///
/// Only the four interchange formats have a media type; `Native` and `Json`
/// are never signed (they return `None`) and must never reach this function on
/// the live path.
pub fn payload_type_for_format(format: &OutputFormat) -> Option<&'static str> {
    match format {
        OutputFormat::Osv => Some("application/vnd.osv+json"),
        OutputFormat::CycloneDx => Some("application/vnd.cyclonedx+json"),
        OutputFormat::Spdx => Some("application/spdx+json"),
        OutputFormat::Vex => Some("application/vnd.openvex+json"),
        OutputFormat::Native | OutputFormat::Json => None,
    }
}

/// Build a DSSE envelope JSON string for `payload`, signed by `signer`.
///
/// Steps:
/// 1. Compute the DSSE PAE: `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`.
/// 2. Sign the PAE with `signer`.
/// 3. Serialise the envelope:
///    ```json
///    {
///      "payload":     "<base64(payload)>",
///      "payloadType": "<payload_type>",
///      "signatures":  [ { "keyid": "<keyid>", "sig": "<base64(sig)>" } ]
///    }
///    ```
///
/// Returns `Err` if the signer fails (REQ-086-05 — the caller treats this as
/// fatal and writes nothing to stdout) or if serialization fails.
pub fn sign_interchange(
    payload: &[u8],
    payload_type: &str,
    signer: &dyn InterchangeSigner,
) -> Result<String> {
    let pae = dsse_pae(payload_type, payload);
    let (sig_bytes, keyid) = signer
        .sign(&pae)
        .map_err(|e| anyhow!("interchange signing failed: {e}"))?;

    let envelope = json!({
        "payload": base64::engine::general_purpose::STANDARD.encode(payload),
        "payloadType": payload_type,
        "signatures": [
            {
                "keyid": keyid,
                "sig": base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
            }
        ],
    });

    serde_json::to_string(&envelope).map_err(|e| anyhow!("failed to serialize DSSE envelope: {e}"))
}

/// Wrap a raw interchange payload with an explicit unsigned marker.
///
/// Used only when `--allow-unsigned` is set.  The raw payload is parsed as JSON
/// (every interchange renderer emits a JSON object) and the marker key
/// [`UNSIGNED_MARKER_KEY`] is injected so a downstream consumer can detect that
/// no signature is present and apply its own policy (REQ-086-06, T-086-18).
///
/// This deliberately does **not** produce a DSSE envelope: there is no
/// `payload`/`signatures` wrapping and the signer is never invoked.
pub fn mark_unsigned(payload: &[u8]) -> Result<String> {
    let mut value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| anyhow!("interchange payload is not valid JSON: {e}"))?;

    match value.as_object_mut() {
        Some(map) => {
            map.insert(UNSIGNED_MARKER_KEY.to_string(), json!(true));
        }
        None => {
            return Err(anyhow!(
                "interchange payload is not a JSON object; cannot attach unsigned marker"
            ));
        }
    }

    serde_json::to_string(&value).map_err(|e| anyhow!("failed to serialize unsigned payload: {e}"))
}

// ---------------------------------------------------------------------------
// Test-only Ed25519 signer
// ---------------------------------------------------------------------------

/// An [`InterchangeSigner`] backed by a static Ed25519 key pair.
///
/// This exists so the envelope construction and the signature round-trip can be
/// exercised without network access or a production signing identity.  Until
/// task 087 wires the production identity (sigstore keyless / operator-
/// provisioned offline key), `run_check` uses this signer as the default so the
/// interchange-output signing path is exercised end-to-end.  Task 087 will
/// replace the `run_check` construction site with the production signer; this
/// type then reverts to test-only use.
pub struct StaticEd25519Signer {
    signing_key: ed25519_dalek::SigningKey,
    keyid: String,
}

impl StaticEd25519Signer {
    /// Generate a fresh random Ed25519 key pair for use in a single test.
    pub fn generate() -> Self {
        use rand_core::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        Self {
            signing_key,
            keyid: "test-ed25519".to_string(),
        }
    }

    /// The verifying (public) key, for round-trip verification in tests.
    #[cfg(test)]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The keyid this signer stamps into the envelope.
    #[cfg(test)]
    pub fn keyid(&self) -> &str {
        &self.keyid
    }
}

impl InterchangeSigner for StaticEd25519Signer {
    fn sign(&self, pae: &[u8]) -> Result<(Vec<u8>, String)> {
        use ed25519_dalek::Signer as _;
        let sig = self.signing_key.sign(pae);
        Ok((sig.to_bytes().to_vec(), self.keyid.clone()))
    }
}

/// A signer that always fails, for exercising the fatal-signing-failure path
/// (REQ-086-05, T-086-17).
#[cfg(test)]
pub struct FailingSigner;

#[cfg(test)]
impl InterchangeSigner for FailingSigner {
    fn sign(&self, _pae: &[u8]) -> Result<(Vec<u8>, String)> {
        Err(anyhow!("no signing identity available"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier as _;

    const OSV_TYPE: &str = "application/vnd.osv+json";

    /// Verify a DSSE envelope against an Ed25519 public key, reconstructing the
    /// PAE from the envelope's own `payload` and `payloadType` exactly as a
    /// downstream consumer would.  Returns `Ok(())` only if the signature is
    /// cryptographically valid.
    fn verify_envelope(
        envelope_json: &str,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        let v: serde_json::Value = serde_json::from_str(envelope_json)?;
        let payload_b64 = v["payload"].as_str().ok_or_else(|| anyhow!("no payload"))?;
        let payload_type = v["payloadType"]
            .as_str()
            .ok_or_else(|| anyhow!("no payloadType"))?;
        let payload = base64::engine::general_purpose::STANDARD.decode(payload_b64)?;
        let sig_b64 = v["signatures"][0]["sig"]
            .as_str()
            .ok_or_else(|| anyhow!("no sig"))?;
        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(sig_b64)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("signature is not 64 bytes"))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        let pae = dsse_pae(payload_type, &payload);
        verifying_key
            .verify(&pae, &signature)
            .map_err(|e| anyhow!("signature verification failed: {e}"))
    }

    // T-086-01: Signed interchange output is a DSSE envelope JSON object.
    #[test]
    fn t_086_01_output_is_dsse_envelope_object() {
        let signer = StaticEd25519Signer::generate();
        let payload = br#"{"results":[]}"#;
        let env = sign_interchange(payload, OSV_TYPE, &signer).expect("sign");
        let v: serde_json::Value = serde_json::from_str(&env).expect("parse");
        assert!(v.is_object(), "T-086-01: envelope must be a JSON object");
        assert!(v["payload"].is_string(), "T-086-01: payload is a string");
        assert!(
            v["payloadType"].is_string(),
            "T-086-01: payloadType is a string"
        );
        let sigs = v["signatures"].as_array().expect("signatures array");
        assert!(!sigs.is_empty(), "T-086-01: signatures non-empty");
    }

    // T-086-02: `payload` is base64-encoded rendered output.
    #[test]
    fn t_086_02_payload_round_trips() {
        let signer = StaticEd25519Signer::generate();
        let payload = br#"{"schema_version":"1.6.0","results":[{"a":1}]}"#;
        let env = sign_interchange(payload, OSV_TYPE, &signer).expect("sign");
        let v: serde_json::Value = serde_json::from_str(&env).expect("parse");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(v["payload"].as_str().unwrap())
            .expect("decode payload");
        assert_eq!(
            decoded,
            payload.to_vec(),
            "T-086-02: decoded payload must equal the original rendered bytes"
        );
    }

    // T-086-03: `payloadType` is a recognized media type per format.
    #[test]
    fn t_086_03_payload_type_per_format() {
        assert_eq!(
            payload_type_for_format(&OutputFormat::Osv),
            Some("application/vnd.osv+json")
        );
        assert_eq!(
            payload_type_for_format(&OutputFormat::CycloneDx),
            Some("application/vnd.cyclonedx+json")
        );
        assert_eq!(
            payload_type_for_format(&OutputFormat::Spdx),
            Some("application/spdx+json")
        );
        assert_eq!(
            payload_type_for_format(&OutputFormat::Vex),
            Some("application/vnd.openvex+json")
        );
        // Native and Json have no media type — they are never signed.
        assert_eq!(payload_type_for_format(&OutputFormat::Native), None);
        assert_eq!(payload_type_for_format(&OutputFormat::Json), None);

        // And the type stamped into the envelope matches.
        let signer = StaticEd25519Signer::generate();
        let env = sign_interchange(b"{}", "application/spdx+json", &signer).expect("sign");
        let v: serde_json::Value = serde_json::from_str(&env).unwrap();
        assert_eq!(v["payloadType"].as_str().unwrap(), "application/spdx+json");
    }

    // T-086-04: `signatures` array has exactly one entry per run.
    #[test]
    fn t_086_04_exactly_one_signature() {
        let signer = StaticEd25519Signer::generate();
        let env = sign_interchange(b"{}", OSV_TYPE, &signer).expect("sign");
        let v: serde_json::Value = serde_json::from_str(&env).unwrap();
        assert_eq!(
            v["signatures"].as_array().unwrap().len(),
            1,
            "T-086-04: exactly one signature entry per run"
        );
    }

    // T-086-05: Each signature entry has non-empty `sig` (base64) and `keyid`.
    #[test]
    fn t_086_05_signature_entry_fields() {
        let signer = StaticEd25519Signer::generate();
        let env = sign_interchange(b"{}", OSV_TYPE, &signer).expect("sign");
        let v: serde_json::Value = serde_json::from_str(&env).unwrap();
        let sig0 = &v["signatures"][0];
        let sig = sig0["sig"].as_str().expect("sig present");
        let keyid = sig0["keyid"].as_str().expect("keyid present");
        assert!(!sig.is_empty(), "T-086-05: sig non-empty");
        assert!(!keyid.is_empty(), "T-086-05: keyid non-empty");
        // sig must be valid base64.
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(sig)
                .is_ok(),
            "T-086-05: sig must be valid base64"
        );
        assert_eq!(keyid, signer.keyid(), "T-086-05: keyid matches signer");
    }

    // T-086-06: Signature verifies with the test public key.
    #[test]
    fn t_086_06_signature_verifies() {
        let signer = StaticEd25519Signer::generate();
        let payload = br#"{"results":[{"id":"GHSA-xxxx"}]}"#;
        let env = sign_interchange(payload, OSV_TYPE, &signer).expect("sign");
        verify_envelope(&env, &signer.verifying_key())
            .expect("T-086-06: signature must verify with the test public key");
    }

    // T-086-07: Tampered payload fails signature verification.
    #[test]
    fn t_086_07_tampered_payload_fails() {
        let signer = StaticEd25519Signer::generate();
        let payload = br#"{"results":[{"id":"GHSA-xxxx"}]}"#;
        let env = sign_interchange(payload, OSV_TYPE, &signer).expect("sign");

        // Alter one byte of the original payload and re-base64-encode it,
        // keeping the original signature.
        let mut v: serde_json::Value = serde_json::from_str(&env).unwrap();
        let mut original = base64::engine::general_purpose::STANDARD
            .decode(v["payload"].as_str().unwrap())
            .unwrap();
        original[0] ^= 0xff;
        v["payload"] = json!(base64::engine::general_purpose::STANDARD.encode(&original));
        let tampered = serde_json::to_string(&v).unwrap();

        assert!(
            verify_envelope(&tampered, &signer.verifying_key()).is_err(),
            "T-086-07: tampered payload must fail verification"
        );
    }

    // T-086-08: Tampered `payloadType` fails signature verification.
    #[test]
    fn t_086_08_tampered_payload_type_fails() {
        let signer = StaticEd25519Signer::generate();
        let payload = br#"{"results":[]}"#;
        let env = sign_interchange(payload, OSV_TYPE, &signer).expect("sign");

        let mut v: serde_json::Value = serde_json::from_str(&env).unwrap();
        // Change to a different (but still well-formed) media type.
        v["payloadType"] = json!("application/vnd.cyclonedx+json");
        let tampered = serde_json::to_string(&v).unwrap();

        assert!(
            verify_envelope(&tampered, &signer.verifying_key()).is_err(),
            "T-086-08: tampered payloadType must fail verification (PAE binds the type)"
        );
    }

    // T-086-15: Signing is one operation per run regardless of result-set size.
    #[test]
    fn t_086_15_one_signature_per_run_large_set() {
        // Simulate a large rendered payload (e.g. 50 results in one OSV doc).
        let mut results = Vec::new();
        for i in 0..50 {
            results.push(json!({ "id": format!("GHSA-{i:04}"), "modified": "2026-01-01" }));
        }
        let doc = json!({ "results": results });
        let payload = serde_json::to_vec(&doc).unwrap();

        let signer = StaticEd25519Signer::generate();
        let env = sign_interchange(&payload, OSV_TYPE, &signer).expect("sign");
        let v: serde_json::Value = serde_json::from_str(&env).unwrap();
        assert_eq!(
            v["signatures"].as_array().unwrap().len(),
            1,
            "T-086-15: all 50 results sit in one payload, signed exactly once"
        );
        // And that single signature must verify over the whole payload.
        verify_envelope(&env, &signer.verifying_key())
            .expect("T-086-15: the single signature covers the full result set");
    }

    // T-086-17: Signing failure returns `Err` and produces no envelope.
    #[test]
    fn t_086_17_signing_failure_is_fatal() {
        let signer = FailingSigner;
        let result = sign_interchange(b"{}", OSV_TYPE, &signer);
        assert!(
            result.is_err(),
            "T-086-17: a signer failure must propagate as Err (no unsigned fallback)"
        );
    }

    // T-086-18: `--allow-unsigned` emits the raw payload with an unsigned marker.
    #[test]
    fn t_086_18_unsigned_marker() {
        let payload = br#"{"schema_version":"1.6.0","results":[]}"#;
        let out = mark_unsigned(payload).expect("mark unsigned");
        let v: serde_json::Value = serde_json::from_str(&out).expect("parse");

        // No DSSE envelope: there must be no `payload`/`signatures` wrapping.
        assert!(
            v.get("signatures").is_none(),
            "T-086-18: unsigned output must not be a DSSE envelope"
        );
        assert!(
            v.get("payload").is_none(),
            "T-086-18: unsigned output must not have a base64 `payload` field"
        );
        // The original content is still present (raw, not base64-wrapped).
        assert_eq!(
            v["schema_version"].as_str(),
            Some("1.6.0"),
            "T-086-18: original payload content is preserved verbatim"
        );
        // Explicit unsigned marker a consumer can detect.
        assert_eq!(
            v[UNSIGNED_MARKER_KEY].as_bool(),
            Some(true),
            "T-086-18: unsigned marker must be present and true"
        );
    }

    // A signed envelope must never carry the unsigned marker — the two outputs
    // are mutually exclusive so a consumer can tell them apart unambiguously.
    #[test]
    fn signed_envelope_never_has_unsigned_marker() {
        let signer = StaticEd25519Signer::generate();
        let env = sign_interchange(br#"{"results":[]}"#, OSV_TYPE, &signer).expect("sign");
        let v: serde_json::Value = serde_json::from_str(&env).unwrap();
        assert!(v.get(UNSIGNED_MARKER_KEY).is_none());
    }
}

// SPDX-License-Identifier: Apache-2.0
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
use sha2::{Digest as _, Sha256};

use crate::cli::OutputFormat;
use crate::config::Config;
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
/// exercised without network access or a production signing identity.  As of
/// task 087 the live `run_check` path resolves a production identity via
/// [`resolve_signer`] (sigstore keyless online / [`OperatorKeySigner`] offline)
/// and no longer constructs this type — it is now test-only.
#[cfg(test)]
pub struct StaticEd25519Signer {
    signing_key: ed25519_dalek::SigningKey,
    keyid: String,
}

#[cfg(test)]
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

#[cfg(test)]
impl InterchangeSigner for StaticEd25519Signer {
    fn sign(&self, pae: &[u8]) -> Result<(Vec<u8>, String)> {
        use ed25519_dalek::Signer as _;
        let sig = self.signing_key.sign(pae);
        Ok((sig.to_bytes().to_vec(), self.keyid.clone()))
    }
}

/// A signer that always fails.
///
/// Two uses:
/// - exercising the fatal-signing-failure path (REQ-086-05, T-086-17);
/// - as a never-invoked placeholder on the paths that do not sign (`--format
///   json`, or any interchange format with `--allow-unsigned`). On those paths
///   the dispatcher never calls `sign`, but if a future refactor ever did, this
///   fails closed rather than emitting an ephemeral-key signature.
pub struct FailingSigner;

impl InterchangeSigner for FailingSigner {
    fn sign(&self, _pae: &[u8]) -> Result<(Vec<u8>, String)> {
        Err(anyhow!("no signing identity available"))
    }
}

// ---------------------------------------------------------------------------
// Key-id derivation (shared with task 089's public-key export)
// ---------------------------------------------------------------------------

/// Derive the stable key-id for an Ed25519 public key.
///
/// The key-id is the **lowercase hex SHA-256 of the 32 raw public-key bytes**
/// (not the SPKI DER, not the PEM). A consumer who holds the public half can
/// recompute this exact value to select the correct verification key.
///
/// This derivation is the single source of truth for the operator-key
/// identity: task 089 exports the public half and MUST stamp the same key-id,
/// and a verifier matches on it. Keep this function as the one place the
/// derivation lives so the signer and the export tool cannot drift apart.
pub fn ed25519_keyid(public_key_bytes: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(public_key_bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Operator-key offline signer (REQ-087-01)
// ---------------------------------------------------------------------------

/// An [`InterchangeSigner`] backed by an operator-provisioned Ed25519 private
/// key loaded from disk (PEM-encoded PKCS#8).
///
/// This is the **offline** signing identity (ADR 006 Q5 / ADR 007). The key is
/// operator-provisioned and never embedded in the binary. Construction reads
/// and parses the key file once; `sign` is a pure local Ed25519 operation. No
/// network access happens during construction or signing.
///
/// The key reference is a filesystem path today; ADR 007 keeps it pluggable so
/// a `pkcs11:` / KMS backend can be added later without a breaking change.
pub struct OperatorKeySigner {
    signing_key: ed25519_dalek::SigningKey,
    keyid: String,
}

impl OperatorKeySigner {
    /// Load an operator signing key from a PEM-encoded PKCS#8 Ed25519 file.
    ///
    /// Returns `Err` if the path cannot be read or the contents do not parse as
    /// a PKCS#8 Ed25519 private key (REQ-087-01, T-087-05) — there is no silent
    /// success with an unusable signer.
    pub fn from_key_path(path: &std::path::Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read signing key {}: {e}", path.display()))?;
        Self::from_pkcs8_pem(&pem)
    }

    /// Parse an operator signing key from PEM-encoded PKCS#8 Ed25519 text.
    ///
    /// Factored out of [`Self::from_key_path`] so tests can construct a signer
    /// from an in-memory PEM string without touching the filesystem.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        use ed25519_dalek::pkcs8::DecodePrivateKey as _;
        let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow!("failed to parse PEM PKCS#8 Ed25519 signing key: {e}"))?;
        let verifying_key = signing_key.verifying_key();
        let keyid = ed25519_keyid(verifying_key.as_bytes());
        Ok(Self { signing_key, keyid })
    }

    /// The verifying (public) key, for round-trip verification in tests and for
    /// task 089's public-key export (which exports this half as PEM SPKI).
    // Not yet called on the live binary path — task 089 will consume it.
    #[allow(dead_code)]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The key-id this signer stamps into the DSSE envelope.
    // Read by tests today; task 089's export reuses the same derivation via
    // `ed25519_keyid` so consumers can match keys.
    #[allow(dead_code)]
    pub fn keyid(&self) -> &str {
        &self.keyid
    }
}

impl InterchangeSigner for OperatorKeySigner {
    fn sign(&self, pae: &[u8]) -> Result<(Vec<u8>, String)> {
        use ed25519_dalek::Signer as _;
        let sig = self.signing_key.sign(pae);
        Ok((sig.to_bytes().to_vec(), self.keyid.clone()))
    }
}

// ---------------------------------------------------------------------------
// Keyless online signer (REQ-087-02)
// ---------------------------------------------------------------------------

/// An [`InterchangeSigner`] that uses sigstore keyless signing: it obtains a
/// short-lived Fulcio code-signing certificate bound to an OIDC identity,
/// signs the PAE with the ephemeral key whose public half the cert certifies,
/// and records the signature in the Rekor transparency log.
///
/// The Fulcio and Rekor URLs are configurable (no hardcoded registry URLs) so
/// tests can point them at a wiremock server. `sign` returns `Err` if either
/// Fulcio or Rekor is unreachable (REQ-087-02, T-087-08) — the keyless path is
/// fail-closed and never produces a partial/unsigned result.
///
/// The synchronous `sign` drives the async Fulcio/Rekor HTTP calls via the
/// `block_in_place` bridge documented in ADR 010.
pub struct KeylessSigner {
    fulcio_url: String,
    rekor_url: String,
    oidc_token: String,
    client: reqwest::Client,
}

impl KeylessSigner {
    /// Construct a keyless signer pointed at the given Fulcio and Rekor base
    /// URLs, authenticating to Fulcio with `oidc_token`.
    ///
    /// Construction makes no network calls (T-087-06 asserts the calls happen
    /// in `sign`, not `new`).
    pub fn new(fulcio_url: &str, rekor_url: &str, oidc_token: &str) -> Self {
        Self {
            fulcio_url: fulcio_url.trim_end_matches('/').to_string(),
            rekor_url: rekor_url.trim_end_matches('/').to_string(),
            oidc_token: oidc_token.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Async core of the keyless flow, driven synchronously by [`Self::sign`].
    async fn sign_async(&self, pae: &[u8]) -> Result<(Vec<u8>, String)> {
        use p256::ecdsa::SigningKey as P256SigningKey;
        use p256::ecdsa::signature::Signer as _;
        use p256::pkcs8::EncodePublicKey as _;
        use rand_core::OsRng;

        // 1. Generate an ephemeral P-256 key (Fulcio certifies its public half).
        let ephemeral = P256SigningKey::random(&mut OsRng);
        let pub_pem = ephemeral
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|e| anyhow!("failed to encode ephemeral public key: {e}"))?;

        // 2. Fulcio: exchange the OIDC token + public key for a signing cert.
        let fulcio_req = json!({
            "credentials": { "oidcIdentityToken": self.oidc_token },
            "publicKeyRequest": {
                "publicKey": { "algorithm": "ECDSA", "content": pub_pem },
                "proofOfPossession": "",
            },
        });
        let fulcio_resp = self
            .client
            .post(format!("{}/api/v2/signingCert", self.fulcio_url))
            .json(&fulcio_req)
            .send()
            .await
            .map_err(|e| anyhow!("Fulcio request failed (network): {e}"))?;
        if !fulcio_resp.status().is_success() {
            return Err(anyhow!(
                "Fulcio returned non-success status {}",
                fulcio_resp.status()
            ));
        }
        let fulcio_body: serde_json::Value = fulcio_resp
            .json()
            .await
            .map_err(|e| anyhow!("Fulcio response was not valid JSON: {e}"))?;
        let keyid = fulcio_subject_keyid(&fulcio_body)
            .ok_or_else(|| anyhow!("Fulcio response did not contain a signing certificate"))?;

        // 3. Sign the PAE with the ephemeral key (ECDSA P-256, DER-encoded).
        let sig: p256::ecdsa::Signature = ephemeral.sign(pae);
        let sig_bytes = sig.to_der().as_bytes().to_vec();

        // 4. Rekor: record the signature in the transparency log. A failure
        //    here is fatal — an unlogged keyless signature is not trustworthy.
        let rekor_req = json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "signature": base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": hex_sha256(pae),
                },
            },
        });
        let rekor_resp = self
            .client
            .post(format!("{}/api/v1/log/entries", self.rekor_url))
            .json(&rekor_req)
            .send()
            .await
            .map_err(|e| anyhow!("Rekor request failed (network): {e}"))?;
        if !rekor_resp.status().is_success() {
            return Err(anyhow!(
                "Rekor returned non-success status {}",
                rekor_resp.status()
            ));
        }

        Ok((sig_bytes, keyid))
    }
}

impl InterchangeSigner for KeylessSigner {
    fn sign(&self, pae: &[u8]) -> Result<(Vec<u8>, String)> {
        // Bridge the synchronous trait to the async HTTP flow (ADR 010).
        // Requires a multi-threaded tokio runtime on the call stack, which the
        // live `run_check` path (`#[tokio::main]`) and the multi-thread test
        // runtime both provide.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.sign_async(pae))
        })
    }
}

/// Derive the keyless key-id from a Fulcio `signingCert` response.
///
/// The key-id is the OIDC subject the cert binds (T-087-07). We surface the
/// leaf certificate (PEM) from the standard Fulcio v2 response shape and use a
/// SHA-256 over its bytes as a stable handle for the identity. Returns `None`
/// if no certificate is present.
fn fulcio_subject_keyid(fulcio_body: &serde_json::Value) -> Option<String> {
    let chain = fulcio_body
        .get("signedCertificateEmbeddedSct")
        .or_else(|| fulcio_body.get("signedCertificateDetachedSct"))
        .and_then(|v| v.get("chain"))
        .and_then(|c| c.get("certificates"))
        .and_then(|certs| certs.as_array())?;
    let leaf = chain.first()?.as_str()?;
    Some(format!("fulcio:{}", hex_sha256(leaf.as_bytes())))
}

fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Signer resolution (REQ-087-03)
// ---------------------------------------------------------------------------

/// The outcome of [`resolve_signer`]: either a concrete signer to use, or an
/// explicit "no offline signing identity available" decision that drives the
/// fail-closed behavior (REQ-087-05).
///
/// This is deliberately **not** a silently-unsigned signer: the absence of an
/// offline key is represented as a distinct variant the caller must handle,
/// never as a no-op signer that would emit unsigned-but-signed-looking output.
pub enum SignerDecision {
    /// A signer is available; use it to produce the DSSE envelope.
    Signer(Box<dyn InterchangeSigner>),
    /// Offline path selected but no `signing.key_path` is configured. The
    /// caller must fail closed (non-zero exit) unless `--allow-unsigned` was
    /// passed. Carries the operator-facing remediation message.
    NoOfflineKey,
}

impl SignerDecision {
    /// Standard fail-closed message naming the two ways forward.
    pub const NO_OFFLINE_KEY_MESSAGE: &'static str = "offline signing requested but no signing key configured; \
         set signing.key_path or pass --allow-unsigned";
}

/// Resolve the signing identity for this run (REQ-087-03).
///
/// Selection order:
/// 1. If `config.signing.offline` is true (which `DEP_SCAN_OFFLINE` may have
///    forced via the config env layer) → offline path.
/// 2. Otherwise probe the network via `network_probe`; success ⇒ keyless,
///    failure ⇒ offline path.
///
/// On the offline path: `signing.key_path` set ⇒ [`OperatorKeySigner`];
/// not set ⇒ [`SignerDecision::NoOfflineKey`] (fail-closed signal).
///
/// `network_probe` is injected so tests can simulate online/offline without a
/// real network call. The live caller passes a lightweight reachability probe.
/// `keyless_factory` builds the keyless signer when the probe succeeds; it is
/// injected for the same reason (tests substitute a stub).
pub fn resolve_signer(
    config: &Config,
    network_probe: impl FnOnce() -> Result<()>,
    keyless_factory: impl FnOnce() -> Box<dyn InterchangeSigner>,
) -> Result<SignerDecision> {
    let offline = config.signing.offline || network_probe().is_err();

    if offline {
        if config.signing.key_path.trim().is_empty() {
            return Ok(SignerDecision::NoOfflineKey);
        }
        let signer =
            OperatorKeySigner::from_key_path(std::path::Path::new(&config.signing.key_path))?;
        Ok(SignerDecision::Signer(Box::new(signer)))
    } else {
        Ok(SignerDecision::Signer(keyless_factory()))
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

    // -----------------------------------------------------------------------
    // Task 087 — operator-key offline signer + keyless online + resolve_signer
    // -----------------------------------------------------------------------

    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    /// Generate a fresh Ed25519 key-pair and return its PEM PKCS#8 private-key
    /// encoding plus the verifying key, for operator-signer tests. The private
    /// key lives only in this test's memory / a tempfile — never committed.
    fn gen_ed25519_pem() -> (String, ed25519_dalek::VerifyingKey) {
        use rand_core::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let pem = sk
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .expect("encode pkcs8 pem")
            .to_string();
        (pem, vk)
    }

    /// Write a PEM private key to a NamedTempFile and return the guard so the
    /// file is deleted on drop (no key material persists on disk after the
    /// test).
    fn write_key_tempfile(pem: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(pem.as_bytes()).expect("write key");
        f.flush().expect("flush");
        f
    }

    // T-087-01: OperatorKeySigner loads a key from a path and signs offline.
    #[test]
    fn t_087_01_operator_key_loads_and_signs() {
        let (pem, _vk) = gen_ed25519_pem();
        let keyfile = write_key_tempfile(&pem);
        let signer = OperatorKeySigner::from_key_path(keyfile.path()).expect("load operator key");
        let (sig, keyid) = signer.sign(b"test payload").expect("sign");
        assert!(!sig.is_empty(), "T-087-01: signature bytes non-empty");
        assert!(!keyid.is_empty(), "T-087-01: keyid non-empty");
        assert_eq!(sig.len(), 64, "Ed25519 signatures are 64 bytes");
    }

    // T-087-02: operator-key signed envelope verifies with the public key.
    #[test]
    fn t_087_02_operator_signature_verifies() {
        use ed25519_dalek::Verifier as _;
        let (pem, vk) = gen_ed25519_pem();
        let keyfile = write_key_tempfile(&pem);
        let signer = OperatorKeySigner::from_key_path(keyfile.path()).expect("load");

        // The signer's exposed public half (used by task 089's export) must
        // match the key-pair we generated.
        assert_eq!(
            signer.verifying_key().as_bytes(),
            vk.as_bytes(),
            "T-087-02: signer.verifying_key() must equal the loaded key's public half"
        );

        // 64-byte payload per the spec.
        let payload = [0x5au8; 64];
        let pae = dsse_pae(OSV_TYPE, &payload);
        let (sig_bytes, _keyid) = signer.sign(&pae).expect("sign");

        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().expect("64-byte sig");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify(&pae, &signature)
            .expect("T-087-02: signature must verify against the public key");
    }

    // T-087-03: key-id is a stable function of the public key, distinct per key.
    #[test]
    fn t_087_03_keyid_derived_from_public_key() {
        // Pre-computed: keyid == lowercase hex SHA-256 of the 32 raw pubkey bytes.
        let (pem, vk) = gen_ed25519_pem();
        let keyfile = write_key_tempfile(&pem);
        let signer = OperatorKeySigner::from_key_path(keyfile.path()).expect("load");

        let expected = {
            let mut h = Sha256::new();
            h.update(vk.as_bytes());
            let d = h.finalize();
            let mut s = String::new();
            for b in d {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
            }
            s
        };
        assert_eq!(
            signer.keyid(),
            expected,
            "T-087-03: keyid must be lowercase hex SHA-256 of the raw public key"
        );
        // Stable across reloads of the same key.
        let signer2 = OperatorKeySigner::from_key_path(keyfile.path()).expect("reload");
        assert_eq!(signer.keyid(), signer2.keyid(), "T-087-03: keyid is stable");

        // Two different keys → two different keyids.
        let (pem_b, _vkb) = gen_ed25519_pem();
        let kf_b = write_key_tempfile(&pem_b);
        let signer_b = OperatorKeySigner::from_key_path(kf_b.path()).expect("load b");
        assert_ne!(
            signer.keyid(),
            signer_b.keyid(),
            "T-087-03: different keys produce different keyids"
        );
    }

    // T-087-03 (cont.): the shared ed25519_keyid function is the derivation
    // source of truth used by both the signer and (later) task 089's export.
    #[test]
    fn t_087_03_shared_keyid_function() {
        let (pem, vk) = gen_ed25519_pem();
        let keyfile = write_key_tempfile(&pem);
        let signer = OperatorKeySigner::from_key_path(keyfile.path()).expect("load");
        assert_eq!(
            signer.keyid(),
            ed25519_keyid(vk.as_bytes()),
            "T-087-03: signer keyid must equal ed25519_keyid(public_key)"
        );
    }

    // T-087-04 (part): no build-time embedded private key — there is no API to
    // construct an OperatorKeySigner without supplying a key. (The "key_path
    // unset ⇒ no signer" half is covered by t_087_15_* via resolve_signer.)
    // This test asserts the signer is purely a function of supplied key bytes.
    #[test]
    fn t_087_04_operator_key_is_pure_local() {
        let (pem, _vk) = gen_ed25519_pem();
        // from_pkcs8_pem takes the key in-memory: construction touches no
        // filesystem and no network.
        let signer = OperatorKeySigner::from_pkcs8_pem(&pem).expect("parse in-memory key");
        let (sig, _keyid) = signer.sign(b"payload").expect("sign offline");
        assert_eq!(sig.len(), 64);
    }

    // T-087-04: OperatorKeySigner makes ZERO outbound network connections during
    // construction *and* signing. We stand up a wiremock server with a catch-all
    // stub mounted `.expect(0)` (same wiremock pattern as the keyless tests
    // above), then load an OperatorKeySigner from a tempfile PEM and sign. After
    // signing we assert the server received zero requests. The `.expect(0)` is
    // verified on MockServer drop too, so this test FAILS if OperatorKeySigner
    // ever issues an HTTP call — proving the offline signer is truly offline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t_087_04_operator_key_makes_zero_network_calls() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Catch-all: any method, any path. If OperatorKeySigner ever reaches out,
        // it is overwhelmingly likely to hit this stub; expect(0) then trips on
        // drop, and the explicit received_requests() assertion below trips first.
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let (pem, _vk) = gen_ed25519_pem();
        let keyfile = write_key_tempfile(&pem);

        // Construction from the on-disk key, and signing, both run on a blocking
        // thread (sign() is synchronous) so nothing about the async runtime masks
        // an outbound call.
        let kf_path = keyfile.path().to_path_buf();
        let sig = tokio::task::spawn_blocking(move || {
            let signer = OperatorKeySigner::from_key_path(&kf_path).expect("load operator key");
            let (sig, _keyid) = signer.sign(b"test payload").expect("sign offline");
            sig
        })
        .await
        .expect("join");
        assert_eq!(
            sig.len(),
            64,
            "T-087-04: Ed25519 signature produced offline"
        );

        // Explicit zero-request assertion: this fails loudly if any HTTP request
        // reached the mock during construction or signing.
        let requests = server
            .received_requests()
            .await
            .expect("wiremock records requests when running");
        assert!(
            requests.is_empty(),
            "T-087-04: OperatorKeySigner must make ZERO network calls, but the mock \
             received {} request(s): {:?}",
            requests.len(),
            requests
        );
        // MockServer drop also verifies the expect(0) expectation.
    }

    // T-087-05: unreadable / malformed key path returns Err.
    #[test]
    fn t_087_05_bad_key_path_errs() {
        // Non-existent path.
        let missing = std::path::Path::new("/tmp/dep-scan-no-such-key-087.pem");
        assert!(
            OperatorKeySigner::from_key_path(missing).is_err(),
            "T-087-05: missing key file must return Err"
        );

        // Garbage bytes (not a PKCS#8 PEM).
        let garbage = write_key_tempfile("not a pkcs8 pem key at all\n\x00\x01\x02");
        assert!(
            OperatorKeySigner::from_key_path(garbage.path()).is_err(),
            "T-087-05: malformed key file must return Err (no silent success)"
        );
    }

    // T-087-06: KeylessSigner triggers a Fulcio + a Rekor request on sign.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t_087_06_keyless_calls_fulcio_and_rekor() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Fulcio signingCert stub: return a minimal v2 response with a cert.
        Mock::given(method("POST"))
            .and(path("/api/v2/signingCert"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signedCertificateEmbeddedSct": {
                    "chain": { "certificates": ["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"] }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Rekor log entry stub.
        Mock::given(method("POST"))
            .and(path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"uuid": "abc"})))
            .expect(1)
            .mount(&server)
            .await;

        let signer = KeylessSigner::new(&server.uri(), &server.uri(), "fake-oidc-token");
        let pae = dsse_pae(OSV_TYPE, b"test payload");

        // block_in_place inside the multi-thread runtime drives sign_async.
        let (sig, keyid) = tokio::task::spawn_blocking(move || signer.sign(&pae))
            .await
            .expect("join")
            .expect("T-087-06: keyless sign must succeed against the stubs");

        assert!(!sig.is_empty(), "T-087-06: signature bytes present");
        assert!(
            keyid.starts_with("fulcio:"),
            "T-087-07: keyid derived from the Fulcio leaf cert, got {keyid}"
        );
        // expect(1) on both mocks asserts exactly one Fulcio + one Rekor call.
    }

    // T-087-07: keyless signature is a valid ECDSA P-256 DER signature; keyid
    // from the Fulcio cert. (Signature validity is structural here since the
    // ephemeral key is internal; we assert it parses as P-256 DER.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t_087_07_keyless_signature_is_p256_der() {
        use p256::ecdsa::Signature as P256Signature;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v2/signingCert"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signedCertificateEmbeddedSct": {
                    "chain": { "certificates": ["leafcert-bytes"] }
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
            .mount(&server)
            .await;

        let signer = KeylessSigner::new(&server.uri(), &server.uri(), "tok");
        let pae = dsse_pae(OSV_TYPE, b"payload");
        let (sig, _keyid) = tokio::task::spawn_blocking(move || signer.sign(&pae))
            .await
            .expect("join")
            .expect("sign");
        assert!(
            P256Signature::from_der(&sig).is_ok(),
            "T-087-07: keyless sig must be a valid ECDSA P-256 DER signature"
        );
    }

    // T-087-08: Fulcio unreachable → Err with a network/Fulcio message.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t_087_08_fulcio_unreachable_errs() {
        // Non-listening address.
        let signer = KeylessSigner::new("http://127.0.0.1:1", "http://127.0.0.1:1", "tok");
        let pae = dsse_pae(OSV_TYPE, b"payload");
        let result = tokio::task::spawn_blocking(move || signer.sign(&pae))
            .await
            .expect("join");
        let err = result.expect_err("T-087-08: unreachable Fulcio must return Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("Fulcio"),
            "T-087-08: error must indicate Fulcio/network failure, got: {msg}"
        );
    }

    // T-087-09: keyless failure produces no output (sign_interchange returns Err).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t_087_09_keyless_failure_no_partial_output() {
        let signer = KeylessSigner::new("http://127.0.0.1:1", "http://127.0.0.1:1", "tok");
        let result = tokio::task::spawn_blocking(move || {
            sign_interchange(b"{\"results\":[]}", OSV_TYPE, &signer)
        })
        .await
        .expect("join");
        assert!(
            result.is_err(),
            "T-087-09: a keyless signing failure must propagate as Err (no envelope produced)"
        );
    }

    // T-087-10: resolve_signer takes the offline path on probe failure and
    // returns an OperatorKeySigner when key_path is set; no keyless factory call.
    #[test]
    fn t_087_10_resolve_offline_on_probe_failure() {
        let (pem, _vk) = gen_ed25519_pem();
        let keyfile = write_key_tempfile(&pem);
        let mut config = Config::default();
        config.signing.key_path = keyfile.path().to_string_lossy().into_owned();

        let keyless_called = std::cell::Cell::new(false);
        let decision = resolve_signer(
            &config,
            || anyhow::bail!("simulated offline"),
            || {
                keyless_called.set(true);
                Box::new(FailingSigner)
            },
        )
        .expect("resolve");

        match decision {
            SignerDecision::Signer(s) => {
                // Must be the operator key — it signs locally with no network.
                let (sig, _) = s.sign(b"x").expect("operator sign");
                assert_eq!(
                    sig.len(),
                    64,
                    "T-087-10: offline path uses OperatorKeySigner"
                );
            }
            SignerDecision::NoOfflineKey => panic!("T-087-10: expected a signer, got NoOfflineKey"),
        }
        assert!(
            !keyless_called.get(),
            "T-087-10: keyless factory must NOT be called on the offline path"
        );
    }

    // T-087-11: resolve_signer returns the keyless signer when the probe succeeds.
    #[test]
    fn t_087_11_resolve_keyless_when_online() {
        let config = Config::default(); // offline = false
        let keyless_called = std::cell::Cell::new(false);
        let decision = resolve_signer(
            &config,
            || Ok(()),
            || {
                keyless_called.set(true);
                // A stub signer standing in for KeylessSigner.
                Box::new(StaticEd25519Signer::generate())
            },
        )
        .expect("resolve");
        assert!(
            matches!(decision, SignerDecision::Signer(_)),
            "T-087-11: online probe must yield a signer"
        );
        assert!(
            keyless_called.get(),
            "T-087-11: the keyless factory must be used when online"
        );
    }

    // T-087-12: the DEP_SCAN_OFFLINE=1 env var forces the offline path,
    // end-to-end through the real production load path: env var → Config::load
    // (which applies env overrides) → resolve_signer. Setting the real env var
    // and loading through Config::load is what production does; nothing here
    // hand-sets config.signing.offline. With the network probe reporting ONLINE,
    // the only thing that can force the offline OperatorKeySigner is the env var
    // having flipped signing.offline. If that chain ever broke, this test would
    // fall through to the keyless factory and fail.
    //
    // DEP_SCAN_OFFLINE is process-global; this test shares config.rs's ENV_LOCK
    // so it serializes against the other DEP_SCAN_OFFLINE-mutating tests, and a
    // drop guard removes the var afterward so no sibling test sees it.
    #[test]
    fn t_087_12_env_var_forces_offline_path_end_to_end() {
        // RAII guard: restore DEP_SCAN_OFFLINE to its prior state on drop, even
        // on panic, so no other test is affected.
        struct EnvGuard {
            prev: Option<String>,
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                unsafe {
                    match &self.prev {
                        Some(v) => std::env::set_var("DEP_SCAN_OFFLINE", v),
                        None => std::env::remove_var("DEP_SCAN_OFFLINE"),
                    }
                }
            }
        }

        let _lock = crate::config::ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard {
            prev: std::env::var("DEP_SCAN_OFFLINE").ok(),
        };

        let (pem, _vk) = gen_ed25519_pem();
        let keyfile = write_key_tempfile(&pem);

        // A config file that explicitly says offline = false, so the ONLY thing
        // that can flip it is the env override applied by Config::load.
        let mut cfg_file = tempfile::NamedTempFile::new().expect("cfg tempfile");
        {
            use std::io::Write as _;
            writeln!(
                cfg_file,
                "[signing]\noffline = false\nkey_path = {:?}",
                keyfile.path().to_string_lossy()
            )
            .expect("write config");
            cfg_file.flush().expect("flush config");
        }

        // Set the real env var, then load through the real production path.
        unsafe {
            std::env::set_var("DEP_SCAN_OFFLINE", "1");
        }
        let config = Config::load(Some(cfg_file.path())).expect("load config");
        assert!(
            config.signing.offline,
            "T-087-12: DEP_SCAN_OFFLINE=1 must flip config.signing.offline via Config::load"
        );

        let keyless_called = std::cell::Cell::new(false);
        let decision = resolve_signer(
            &config,
            || Ok(()), // probe says ONLINE — only the env-forced offline flag can win
            || {
                keyless_called.set(true);
                Box::new(FailingSigner)
            },
        )
        .expect("resolve");

        match decision {
            SignerDecision::Signer(s) => {
                // The offline OperatorKeySigner signs locally (64-byte Ed25519).
                let (sig, _) = s.sign(b"x").expect("operator sign");
                assert_eq!(
                    sig.len(),
                    64,
                    "T-087-12: env-forced offline path must yield the OperatorKeySigner"
                );
            }
            SignerDecision::NoOfflineKey => {
                panic!("T-087-12: expected an OperatorKeySigner, got NoOfflineKey")
            }
        }
        assert!(
            !keyless_called.get(),
            "T-087-12: env-forced offline path must NOT call the keyless factory"
        );
    }

    // T-087-15 (unit): offline + no key_path → NoOfflineKey (fail-closed signal).
    #[test]
    fn t_087_15_offline_no_key_is_no_offline_key() {
        let mut config = Config::default();
        config.signing.offline = true;
        config.signing.key_path = String::new(); // unset

        let decision =
            resolve_signer(&config, || Ok(()), || Box::new(FailingSigner)).expect("resolve");
        assert!(
            matches!(decision, SignerDecision::NoOfflineKey),
            "T-087-15: offline with no key_path must signal NoOfflineKey (not a silent signer)"
        );
        // The message names the remediation paths.
        assert!(
            SignerDecision::NO_OFFLINE_KEY_MESSAGE.contains("signing.key_path"),
            "message must name signing.key_path"
        );
        assert!(
            SignerDecision::NO_OFFLINE_KEY_MESSAGE.contains("--allow-unsigned"),
            "message must name --allow-unsigned"
        );
    }

    // T-087-16: external key_path is loaded (PEM PKCS#8) and produces a
    // verifiable signature.
    #[test]
    fn t_087_16_external_key_path_loaded_and_verifies() {
        use ed25519_dalek::Verifier as _;
        let (pem, vk) = gen_ed25519_pem();
        let keyfile = write_key_tempfile(&pem);
        let mut config = Config::default();
        config.signing.key_path = keyfile.path().to_string_lossy().into_owned();
        config.signing.offline = true;

        let decision =
            resolve_signer(&config, || Ok(()), || Box::new(FailingSigner)).expect("resolve");
        let signer = match decision {
            SignerDecision::Signer(s) => s,
            SignerDecision::NoOfflineKey => panic!("expected operator signer"),
        };
        let pae = dsse_pae(OSV_TYPE, b"interchange payload");
        let (sig_bytes, _keyid) = signer.sign(&pae).expect("sign");
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().expect("64-byte sig");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify(&pae, &signature)
            .expect("T-087-16: signature from key_path must verify with the matching public key");
    }
}

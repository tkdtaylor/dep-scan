//! npm provenance attestation client.
//!
//! Fetches and parses sigstore attestation bundles from the npm registry
//! attestation endpoint (`/-/npm/v1/attestations/<name>@<version>`).
//!
//! The attestation response contains a list of bundles in sigstore v0.2+ format.
//! Each bundle contains a DSSE envelope with a SLSA predicate whose
//! `subject.digest` carries the sha512 hex of the npm tarball — this is what
//! we compare against `dist.integrity` (captured in task 029).
//!
//! # Fixture provenance
//!
//! Test fixtures are hand-crafted JSON matching the real npm attestation response
//! shape (verified against `semver@7.6.0` on 2026-05-21).  The SLSA payload
//! bytes in test fixtures are real base64-encoded JSON so predicate parsing
//! tests exercise the actual code path.

use reqwest::Client;

use super::RegistryError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single attestation bundle returned from the npm attestation endpoint.
///
/// An npm attestation response contains a list of these — typically one
/// "publish" attestation and one SLSA provenance attestation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AttestationBundle {
    /// The SLSA/in-toto predicate type URI
    /// (e.g. `https://slsa.dev/provenance/v1`).
    pub predicate_type: String,

    /// The DSSE envelope contained in the bundle.
    pub dsse_envelope: DsseEnvelope,

    /// The verification material (x509 cert chain or public key hint).
    pub verification_material: VerificationMaterial,
}

/// A DSSE (Dead Simple Signing Envelope) envelope.
///
/// <https://github.com/secure-systems-lab/dsse>
#[derive(Debug, Clone)]
pub struct DsseEnvelope {
    /// Base64-encoded payload (the SLSA/in-toto statement JSON).
    pub payload_b64: String,
    /// Payload MIME type (e.g. `application/vnd.in-toto+json`).
    pub payload_type: String,
    /// DSSE signatures over the PAE-encoded envelope.
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    /// Decode the base64 payload and return the raw JSON bytes.
    ///
    /// Returns `None` if the base64 is invalid.
    pub fn decoded_payload(&self) -> Option<Vec<u8>> {
        use base64::Engine as _;
        // npm uses standard base64; some toolchains emit URL-safe, try both.
        base64::engine::general_purpose::STANDARD
            .decode(&self.payload_b64)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&self.payload_b64))
            .ok()
    }
}

/// A single DSSE signature entry.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DsseSignature {
    /// Base64-encoded DER signature bytes.
    pub sig_b64: String,
    /// Key hint (e.g. `SHA256:<fingerprint>`), empty for keyless.
    pub keyid: String,
}

/// Verification material for a sigstore bundle — either an x509 cert chain
/// or a public key hint (used for keyless npm publish attestations).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum VerificationMaterial {
    /// One or more DER-encoded certificates (base64-encoded).
    /// The first certificate is the leaf (signing) certificate.
    X509CertChain(Vec<String>),
    /// A public key hint (e.g. `SHA256:...`); no cert chain available.
    PublicKeyHint(String),
}

// ---------------------------------------------------------------------------
// SLSA predicate types
// ---------------------------------------------------------------------------

/// An in-toto statement's `subject` entry.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SlsaSubject {
    /// Subject name (e.g. `pkg:npm/semver@7.6.0`).
    pub name: String,
    /// Digest map — algorithm → hex value.
    pub digest: std::collections::HashMap<String, String>,
}

/// Parsed SLSA/in-toto statement from a DSSE payload.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SlsaStatement {
    /// Subject artifacts referenced by this statement.
    pub subjects: Vec<SlsaSubject>,
    /// Predicate type URI.
    pub predicate_type: String,
}

impl SlsaStatement {
    /// Extract the first subject's digest for a given algorithm.
    ///
    /// `algo` should be `"sha512"`, `"sha256"`, etc.
    /// Returns `None` if no subject with that algorithm digest was found.
    pub fn subject_digest(&self, algo: &str) -> Option<&str> {
        self.subjects
            .first()
            .and_then(|s| s.digest.get(algo))
            .map(String::as_str)
    }
}

/// Parse the DSSE payload bytes as an in-toto/SLSA statement.
///
/// Returns `Err` with a description if parsing fails.
pub fn parse_slsa_statement(payload: &[u8]) -> Result<SlsaStatement, String> {
    let raw: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| format!("invalid JSON in SLSA payload: {e}"))?;

    let predicate_type = raw["predicateType"]
        .as_str()
        .or_else(|| raw["predicateType"].as_str())
        .unwrap_or("")
        .to_string();

    let subjects_raw = raw["subject"].as_array().ok_or("missing 'subject' array")?;

    let mut subjects = Vec::new();
    for subj_val in subjects_raw {
        let name = subj_val["name"].as_str().unwrap_or("").to_string();
        let digest_obj = subj_val["digest"]
            .as_object()
            .ok_or("missing 'digest' object in subject")?;
        let mut digest = std::collections::HashMap::new();
        for (k, v) in digest_obj {
            if let Some(hex) = v.as_str() {
                digest.insert(k.clone(), hex.to_string());
            }
        }
        subjects.push(SlsaSubject { name, digest });
    }

    Ok(SlsaStatement {
        subjects,
        predicate_type,
    })
}

// ---------------------------------------------------------------------------
// npm attestation HTTP client
// ---------------------------------------------------------------------------

/// Client for the npm attestation API endpoint.
pub struct NpmAttestationClient {
    /// Base URL of the npm registry (e.g. `https://registry.npmjs.org`).
    pub base_url: String,
    client: Client,
}

impl NpmAttestationClient {
    /// Create a new client.
    pub fn new(base_url: String) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            base_url,
            client: Client::new(),
        }
    }

    /// Fetch attestation bundles for `<name>@<version>`.
    ///
    /// - Returns `Ok(vec![])` when the endpoint returns 404 (no attestations published).
    /// - Returns `Err(_)` for 5xx, non-JSON body, or network failure.
    pub async fn get_attestations(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Vec<AttestationBundle>, RegistryError> {
        let url = format!(
            "{}/-/npm/v1/attestations/{}@{}",
            self.base_url, name, version
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        match response.status().as_u16() {
            404 => return Ok(vec![]),
            200 => {}
            status => {
                return Err(RegistryError::NetworkError(format!(
                    "attestations endpoint returned unexpected status: {status}"
                )));
            }
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        // Defensive parse: if the body doesn't look like JSON (e.g. HTML error page),
        // the JSON parser in `parse_attestation_response` will produce a ParseError.
        // T-032-04 requires this path for non-JSON bodies.
        parse_attestation_response(&body)
    }
}

/// Parse the raw attestation endpoint JSON body into a list of `AttestationBundle`s.
///
/// Returns `Err` for invalid JSON or unexpected shape.
pub fn parse_attestation_response(body: &[u8]) -> Result<Vec<AttestationBundle>, RegistryError> {
    let raw: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        RegistryError::ParseError(format!("invalid JSON in attestation response: {e}"))
    })?;

    // Check for explicit error field (e.g. `{"error": "Not found"}`).
    if let Some(err_msg) = raw.get("error").and_then(|v| v.as_str()) {
        // npm returns `{"error": "Not found"}` as 200 in some edge cases.
        if err_msg.contains("Not found") || err_msg.contains("not found") {
            return Ok(vec![]);
        }
        return Err(RegistryError::ParseError(format!(
            "attestation endpoint error: {err_msg}"
        )));
    }

    let attestations = raw["attestations"]
        .as_array()
        .ok_or_else(|| RegistryError::ParseError("missing 'attestations' array".to_string()))?;

    let mut bundles = Vec::with_capacity(attestations.len());

    for att in attestations {
        let predicate_type = att["predicateType"].as_str().unwrap_or("").to_string();

        let bundle_val = &att["bundle"];

        // Parse DSSE envelope.
        let dsse = &bundle_val["dsseEnvelope"];
        if dsse.is_null() {
            // Skip attestations without a DSSE envelope (e.g. simple message sigs).
            continue;
        }

        let payload_b64 = dsse["payload"].as_str().unwrap_or("").to_string();
        let payload_type = dsse["payloadType"].as_str().unwrap_or("").to_string();

        let sigs_raw = dsse["signatures"].as_array();
        let signatures = sigs_raw
            .map(|arr| {
                arr.iter()
                    .map(|s| DsseSignature {
                        sig_b64: s["sig"].as_str().unwrap_or("").to_string(),
                        keyid: s["keyid"].as_str().unwrap_or("").to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let dsse_envelope = DsseEnvelope {
            payload_b64,
            payload_type,
            signatures,
        };

        // Parse verification material.
        let vm = &bundle_val["verificationMaterial"];

        let verification_material =
            if let Some(chain) = vm["x509CertificateChain"]["certificates"].as_array() {
                let certs = chain
                    .iter()
                    .filter_map(|c| c["rawBytes"].as_str())
                    .map(|s| s.to_string())
                    .collect();
                VerificationMaterial::X509CertChain(certs)
            } else if let Some(hint) = vm["publicKey"]["hint"].as_str() {
                VerificationMaterial::PublicKeyHint(hint.to_string())
            } else {
                // No usable verification material — still include the bundle but
                // the verifier will fail when trying to check the signature.
                VerificationMaterial::PublicKeyHint(String::new())
            };

        bundles.push(AttestationBundle {
            predicate_type,
            dsse_envelope,
            verification_material,
        });
    }

    Ok(bundles)
}

// ---------------------------------------------------------------------------
// DSSE PAE encoding
// ---------------------------------------------------------------------------

/// Build the DSSE "Pre-Authentication Encoding" for signature verification.
///
/// Per the DSSE spec: `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`
/// where `<len(x)>` is the ASCII decimal length of `x`.
///
/// <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Minimal valid attestation JSON with one SLSA bundle (DSSE envelope + x509 chain).
    fn single_bundle_json() -> &'static str {
        r#"{
            "attestations": [
                {
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "bundle": {
                        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
                        "verificationMaterial": {
                            "x509CertificateChain": {
                                "certificates": [
                                    { "rawBytes": "MIIB..." }
                                ]
                            },
                            "tlogEntries": [],
                            "timestampVerificationData": { "rfc3161Timestamps": [] }
                        },
                        "dsseEnvelope": {
                            "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoicGtnOm5wbS9sb2Rhc2hANC4xNy4yMSIsImRpZ2VzdCI6eyJzaGE1MTIiOiJhYWFhYmJiYmNjY2NkZGRkIn19XSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vc2xzYS5kZXYvcHJvdmVuYW5jZS92MSIsInByZWRpY2F0ZSI6e319",
                            "payloadType": "application/vnd.in-toto+json",
                            "signatures": [
                                { "sig": "MEYCIQCY+TSB151YxK0=", "keyid": "" }
                            ]
                        }
                    }
                }
            ]
        }"#
    }

    // T-032-01: get_attestations parses a single-bundle response
    #[tokio::test]
    async fn get_attestations_parses_single_bundle() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/lodash@4.17.21"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string(single_bundle_json()),
            )
            .mount(&server)
            .await;

        let client = NpmAttestationClient::new(server.uri());
        let bundles = client.get_attestations("lodash", "4.17.21").await.unwrap();

        assert_eq!(bundles.len(), 1, "T-032-01: expected 1 bundle");
        assert_eq!(
            bundles[0].predicate_type, "https://slsa.dev/provenance/v1",
            "T-032-01: predicate type mismatch"
        );
    }

    // T-032-02: get_attestations on 404 returns empty vec
    #[tokio::test]
    async fn get_attestations_404_returns_empty_vec() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/obscure-pkg@1.0.0"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = NpmAttestationClient::new(server.uri());
        let result = client.get_attestations("obscure-pkg", "1.0.0").await;

        // T-032-02: 404 must return Ok(vec![]), NOT an error
        assert!(
            result.is_ok(),
            "T-032-02: expected Ok, got Err: {:?}",
            result.err()
        );
        assert!(
            result.unwrap().is_empty(),
            "T-032-02: expected empty vec for 404"
        );
    }

    // T-032-03: get_attestations on 500 returns error
    #[tokio::test]
    async fn get_attestations_500_returns_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/pkg@1.0.0"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&server)
            .await;

        let client = NpmAttestationClient::new(server.uri());
        let result = client.get_attestations("pkg", "1.0.0").await;

        assert!(result.is_err(), "T-032-03: expected Err for 500 response");
    }

    // T-032-04: get_attestations rejects non-JSON body
    #[tokio::test]
    async fn get_attestations_rejects_non_json_body() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/pkg@1.0.0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html>Not found</html>"),
            )
            .mount(&server)
            .await;

        let client = NpmAttestationClient::new(server.uri());
        let result = client.get_attestations("pkg", "1.0.0").await;

        assert!(
            result.is_err(),
            "T-032-04: expected Err for non-JSON response"
        );
    }

    #[test]
    fn dsse_pae_format_is_correct() {
        // From the DSSE spec: DSSEv1 SP len(payloadType) SP payloadType SP len(payload) SP payload
        // "application/vnd.in-toto+json" has 28 bytes.
        let pae = dsse_pae("application/vnd.in-toto+json", b"hello");
        let expected = b"DSSEv1 28 application/vnd.in-toto+json 5 hello";
        assert_eq!(pae, expected);
    }

    #[test]
    fn parse_slsa_statement_extracts_sha512_digest() {
        // Decoded from the single_bundle_json payload above:
        // {"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"pkg:npm/lodash@4.17.21","digest":{"sha512":"aaaabbbbccccdddd"}}],...}
        let payload = r#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"pkg:npm/lodash@4.17.21","digest":{"sha512":"aaaabbbbccccdddd"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}"#;
        let stmt = parse_slsa_statement(payload.as_bytes()).unwrap();
        assert_eq!(stmt.subject_digest("sha512"), Some("aaaabbbbccccdddd"));
    }
}

//! PyPI provenance attestation client (PEP 740 / PEP 691).
//!
//! Fetches and parses sigstore attestation bundles from PyPI's Simple Index
//! (PEP 691) endpoint.  The Simple Index response (JSON v1) includes an
//! optional `provenance` URL per file; fetching that URL returns a JSON
//! envelope containing one or more sigstore bundles.
//!
//! # PEP 740 bundle format
//!
//! ```json
//! {
//!   "attestations": [
//!     {
//!       "bundle": { /* sigstore v0.2+ bundle */ }
//!     }
//!   ]
//! }
//! ```
//!
//! This format is structurally equivalent to the npm attestation response
//! (after unwrapping the outer `attestations` array), so we reuse
//! `AttestationBundle`, `DsseEnvelope`, `VerificationMaterial`, etc. from
//! `npm_attestation`.
//!
//! # File selection rule
//!
//! Mirrors task 029 exactly: sdist preferred (`packagetype = "sdist"`),
//! else first wheel (`packagetype = "bdist_wheel"`).

use reqwest::Client;

use super::RegistryError;
use crate::registry::npm_attestation::AttestationBundle;

// ---------------------------------------------------------------------------
// Simple Index types (PEP 691 / JSON v1)
// ---------------------------------------------------------------------------

/// A single file entry within the PEP 691 Simple Index JSON response.
#[derive(Debug, Clone)]
#[allow(dead_code)] // filename and sha256 are read in tests; provenance_url and packagetype are used in main.rs
pub struct SimpleIndexFile {
    /// Filename as reported by PyPI (e.g. `requests-2.31.0.tar.gz`).
    pub filename: String,
    /// Package type: `"sdist"` or `"bdist_wheel"`.
    pub packagetype: Option<String>,
    /// URL to fetch the provenance attestation bundle, if published.
    pub provenance_url: Option<String>,
    /// SHA-256 digest of the file (hex), if available.
    pub sha256: Option<String>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client for the PEP 691 Simple Index endpoint and PEP 740 provenance URLs.
pub struct PyPiProvenanceClient {
    /// Base URL of the PyPI registry (e.g. `https://pypi.org`).
    pub base_url: String,
    client: Client,
}

impl PyPiProvenanceClient {
    /// Create a new client.
    pub fn new(base_url: String) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            base_url,
            client: Client::new(),
        }
    }

    /// Fetch the PEP 691 Simple Index for `name` and return the file list.
    ///
    /// Uses `Accept: application/vnd.pypi.simple.v1+json` to request the JSON v1
    /// response that includes the optional `provenance` URL per file.
    ///
    /// Returns `Ok(None)` when the server responds with a non-JSON body
    /// (e.g. an older mirror that only serves HTML — this is the "legacy mirror"
    /// case described in the task risk notes).
    pub async fn fetch_simple_index(
        &self,
        name: &str,
    ) -> Result<Option<Vec<SimpleIndexFile>>, RegistryError> {
        let url = format!("{}/simple/{}/", self.base_url, name);

        let response = self
            .client
            .get(&url)
            .header(
                "Accept",
                "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.1, text/html;q=0.01",
            )
            .send()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        match response.status().as_u16() {
            404 => return Ok(Some(vec![])),
            s if !(200..300).contains(&s) => {
                return Err(RegistryError::NetworkError(format!(
                    "simple index returned unexpected status: {s}"
                )));
            }
            _ => {}
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let body = response
            .bytes()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        // If the server returned HTML (not JSON v1), treat as "legacy mirror" —
        // return Ok(None) so the caller can degrade to a Warn.
        if !content_type.contains("application/vnd.pypi.simple.v1+json") {
            // Try parsing as JSON anyway (some mirrors send JSON without the strict content-type).
            if serde_json::from_slice::<serde_json::Value>(&body).is_err() {
                return Ok(None); // HTML or non-JSON → legacy mirror
            }
        }

        parse_simple_index(&body).map(Some)
    }

    /// Fetch the provenance attestation for a specific file.
    ///
    /// - `name`: package name (for the Simple Index lookup).
    /// - `version`: version string (used to select the right file from the index).
    /// - `filename`: exact filename to look up (from the Simple Index file list).
    ///
    /// Returns:
    /// - `Ok(Some(bundle))` when the attestation is present and parseable.
    /// - `Ok(None)` when no `provenance` URL is found for the file, or the URL returns 404.
    /// - `Err(_)` for server errors (5xx) or non-JSON bodies on the provenance URL (fail-closed).
    #[allow(dead_code)] // used in unit tests; main.rs uses fetch_simple_index + select_file directly
    pub async fn get_provenance(
        &self,
        name: &str,
        _version: &str,
        filename: &str,
    ) -> Result<Option<AttestationBundle>, RegistryError> {
        // Step 1: Fetch the Simple Index to find the provenance URL for `filename`.
        let files = match self.fetch_simple_index(name).await? {
            Some(f) => f,
            None => return Ok(None), // legacy mirror, degrade gracefully
        };

        let file_entry = files.iter().find(|f| f.filename == filename);

        let provenance_url = match file_entry.and_then(|f| f.provenance_url.as_deref()) {
            Some(url) => url.to_string(),
            None => return Ok(None), // no provenance URL for this file
        };

        // Step 2: Fetch the provenance URL.
        self.fetch_provenance_url(&provenance_url).await
    }

    /// Select the appropriate file from a Simple Index file list using the same
    /// rule as task 029 (sdist preferred, else first wheel) and return its filename.
    pub fn select_file(files: &[SimpleIndexFile]) -> Option<&SimpleIndexFile> {
        // Prefer sdist
        if let Some(sdist) = files
            .iter()
            .find(|f| f.packagetype.as_deref() == Some("sdist"))
        {
            return Some(sdist);
        }
        // Fall back to first wheel
        files
            .iter()
            .find(|f| f.packagetype.as_deref() == Some("bdist_wheel"))
    }

    /// Fetch and parse a provenance URL directly.
    ///
    /// - Returns `Ok(None)` for 404.
    /// - Returns `Err(_)` for 5xx or non-JSON body.
    pub async fn fetch_provenance_url(
        &self,
        url: &str,
    ) -> Result<Option<AttestationBundle>, RegistryError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        match response.status().as_u16() {
            404 => return Ok(None),
            200 => {}
            status => {
                return Err(RegistryError::NetworkError(format!(
                    "provenance URL returned unexpected status: {status}"
                )));
            }
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        let bundle = parse_provenance_response(&body)?;
        Ok(bundle)
    }
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// Parse the PEP 691 Simple Index JSON body into a list of `SimpleIndexFile`s.
pub fn parse_simple_index(body: &[u8]) -> Result<Vec<SimpleIndexFile>, RegistryError> {
    let raw: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        RegistryError::ParseError(format!("invalid JSON in simple index response: {e}"))
    })?;

    let files_arr = raw["files"].as_array().ok_or_else(|| {
        RegistryError::ParseError("missing 'files' array in simple index".to_string())
    })?;

    let mut files = Vec::with_capacity(files_arr.len());

    for file_val in files_arr {
        let filename = file_val["filename"].as_str().unwrap_or("").to_string();

        // Determine package type from the filename extension.
        let packagetype = if filename.ends_with(".tar.gz")
            || filename.ends_with(".zip")
            || filename.ends_with(".tar.bz2")
        {
            Some("sdist".to_string())
        } else if filename.ends_with(".whl") {
            Some("bdist_wheel".to_string())
        } else {
            file_val["yanked"].as_bool().map(|_| "unknown".to_string())
        };

        // PEP 740: `provenance` key holds a URL or null.
        let provenance_url = file_val["provenance"].as_str().map(|s| s.to_string());

        // PEP 691: digests are under `digests.sha256`.
        let sha256 = file_val["digests"]["sha256"]
            .as_str()
            .map(|s| s.to_string());

        files.push(SimpleIndexFile {
            filename,
            packagetype,
            provenance_url,
            sha256,
        });
    }

    Ok(files)
}

/// Parse the PEP 740 provenance endpoint JSON body into an `AttestationBundle`.
///
/// Accepts two shapes:
///
/// 1. **Synthetic / test shape**:
///    ```json
///    { "attestations": [{ "bundle": { "dsseEnvelope": ..., "verificationMaterial": ... } }] }
///    ```
/// 2. **Real PEP 740 shape** (as served by pypi.org/integrity/...):
///    ```json
///    {
///      "attestation_bundles": [{
///        "attestations": [{
///          "envelope": { "statement": "<b64>", "signature": "<b64>" },
///          "verification_material": {
///            "certificate": "<b64-DER>",
///            "transparency_entries": [...]
///          }
///        }]
///      }]
///    }
///    ```
///
/// Returns `Ok(Some(bundle))` for the first usable bundle found.
/// Returns `Ok(None)` when no attestations are present.
/// Returns `Err(ParseError)` for invalid JSON.
pub fn parse_provenance_response(body: &[u8]) -> Result<Option<AttestationBundle>, RegistryError> {
    let raw: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        RegistryError::ParseError(format!("invalid JSON in provenance response: {e}"))
    })?;

    // Dispatch on top-level shape.
    if raw["attestation_bundles"].is_array() {
        parse_real_pep740(&raw)
    } else if raw["attestations"].is_array() {
        parse_synthetic_shape(&raw)
    } else {
        Err(RegistryError::ParseError(
            "missing 'attestations' or 'attestation_bundles' in provenance response".to_string(),
        ))
    }
}

fn parse_synthetic_shape(
    raw: &serde_json::Value,
) -> Result<Option<AttestationBundle>, RegistryError> {
    use crate::registry::npm_attestation::{
        DsseEnvelope, DsseSignature, VerificationMaterial, parse_tlog_entries,
    };

    let attestations = raw["attestations"]
        .as_array()
        .expect("checked in caller that 'attestations' is an array");

    for att_val in attestations {
        let bundle_val = &att_val["bundle"];
        if bundle_val.is_null() {
            continue;
        }

        let dsse = &bundle_val["dsseEnvelope"];
        if dsse.is_null() {
            continue;
        }

        let payload_b64 = dsse["payload"].as_str().unwrap_or("").to_string();
        let payload_type = dsse["payloadType"].as_str().unwrap_or("").to_string();

        let signatures = dsse["signatures"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|s| DsseSignature {
                        sig_b64: s["sig"].as_str().unwrap_or("").to_string(),
                        keyid: s["keyid"].as_str().unwrap_or("").to_string(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let dsse_envelope = DsseEnvelope {
            payload_b64,
            payload_type,
            signatures,
        };

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
                VerificationMaterial::PublicKeyHint(String::new())
            };

        let tlog_entries = parse_tlog_entries(&vm["tlogEntries"]);

        let predicate_type = att_val["predicateType"]
            .as_str()
            .unwrap_or("https://docs.pypi.org/attestations/publish/v1")
            .to_string();

        return Ok(Some(AttestationBundle {
            predicate_type,
            dsse_envelope,
            verification_material,
            tlog_entries,
        }));
    }

    Ok(None)
}

fn parse_real_pep740(raw: &serde_json::Value) -> Result<Option<AttestationBundle>, RegistryError> {
    use crate::registry::npm_attestation::{
        DsseEnvelope, DsseSignature, VerificationMaterial, parse_tlog_entries,
    };

    let bundles = raw["attestation_bundles"]
        .as_array()
        .expect("checked in caller that 'attestation_bundles' is an array");

    for bundle_obj in bundles {
        let attestations = match bundle_obj["attestations"].as_array() {
            Some(a) => a,
            None => continue,
        };

        for att in attestations {
            let env = &att["envelope"];
            if env.is_null() {
                continue;
            }

            let payload_b64 = env["statement"].as_str().unwrap_or("").to_string();
            // PEP 740's envelope is implicitly DSSE-shaped with payloadType
            // application/vnd.in-toto+json (the in-toto Statement v1).
            let payload_type = "application/vnd.in-toto+json".to_string();
            let sig_b64 = env["signature"].as_str().unwrap_or("").to_string();

            let dsse_envelope = DsseEnvelope {
                payload_b64,
                payload_type,
                signatures: vec![DsseSignature {
                    sig_b64,
                    keyid: String::new(),
                }],
            };

            let vm = &att["verification_material"];
            // PEP 740 carries a single cert (the leaf) under
            // verification_material.certificate. Wrap it as a single-element
            // X509CertChain for compatibility with the existing verifier.
            let verification_material = if let Some(cert) = vm["certificate"].as_str() {
                VerificationMaterial::X509CertChain(vec![cert.to_string()])
            } else {
                VerificationMaterial::PublicKeyHint(String::new())
            };

            let tlog_entries = parse_tlog_entries(&vm["transparency_entries"]);

            return Ok(Some(AttestationBundle {
                predicate_type: "https://docs.pypi.org/attestations/publish/v1".to_string(),
                dsse_envelope,
                verification_material,
                tlog_entries,
            }));
        }
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// PEP 691 Simple Index JSON fixture for "requests" 2.31.0.
    fn simple_index_with_provenance(provenance_url: &str) -> String {
        format!(
            r#"{{
                "meta": {{"api-version": "1.0"}},
                "name": "requests",
                "files": [
                    {{
                        "filename": "requests-2.31.0.tar.gz",
                        "url": "https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz",
                        "digests": {{"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}},
                        "provenance": "{provenance_url}"
                    }},
                    {{
                        "filename": "requests-2.31.0-py3-none-any.whl",
                        "url": "https://files.pythonhosted.org/packages/requests-2.31.0-py3-none-any.whl",
                        "digests": {{"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}}
                    }}
                ]
            }}"#
        )
    }

    fn simple_index_without_provenance() -> &'static str {
        r#"{
            "meta": {"api-version": "1.0"},
            "name": "requests",
            "files": [
                {
                    "filename": "requests-2.31.0.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz",
                    "digests": {"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}
                }
            ]
        }"#
    }

    fn minimal_provenance_bundle_json(sha256_hex: &str) -> String {
        use base64::Engine as _;
        let payload = format!(
            r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[{{"name":"requests-2.31.0.tar.gz","digest":{{"sha256":"{sha256_hex}"}}}}],"predicateType":"https://docs.pypi.org/attestations/publish/v1","predicate":{{}}}}"#
        );
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        format!(
            r#"{{
                "attestations": [
                    {{
                        "predicateType": "https://docs.pypi.org/attestations/publish/v1",
                        "bundle": {{
                            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
                            "verificationMaterial": {{
                                "x509CertificateChain": {{
                                    "certificates": [{{"rawBytes": "MIIB..."}}]
                                }},
                                "tlogEntries": [],
                                "timestampVerificationData": {{"rfc3161Timestamps": []}}
                            }},
                            "dsseEnvelope": {{
                                "payload": "{payload_b64}",
                                "payloadType": "application/vnd.in-toto+json",
                                "signatures": [{{"sig": "MEYCIQCY+TSB151Y=", "keyid": ""}}]
                            }}
                        }}
                    }}
                ]
            }}"#
        )
    }

    // T-033-01: Simple Index request uses JSON v1 Accept header
    #[tokio::test]
    async fn simple_index_uses_json_v1_accept_header() {
        use wiremock::Request;

        // Use a custom matcher to inspect the Accept header value.
        struct AcceptsJsonV1;
        impl wiremock::Match for AcceptsJsonV1 {
            fn matches(&self, request: &Request) -> bool {
                request
                    .headers
                    .get("accept")
                    .and_then(|val| val.to_str().ok())
                    .map(|s| s.contains("application/vnd.pypi.simple.v1+json"))
                    .unwrap_or(false)
            }
        }

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/simple/requests/"))
            .and(AcceptsJsonV1)
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.pypi.simple.v1+json")
                    .set_body_string(simple_index_without_provenance()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = PyPiProvenanceClient::new(server.uri());
        let result = client.fetch_simple_index("requests").await;
        assert!(
            result.is_ok(),
            "T-033-01: expected Ok, got: {:?}",
            result.err()
        );
        // wiremock verifies the Accept header was sent on drop (expect(1) check)
    }

    // T-033-02: get_provenance returns Some(bundle) when provenance field is present
    #[tokio::test]
    async fn get_provenance_returns_bundle_when_present() {
        let server = MockServer::start().await;
        let provenance_url = format!(
            "{}/provenance/requests/2.31.0/requests-2.31.0.tar.gz",
            server.uri()
        );

        Mock::given(method("GET"))
            .and(path("/simple/requests/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.pypi.simple.v1+json")
                    .set_body_string(simple_index_with_provenance(&provenance_url)),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/provenance/requests/2.31.0/requests-2.31.0.tar.gz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string(minimal_provenance_bundle_json(
                        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    )),
            )
            .mount(&server)
            .await;

        let client = PyPiProvenanceClient::new(server.uri());
        let result = client
            .get_provenance("requests", "2.31.0", "requests-2.31.0.tar.gz")
            .await;
        assert!(
            result.is_ok(),
            "T-033-02: expected Ok, got: {:?}",
            result.err()
        );
        assert!(
            result.unwrap().is_some(),
            "T-033-02: expected Some(bundle) when provenance is present"
        );
    }

    // T-033-03: get_provenance returns None when the file has no `provenance` field
    #[tokio::test]
    async fn get_provenance_returns_none_when_field_absent() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/simple/requests/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.pypi.simple.v1+json")
                    .set_body_string(simple_index_without_provenance()),
            )
            .mount(&server)
            .await;

        let client = PyPiProvenanceClient::new(server.uri());
        let result = client
            .get_provenance("requests", "2.31.0", "requests-2.31.0.tar.gz")
            .await;
        assert!(result.is_ok(), "T-033-03: expected Ok");
        assert!(
            result.unwrap().is_none(),
            "T-033-03: expected None when provenance field is absent"
        );
    }

    // T-033-04: get_provenance returns None when the provenance URL itself returns 404
    #[tokio::test]
    async fn get_provenance_404_returns_none() {
        let server = MockServer::start().await;
        let provenance_url = format!("{}/provenance/requests/gone", server.uri());

        Mock::given(method("GET"))
            .and(path("/simple/requests/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.pypi.simple.v1+json")
                    .set_body_string(simple_index_with_provenance(&provenance_url)),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/provenance/requests/gone"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = PyPiProvenanceClient::new(server.uri());
        let result = client
            .get_provenance("requests", "2.31.0", "requests-2.31.0.tar.gz")
            .await;
        assert!(
            result.is_ok(),
            "T-033-04: expected Ok for 404 provenance URL"
        );
        assert!(
            result.unwrap().is_none(),
            "T-033-04: expected None for 404 response"
        );
    }

    // T-033-05: get_provenance 500 returns Err (fail-closed)
    #[tokio::test]
    async fn get_provenance_500_returns_error() {
        let server = MockServer::start().await;
        let provenance_url = format!("{}/provenance/requests/error", server.uri());

        Mock::given(method("GET"))
            .and(path("/simple/requests/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.pypi.simple.v1+json")
                    .set_body_string(simple_index_with_provenance(&provenance_url)),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/provenance/requests/error"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&server)
            .await;

        let client = PyPiProvenanceClient::new(server.uri());
        let result = client
            .get_provenance("requests", "2.31.0", "requests-2.31.0.tar.gz")
            .await;
        assert!(result.is_err(), "T-033-05: expected Err for 500 response");
    }

    // T-033-06: get_provenance rejects non-JSON body (fail-closed)
    #[tokio::test]
    async fn get_provenance_rejects_non_json_body() {
        let server = MockServer::start().await;
        let provenance_url = format!("{}/provenance/requests/html", server.uri());

        Mock::given(method("GET"))
            .and(path("/simple/requests/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.pypi.simple.v1+json")
                    .set_body_string(simple_index_with_provenance(&provenance_url)),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/provenance/requests/html"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body>Not found</body></html>"),
            )
            .mount(&server)
            .await;

        let client = PyPiProvenanceClient::new(server.uri());
        let result = client
            .get_provenance("requests", "2.31.0", "requests-2.31.0.tar.gz")
            .await;
        assert!(
            result.is_err(),
            "T-033-06: expected Err for non-JSON body, got: {:?}",
            result.ok()
        );
    }

    // T-033-07: File selection — sdist preferred over wheels
    #[tokio::test]
    async fn file_selection_prefers_sdist_over_wheels() {
        let files = vec![
            SimpleIndexFile {
                filename: "pkg-1.0-py3-none-any.whl".to_string(),
                packagetype: Some("bdist_wheel".to_string()),
                provenance_url: Some("https://example.com/wheel-provenance".to_string()),
                sha256: None,
            },
            SimpleIndexFile {
                filename: "pkg-1.0.tar.gz".to_string(),
                packagetype: Some("sdist".to_string()),
                provenance_url: Some("https://example.com/sdist-provenance".to_string()),
                sha256: None,
            },
        ];

        let selected = PyPiProvenanceClient::select_file(&files);
        assert!(
            selected.is_some(),
            "T-033-07: expected a file to be selected"
        );
        assert_eq!(
            selected.unwrap().filename,
            "pkg-1.0.tar.gz",
            "T-033-07: sdist should be preferred over wheel"
        );
    }

    // T-033-08: File selection — first wheel when no sdist
    #[tokio::test]
    async fn file_selection_falls_back_to_first_wheel() {
        let files = vec![
            SimpleIndexFile {
                filename: "pkg-1.0-cp39-cp39-linux_x86_64.whl".to_string(),
                packagetype: Some("bdist_wheel".to_string()),
                provenance_url: Some("https://example.com/wheel1-provenance".to_string()),
                sha256: None,
            },
            SimpleIndexFile {
                filename: "pkg-1.0-cp310-cp310-linux_x86_64.whl".to_string(),
                packagetype: Some("bdist_wheel".to_string()),
                provenance_url: Some("https://example.com/wheel2-provenance".to_string()),
                sha256: None,
            },
        ];

        let selected = PyPiProvenanceClient::select_file(&files);
        assert!(
            selected.is_some(),
            "T-033-08: expected a file to be selected"
        );
        assert_eq!(
            selected.unwrap().filename,
            "pkg-1.0-cp39-cp39-linux_x86_64.whl",
            "T-033-08: first wheel should be selected when no sdist"
        );
    }

    // T-033-21 (unit): Legacy mirror returns HTML → Ok(None) (no crash)
    #[tokio::test]
    async fn legacy_mirror_html_response_returns_none() {
        let server = MockServer::start().await;

        // Server returns HTML (old-style Simple Index, no JSON v1 support)
        Mock::given(method("GET"))
            .and(path("/simple/requests/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(
                        r#"<!DOCTYPE html>
<html><body>
<a href="/packages/requests-2.31.0.tar.gz#sha256=abcd">requests-2.31.0.tar.gz</a>
</body></html>"#,
                    ),
            )
            .mount(&server)
            .await;

        let client = PyPiProvenanceClient::new(server.uri());
        let result = client.fetch_simple_index("requests").await;
        // Should return Ok(None) — legacy mirror, not an error
        assert!(result.is_ok(), "T-033-21: expected Ok for HTML response");
        assert!(
            result.unwrap().is_none(),
            "T-033-21: expected None for HTML (legacy mirror) response"
        );
    }
}

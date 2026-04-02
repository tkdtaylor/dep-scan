use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::types::VulnerabilityInfo;

/// Client for querying the OSV.dev vulnerability database.
///
/// OSV.dev is a free, open vulnerability database. This client sends
/// single-package queries to its `/v1/query` endpoint and maps results
/// to `VulnerabilityInfo` structs used by the policy engine.
pub struct OsvClient {
    /// Base URL of the OSV API (e.g. "https://api.osv.dev").
    base_url: String,
    /// Reusable HTTP client for connection pooling.
    client: reqwest::Client,
}

/// Request body for the OSV `/v1/query` endpoint.
#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
    version: String,
}

/// Package identifier within an OSV query.
#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

/// Top-level OSV response containing a list of vulnerabilities.
#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

/// A single vulnerability record from the OSV API.
#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

/// Severity entry in an OSV vulnerability record.
#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    _severity_type: Option<String>,
    score: Option<String>,
}

/// Affected package info in an OSV vulnerability record.
#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

/// Version range info for an affected package.
#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

/// A single version event (introduced or fixed).
#[derive(Debug, Deserialize)]
struct OsvEvent {
    #[serde(default)]
    fixed: Option<String>,
}

impl OsvClient {
    /// Create a new `OsvClient` with the given base URL.
    ///
    /// The base URL should not include a trailing slash (e.g. "https://api.osv.dev").
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    /// Query OSV for known vulnerabilities affecting a specific package version.
    ///
    /// # Arguments
    /// * `name` - Package name (e.g. "lodash")
    /// * `version` - Package version (e.g. "4.17.20")
    /// * `ecosystem` - OSV ecosystem string (e.g. "npm", "PyPI")
    ///
    /// # Returns
    /// A list of `VulnerabilityInfo` for known vulnerabilities, or an empty Vec if clean.
    pub async fn query(
        &self,
        name: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<Vec<VulnerabilityInfo>> {
        let url = format!("{}/v1/query", self.base_url);

        let request_body = OsvQueryRequest {
            package: OsvPackage {
                name: name.to_string(),
                ecosystem: ecosystem.to_string(),
            },
            version: version.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .with_context(|| {
                format!("Failed to query OSV for {name}@{version} (ecosystem: {ecosystem})")
            })?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!(
                "OSV API returned HTTP {status} for {name}@{version} (ecosystem: {ecosystem})"
            );
        }

        let osv_response: OsvResponse = response
            .json()
            .await
            .with_context(|| format!("Failed to parse OSV response for {name}@{version}"))?;

        let vulns = osv_response
            .vulns
            .into_iter()
            .map(|v| {
                // Extract the first severity score, if any
                let severity = v.severity.first().and_then(|s| s.score.clone());

                // Extract fixed versions from all affected ranges
                let fixed_versions: Vec<String> = v
                    .affected
                    .iter()
                    .flat_map(|a| &a.ranges)
                    .flat_map(|r| &r.events)
                    .filter_map(|e| e.fixed.clone())
                    .collect();

                VulnerabilityInfo {
                    id: v.id,
                    summary: v.summary,
                    severity,
                    aliases: v.aliases,
                    fixed_versions,
                }
            })
            .collect();

        Ok(vulns)
    }
}

/// Map a `RegistryType` to the OSV ecosystem string.
pub fn registry_to_ecosystem(reg: &crate::registry::RegistryType) -> &'static str {
    match reg {
        crate::registry::RegistryType::Npm => "npm",
        crate::registry::RegistryType::PyPI => "PyPI",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::RegistryType;
    use wiremock::matchers::{body_json_string, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper: build a full OSV vulnerability response JSON string.
    fn osv_response_with_vuln() -> String {
        serde_json::json!({
            "vulns": [{
                "id": "GHSA-35jh-r3h4-6jhm",
                "summary": "Prototype Pollution in lodash",
                "aliases": ["CVE-2021-23337"],
                "severity": [{
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
                }],
                "affected": [{
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [{
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "4.17.21"}
                        ]
                    }]
                }]
            }]
        })
        .to_string()
    }

    /// Helper: build an OSV response with no vulnerabilities.
    fn osv_response_empty() -> String {
        serde_json::json!({"vulns": []}).to_string()
    }

    // T-011-01: Query returns vulnerabilities
    #[tokio::test]
    async fn query_returns_vulnerabilities() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_string(osv_response_with_vuln()))
            .expect(1)
            .mount(&server)
            .await;

        let client = OsvClient::new(server.uri());
        let results = client.query("lodash", "4.17.20", "npm").await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "GHSA-35jh-r3h4-6jhm");
        assert_eq!(
            results[0].summary,
            Some("Prototype Pollution in lodash".to_string())
        );
        assert_eq!(
            results[0].severity,
            Some("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H".to_string())
        );
        assert_eq!(results[0].aliases, vec!["CVE-2021-23337".to_string()]);
        assert_eq!(results[0].fixed_versions, vec!["4.17.21".to_string()]);
    }

    // T-011-02: Query returns empty for clean package
    #[tokio::test]
    async fn query_returns_empty_for_clean_package() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_string(osv_response_empty()))
            .expect(1)
            .mount(&server)
            .await;

        let client = OsvClient::new(server.uri());
        let results = client.query("safe-pkg", "1.0.0", "npm").await.unwrap();

        assert!(results.is_empty());
    }

    // T-011-03: Query handles multiple packages (call query twice)
    #[tokio::test]
    async fn query_handles_multiple_packages() {
        let server = MockServer::start().await;

        // First call returns vulns, second returns empty
        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .and(body_json_string(
                serde_json::json!({
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "version": "4.17.20"
                })
                .to_string(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(osv_response_with_vuln()))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .and(body_json_string(
                serde_json::json!({
                    "package": {"name": "safe-pkg", "ecosystem": "npm"},
                    "version": "1.0.0"
                })
                .to_string(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(osv_response_empty()))
            .mount(&server)
            .await;

        let client = OsvClient::new(server.uri());

        let vuln_results = client.query("lodash", "4.17.20", "npm").await.unwrap();
        assert_eq!(vuln_results.len(), 1);

        let clean_results = client.query("safe-pkg", "1.0.0", "npm").await.unwrap();
        assert!(clean_results.is_empty());
    }

    // T-011-04: Network error handled gracefully
    #[tokio::test]
    async fn network_error_handled_gracefully() {
        // Point at an unreachable address
        let client = OsvClient::new("http://127.0.0.1:1".to_string());
        let result = client.query("any-pkg", "1.0.0", "npm").await;

        assert!(result.is_err(), "Should return an error, not panic");
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("Failed to query OSV"),
            "Error should mention OSV query failure, got: {err_msg}"
        );
    }

    // T-011-05: Custom endpoint URL is used
    #[tokio::test]
    async fn custom_endpoint_url_is_used() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_string(osv_response_empty()))
            .expect(1)
            .mount(&server)
            .await;

        // Use the wiremock server URI as the custom endpoint
        let client = OsvClient::new(server.uri());
        let _results = client.query("test-pkg", "1.0.0", "npm").await.unwrap();

        // If we get here without error, the request hit wiremock (not default OSV.dev).
        // The expect(1) on the mock also verifies exactly one request arrived.
    }

    // Test: OSV response with empty body (no "vulns" key) still works
    #[tokio::test]
    async fn empty_response_body_returns_empty_vec() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .expect(1)
            .mount(&server)
            .await;

        let client = OsvClient::new(server.uri());
        let results = client.query("clean-pkg", "2.0.0", "npm").await.unwrap();

        assert!(results.is_empty());
    }

    // Test: registry_to_ecosystem mapping
    #[test]
    fn registry_type_to_ecosystem_mapping() {
        assert_eq!(registry_to_ecosystem(&RegistryType::Npm), "npm");
        assert_eq!(registry_to_ecosystem(&RegistryType::PyPI), "PyPI");
    }
}

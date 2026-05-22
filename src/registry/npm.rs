use std::collections::HashMap;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;

use super::{Registry, RegistryError};
use crate::types::{InstallScript, PackageMetadata};

/// npm registry client.
///
/// Fetches package metadata from the npm registry API.
/// The base URL is configurable — it must NOT be hardcoded.
pub struct NpmRegistry {
    base_url: String,
    client: Client,
}

impl NpmRegistry {
    /// Create a new npm registry client with the given base URL.
    ///
    /// The `base_url` should be the root URL of the npm-compatible registry
    /// (e.g. `https://registry.npmjs.org`). No trailing slash.
    pub fn new(base_url: String) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            base_url,
            client: Client::new(),
        }
    }
}

/// The npm script hook names that are relevant for install-time analysis.
const INSTALL_SCRIPT_NAMES: &[&str] = &["preinstall", "install", "postinstall"];

impl NpmRegistry {
    /// Fetch install scripts for a package from the npm registry.
    ///
    /// Makes a request to the npm registry and extracts the `scripts` field
    /// from the resolved version's metadata. Only `preinstall`, `install`,
    /// and `postinstall` scripts are returned.
    pub async fn get_install_scripts(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<Vec<InstallScript>, RegistryError> {
        let url = format!("{}/{}", self.base_url, name);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        match response.status().as_u16() {
            404 => return Err(RegistryError::NotFound(name.to_string())),
            429 => return Err(RegistryError::RateLimited),
            200 => {}
            status => {
                return Err(RegistryError::NetworkError(format!(
                    "unexpected status code: {status}"
                )));
            }
        }

        let npm_response: NpmPackageResponse = response
            .json()
            .await
            .map_err(|e| RegistryError::ParseError(e.to_string()))?;

        let resolved_version = match version {
            Some(v) => v.to_string(),
            None => npm_response
                .dist_tags
                .get("latest")
                .cloned()
                .ok_or_else(|| RegistryError::ParseError("missing dist-tags.latest".to_string()))?,
        };

        let scripts = npm_response
            .versions
            .as_ref()
            .and_then(|v| v.get(&resolved_version))
            .and_then(|vi| vi.scripts.as_ref())
            .map(|scripts_map| {
                INSTALL_SCRIPT_NAMES
                    .iter()
                    .filter_map(|&hook| {
                        scripts_map.get(hook).map(|content| InstallScript {
                            name: hook.to_string(),
                            content: content.clone(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(scripts)
    }
}

/// Parse an npm SRI integrity string (e.g. `sha512-<base64>`) into
/// the normalized `<algo>:<hex>` format used by dep-scan.
///
/// Returns `None` if the format is unrecognized or the base64 is invalid.
fn parse_npm_integrity(integrity: &str) -> Option<String> {
    // SRI format: "<algo>-<base64>"
    let (algo, b64) = integrity.split_once('-')?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Some(format!("{algo}:{hex}"))
}

/// Extract the content hash from an npm `dist` block.
///
/// Prefers `integrity` (SRI format, decoded to hex) over `shasum` (raw SHA-1 hex).
fn extract_npm_content_hash(dist: Option<&NpmDist>) -> Option<String> {
    let dist = dist?;
    if let Some(ref integrity) = dist.integrity
        && let Some(hash) = parse_npm_integrity(integrity)
    {
        return Some(hash);
    }
    dist.shasum
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| format!("sha1:{s}"))
}

impl Registry for NpmRegistry {
    async fn get_metadata(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<PackageMetadata, RegistryError> {
        let url = format!("{}/{}", self.base_url, name);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        match response.status().as_u16() {
            404 => return Err(RegistryError::NotFound(name.to_string())),
            429 => return Err(RegistryError::RateLimited),
            200 => {}
            status => {
                return Err(RegistryError::NetworkError(format!(
                    "unexpected status code: {status}"
                )));
            }
        }

        let npm_response: NpmPackageResponse = response
            .json()
            .await
            .map_err(|e| RegistryError::ParseError(e.to_string()))?;

        // Determine the resolved version: either the explicitly requested one
        // or the latest from dist-tags.
        let resolved_version = match version {
            Some(v) => v.to_string(),
            None => npm_response
                .dist_tags
                .get("latest")
                .cloned()
                .ok_or_else(|| RegistryError::ParseError("missing dist-tags.latest".to_string()))?,
        };

        // Extract the publish time for the resolved version from the `time` map.
        let published_at = npm_response
            .time
            .as_ref()
            .and_then(|t| t.get(&resolved_version))
            .and_then(|ts| ts.parse::<DateTime<Utc>>().ok());

        // Extract maintainer names.
        let maintainers = npm_response
            .maintainers
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.name)
            .collect();

        // Extract the repository URL, stripping "git+" prefix if present.
        let repository_url = npm_response
            .versions
            .as_ref()
            .and_then(|v| v.get(&resolved_version))
            .and_then(|vi| vi.repository.as_ref())
            .map(|repo| {
                let url = &repo.url;
                if let Some(stripped) = url.strip_prefix("git+") {
                    stripped.to_string()
                } else {
                    url.clone()
                }
            });

        // Extract description — prefer version-specific, fall back to top-level.
        let description = npm_response
            .versions
            .as_ref()
            .and_then(|v| v.get(&resolved_version))
            .and_then(|vi| vi.description.clone())
            .or(npm_response.description);

        // Extract content hash from dist.integrity (preferred) or dist.shasum fallback.
        let content_hash = npm_response
            .versions
            .as_ref()
            .and_then(|v| v.get(&resolved_version))
            .and_then(|vi| extract_npm_content_hash(vi.dist.as_ref()));

        Ok(PackageMetadata {
            name: npm_response.name,
            version: resolved_version,
            description,
            published_at,
            maintainers,
            downloads: None, // npm registry API does not include download counts
            repository_url,
            content_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// Private serde structs for the npm registry JSON response
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct NpmPackageResponse {
    name: String,
    description: Option<String>,
    #[serde(rename = "dist-tags")]
    dist_tags: HashMap<String, String>,
    versions: Option<HashMap<String, NpmVersionInfo>>,
    time: Option<HashMap<String, String>>,
    maintainers: Option<Vec<NpmMaintainer>>,
}

#[derive(Debug, Deserialize)]
struct NpmVersionInfo {
    description: Option<String>,
    repository: Option<NpmRepository>,
    scripts: Option<HashMap<String, String>>,
    dist: Option<NpmDist>,
}

/// The `dist` block in an npm version entry — contains integrity and shasum.
#[derive(Debug, Deserialize)]
struct NpmDist {
    /// SRI-format integrity string, e.g. `sha512-<base64>`.
    integrity: Option<String>,
    /// SHA-1 hex digest fallback.
    shasum: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NpmRepository {
    url: String,
}

#[derive(Debug, Deserialize)]
struct NpmMaintainer {
    name: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Realistic npm JSON fixture for "lodash".
    fn lodash_json() -> String {
        r#"{
            "name": "lodash",
            "description": "Lodash modular utilities.",
            "dist-tags": { "latest": "4.17.21" },
            "versions": {
                "4.17.20": {
                    "name": "lodash",
                    "version": "4.17.20",
                    "description": "Lodash modular utilities.",
                    "repository": {
                        "type": "git",
                        "url": "git+https://github.com/lodash/lodash.git"
                    }
                },
                "4.17.21": {
                    "name": "lodash",
                    "version": "4.17.21",
                    "description": "Lodash modular utilities.",
                    "repository": {
                        "type": "git",
                        "url": "git+https://github.com/lodash/lodash.git"
                    }
                }
            },
            "time": {
                "created": "2012-04-23T17:17:23.150Z",
                "modified": "2025-01-01T00:00:00.000Z",
                "4.17.20": "2020-08-13T03:01:14.171Z",
                "4.17.21": "2021-02-20T15:42:16.891Z"
            },
            "maintainers": [
                { "name": "jdalton", "email": "john@example.com" }
            ]
        }"#
        .to_string()
    }

    /// Realistic npm JSON fixture for "express" (multiple maintainers).
    fn express_json() -> String {
        r#"{
            "name": "express",
            "description": "Fast, unopinionated, minimalist web framework",
            "dist-tags": { "latest": "4.18.2" },
            "versions": {
                "4.18.2": {
                    "name": "express",
                    "version": "4.18.2",
                    "description": "Fast, unopinionated, minimalist web framework",
                    "repository": {
                        "type": "git",
                        "url": "git+https://github.com/expressjs/express.git"
                    }
                }
            },
            "time": {
                "4.18.2": "2022-10-08T17:58:26.843Z"
            },
            "maintainers": [
                { "name": "dougwilson", "email": "doug@example.com" },
                { "name": "wesleytodd", "email": "wes@example.com" }
            ]
        }"#
        .to_string()
    }

    // T-005-01: Fetch metadata for existing package
    #[tokio::test]
    async fn fetch_metadata_for_existing_package() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/lodash"))
            .respond_with(ResponseTemplate::new(200).set_body_string(lodash_json()))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let meta = registry.get_metadata("lodash", None).await.unwrap();

        assert_eq!(meta.name, "lodash");
        assert_eq!(meta.version, "4.17.21");
        assert_eq!(
            meta.description,
            Some("Lodash modular utilities.".to_string())
        );
        assert_eq!(
            meta.published_at.unwrap().to_rfc3339(),
            "2021-02-20T15:42:16.891+00:00"
        );
        assert_eq!(meta.maintainers, vec!["jdalton"]);
        assert_eq!(
            meta.repository_url,
            Some("https://github.com/lodash/lodash.git".to_string())
        );
    }

    // T-005-02: Package not found returns NotFound
    #[tokio::test]
    async fn package_not_found_returns_not_found() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/nonexistent-pkg-xyz"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let result = registry.get_metadata("nonexistent-pkg-xyz", None).await;

        match result {
            Err(RegistryError::NotFound(name)) => {
                assert_eq!(name, "nonexistent-pkg-xyz");
            }
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    // T-005-03: Rate limited returns RateLimited
    #[tokio::test]
    async fn rate_limited_returns_rate_limited() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/lodash"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let result = registry.get_metadata("lodash", None).await;

        match result {
            Err(RegistryError::RateLimited) => {}
            other => panic!("expected RateLimited, got {:?}", other),
        }
    }

    // T-005-04: Network error returns NetworkError
    #[tokio::test]
    async fn network_error_returns_network_error() {
        // Use an unreachable address — port 1 is almost certainly not serving HTTP.
        let registry = NpmRegistry::new("http://127.0.0.1:1".to_string());
        let result = registry.get_metadata("lodash", None).await;

        match result {
            Err(RegistryError::NetworkError(_)) => {}
            other => panic!("expected NetworkError, got {:?}", other),
        }
    }

    // T-005-05: Malformed JSON returns ParseError
    #[tokio::test]
    async fn malformed_json_returns_parse_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/lodash"))
            .respond_with(ResponseTemplate::new(200).set_body_string("this is not json"))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let result = registry.get_metadata("lodash", None).await;

        match result {
            Err(RegistryError::ParseError(_)) => {}
            other => panic!("expected ParseError, got {:?}", other),
        }
    }

    // T-005-06: Extracts publish time from time field (specific version)
    #[tokio::test]
    async fn extracts_publish_time_for_specific_version() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/lodash"))
            .respond_with(ResponseTemplate::new(200).set_body_string(lodash_json()))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let meta = registry
            .get_metadata("lodash", Some("4.17.20"))
            .await
            .unwrap();

        assert_eq!(meta.version, "4.17.20");
        assert_eq!(
            meta.published_at.unwrap().to_rfc3339(),
            "2020-08-13T03:01:14.171+00:00"
        );
    }

    // T-005-07: Extracts maintainers list
    #[tokio::test]
    async fn extracts_maintainers_list() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/express"))
            .respond_with(ResponseTemplate::new(200).set_body_string(express_json()))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let meta = registry.get_metadata("express", None).await.unwrap();

        assert_eq!(meta.maintainers, vec!["dougwilson", "wesleytodd"]);
    }

    // T-005-08: Custom base URL is used (wiremock on custom port)
    #[tokio::test]
    async fn custom_base_url_is_used() {
        let server = MockServer::start().await;
        // The server is already on a random port, proving the base URL is configurable.
        let custom_url = server.uri();
        assert!(
            custom_url.contains("127.0.0.1"),
            "wiremock should bind locally"
        );

        Mock::given(method("GET"))
            .and(path("/lodash"))
            .respond_with(ResponseTemplate::new(200).set_body_string(lodash_json()))
            .expect(1) // Verify that exactly one request is made to the mock
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(custom_url);
        let meta = registry.get_metadata("lodash", None).await.unwrap();

        assert_eq!(meta.name, "lodash");
        // The expect(1) on the mock will panic on drop if the request was not received,
        // confirming the custom base URL was used.
    }

    /// npm JSON fixture with install scripts.
    fn malicious_pkg_json() -> String {
        r#"{
            "name": "malicious-pkg",
            "description": "A malicious package",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "malicious-pkg",
                    "version": "1.0.0",
                    "description": "A malicious package",
                    "scripts": {
                        "preinstall": "node setup.js",
                        "postinstall": "node malicious.js",
                        "test": "jest"
                    }
                }
            },
            "time": {
                "1.0.0": "2025-06-01T00:00:00.000Z"
            },
            "maintainers": [
                { "name": "attacker", "email": "attacker@example.com" }
            ]
        }"#
        .to_string()
    }

    // T-012-09: npm registry extracts scripts field
    #[tokio::test]
    async fn npm_registry_extracts_scripts_field() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/malicious-pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_string(malicious_pkg_json()))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let scripts = registry
            .get_install_scripts("malicious-pkg", None)
            .await
            .unwrap();

        // Should extract preinstall and postinstall, but NOT test
        assert_eq!(scripts.len(), 2);

        let preinstall = scripts.iter().find(|s| s.name == "preinstall").unwrap();
        assert_eq!(preinstall.content, "node setup.js");

        let postinstall = scripts.iter().find(|s| s.name == "postinstall").unwrap();
        assert_eq!(postinstall.content, "node malicious.js");

        // "test" script should not be included
        assert!(scripts.iter().all(|s| s.name != "test"));
    }

    // T-012-10: npm package without scripts field -> empty Vec
    #[tokio::test]
    async fn npm_package_without_scripts_field_returns_empty() {
        let server = MockServer::start().await;

        // lodash_json() has no scripts field
        Mock::given(method("GET"))
            .and(path("/lodash"))
            .respond_with(ResponseTemplate::new(200).set_body_string(lodash_json()))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let scripts = registry.get_install_scripts("lodash", None).await.unwrap();

        assert!(
            scripts.is_empty(),
            "Package without scripts should return empty Vec"
        );
    }

    // T-029-02: npm client extracts dist.integrity (sha512 SRI → hex)
    #[tokio::test]
    async fn npm_extracts_dist_integrity_as_hex() {
        let server = MockServer::start().await;

        // sha512 of the bytes [0xDE, 0xAD, 0xBE, 0xEF] in standard base64 is "3q2+7w=="
        // We'll use a known base64 payload and verify the hex output.
        // base64("deadbeef" as bytes) — craft a simple example:
        // bytes: [0x00, 0x01, 0x02] → base64 "AAEC" → hex "000102"
        let json = r#"{
            "name": "test-pkg",
            "description": "A test package",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "dist": {
                        "integrity": "sha512-AAEC",
                        "shasum": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
                    }
                }
            },
            "time": { "1.0.0": "2024-01-01T00:00:00.000Z" },
            "maintainers": [{ "name": "alice" }]
        }"#;

        Mock::given(method("GET"))
            .and(path("/test-pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let meta = registry.get_metadata("test-pkg", None).await.unwrap();

        // AAEC (standard base64) decodes to bytes [0x00, 0x01, 0x02] → hex "000102"
        assert_eq!(
            meta.content_hash,
            Some("sha512:000102".to_string()),
            "integrity sha512-AAEC should decode to sha512:000102"
        );
    }

    // T-029-03: npm client falls back to dist.shasum when integrity missing
    #[tokio::test]
    async fn npm_falls_back_to_shasum() {
        let server = MockServer::start().await;

        let json = r#"{
            "name": "test-pkg",
            "description": "A test package",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "dist": {
                        "shasum": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
                    }
                }
            },
            "time": { "1.0.0": "2024-01-01T00:00:00.000Z" },
            "maintainers": [{ "name": "alice" }]
        }"#;

        Mock::given(method("GET"))
            .and(path("/test-pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let meta = registry.get_metadata("test-pkg", None).await.unwrap();

        assert_eq!(
            meta.content_hash,
            Some("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
            "should fall back to sha1:<shasum> when integrity is absent"
        );
    }

    // T-040-01: Package with SRI `integrity` field returns sha512 hash (unchanged)
    // The `shasum` field is present but must be ignored in favour of `integrity`.
    #[test]
    fn extract_npm_content_hash_prefers_integrity_over_shasum() {
        let dist = NpmDist {
            integrity: Some("sha512-AAEC".to_string()),
            shasum: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
        };
        let result = extract_npm_content_hash(Some(&dist));
        // sha512-AAEC decodes to bytes [0x00,0x01,0x02] → "sha512:000102"
        assert_eq!(
            result,
            Some("sha512:000102".to_string()),
            "T-040-01: integrity sha512-AAEC should decode to sha512:000102, ignoring shasum"
        );
    }

    // T-040-02: Package with only `shasum` (no `integrity`) returns `sha1:`-prefixed hash.
    // This is existing behaviour that must remain unchanged — the function still
    // extracts the sha1 for informational purposes; policy enforcement is in the cache layer.
    #[test]
    fn extract_npm_content_hash_returns_sha1_prefix_for_shasum_only() {
        let dist = NpmDist {
            integrity: None,
            shasum: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
        };
        let result = extract_npm_content_hash(Some(&dist));
        assert_eq!(
            result,
            Some("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
            "T-040-02: sha1 fallback must still return sha1:<shasum> for informational use"
        );
    }

    // T-040-03: Package with neither `integrity` nor `shasum` returns `None`.
    #[test]
    fn extract_npm_content_hash_none_when_both_absent() {
        let dist = NpmDist {
            integrity: None,
            shasum: None,
        };
        let result = extract_npm_content_hash(Some(&dist));
        assert_eq!(result, None, "T-040-03: both absent should return None");
    }

    // T-029-04: npm client tolerates missing dist
    #[tokio::test]
    async fn npm_tolerates_missing_dist() {
        let server = MockServer::start().await;

        // lodash_json() has no dist field
        Mock::given(method("GET"))
            .and(path("/lodash"))
            .respond_with(ResponseTemplate::new(200).set_body_string(lodash_json()))
            .mount(&server)
            .await;

        let registry = NpmRegistry::new(server.uri());
        let meta = registry.get_metadata("lodash", None).await.unwrap();

        assert_eq!(
            meta.content_hash, None,
            "content_hash should be None when dist is absent"
        );
    }
}

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;

use super::{Registry, RegistryError};
use crate::types::PackageMetadata;

/// crates.io registry client.
///
/// Fetches package metadata from the crates.io API.
/// The base URL is configurable — it must NOT be hardcoded.
pub struct CratesRegistry {
    base_url: String,
    client: Client,
}

impl CratesRegistry {
    /// Create a new crates.io registry client with the given base URL.
    ///
    /// The `base_url` should be the root URL of the crates.io-compatible registry
    /// (e.g. `https://crates.io`). No trailing slash.
    ///
    /// crates.io requires a User-Agent header; requests without one receive 403.
    pub fn new(base_url: String) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let client = Client::builder()
            .user_agent("dep-scan/0.2.0 (https://github.com/tkdtaylor/dep-scan)")
            .build()
            .unwrap_or_default();
        Self { base_url, client }
    }
}

impl Registry for CratesRegistry {
    async fn get_metadata(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<PackageMetadata, RegistryError> {
        let url = format!("{}/api/v1/crates/{}", self.base_url, name);

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

        let api_response: CratesApiResponse = response
            .json()
            .await
            .map_err(|e| RegistryError::ParseError(e.to_string()))?;

        // Determine the resolved version entry
        let resolved_version_entry = match version {
            Some(v) => api_response
                .versions
                .iter()
                .find(|ver| ver.num == v)
                .ok_or_else(|| RegistryError::NotFound(format!("{name}@{v}")))?,
            None => api_response
                .versions
                .first()
                .ok_or_else(|| RegistryError::ParseError("no versions found".to_string()))?,
        };

        let version_str = resolved_version_entry.num.clone();

        // Parse the version-specific created_at timestamp
        let published_at = resolved_version_entry
            .created_at
            .parse::<DateTime<Utc>>()
            .ok();

        // Extract maintainer identity.
        //
        // Priority:
        //   1. `published_by` (traditional token-based publish) — use the login directly.
        //   2. `trustpub_data` (OIDC Trusted Publishing, `published_by` is intentionally null)
        //      — synthesise a stable label `trustpub:<provider>:<repository>`.
        //   3. Neither present (very old versions) — return empty Vec.
        let maintainers = resolved_version_entry.maintainer_identities();

        // Extract downloads count
        let downloads = Some(api_response.krate.downloads);

        // Extract repository URL (if non-empty)
        let repository_url = api_response.krate.repository.filter(|s| !s.is_empty());

        // Extract description
        let description = api_response.krate.description.filter(|s| !s.is_empty());

        // Extract content hash from cksum field (sha256 hex).
        let content_hash = resolved_version_entry
            .cksum
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("sha256:{s}"));

        Ok(PackageMetadata {
            name: api_response.krate.name,
            version: version_str,
            description,
            published_at,
            maintainers,
            downloads,
            repository_url,
            content_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// Private serde structs for the crates.io API JSON response
// ---------------------------------------------------------------------------

/// Top-level response from `GET /api/v1/crates/{name}`.
#[derive(Debug, Deserialize)]
struct CratesApiResponse {
    #[serde(rename = "crate")]
    krate: CrateInfo,
    versions: Vec<CrateVersion>,
}

/// The `crate` object in the crates.io API response.
#[derive(Debug, Deserialize)]
struct CrateInfo {
    name: String,
    #[allow(dead_code)]
    max_version: Option<String>,
    description: Option<String>,
    downloads: u64,
    repository: Option<String>,
    #[allow(dead_code)]
    created_at: Option<String>,
}

/// A single version entry in the crates.io API response.
#[derive(Debug, Deserialize)]
struct CrateVersion {
    num: String,
    created_at: String,
    published_by: Option<PublishedBy>,
    /// Trusted Publishing (OIDC) metadata, present when `published_by` is null.
    /// crates.io populates this when a crate is published via GitHub Actions OIDC
    /// tokens instead of personal API tokens.
    #[serde(default)]
    trustpub_data: Option<TrustPubData>,
    /// SHA-256 checksum of the crate tarball, as a hex string.
    #[serde(default)]
    cksum: Option<String>,
}

impl CrateVersion {
    /// Return the maintainer identity strings for this version.
    ///
    /// Priority:
    ///   1. `published_by.login` when present (traditional token-based publish).
    ///   2. Synthesised `trustpub:<provider>:<repository>` when `trustpub_data`
    ///      is present and `published_by` is null (OIDC Trusted Publishing).
    ///   3. Empty Vec when neither is present (very old versions).
    fn maintainer_identities(&self) -> Vec<String> {
        if let Some(pb) = &self.published_by {
            return vec![pb.login.clone()];
        }
        if let Some(tp) = &self.trustpub_data {
            return vec![format!("trustpub:{}:{}", tp.provider, tp.repository)];
        }
        Vec::new()
    }
}

/// The publisher of a version.
#[derive(Debug, Deserialize)]
struct PublishedBy {
    login: String,
    #[allow(dead_code)]
    name: Option<String>,
}

/// Trusted Publishing (OIDC) data attached to a version when `published_by` is null.
///
/// crates.io uses this for packages published via GitHub Actions OIDC tokens.
/// The struct intentionally ignores unknown extra fields (e.g. `run_id`, `sha`)
/// to remain forward-compatible as crates.io adds new fields.
#[derive(Debug, Deserialize)]
struct TrustPubData {
    provider: String,
    repository: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Realistic crates.io JSON fixture for "serde".
    fn serde_json() -> String {
        r#"{
            "crate": {
                "name": "serde",
                "max_version": "1.0.228",
                "description": "A generic serialization/deserialization framework",
                "downloads": 903219797,
                "repository": "https://github.com/serde-rs/serde",
                "created_at": "2015-02-27T05:17:50.502704+00:00"
            },
            "versions": [
                {
                    "num": "1.0.228",
                    "created_at": "2026-03-15T00:00:00.000000+00:00",
                    "published_by": {
                        "login": "dtolnay",
                        "name": "David Tolnay"
                    }
                },
                {
                    "num": "1.0.227",
                    "created_at": "2026-02-01T00:00:00.000000+00:00",
                    "published_by": {
                        "login": "dtolnay",
                        "name": "David Tolnay"
                    }
                }
            ]
        }"#
        .to_string()
    }

    // T-018-01: Fetch metadata for existing crate
    #[tokio::test]
    async fn fetch_metadata_for_existing_crate() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/serde"))
            .respond_with(ResponseTemplate::new(200).set_body_string(serde_json()))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        let meta = registry.get_metadata("serde", None).await.unwrap();

        assert_eq!(meta.name, "serde");
        assert_eq!(meta.version, "1.0.228");
        assert_eq!(
            meta.description,
            Some("A generic serialization/deserialization framework".to_string())
        );
        assert!(meta.published_at.is_some());
        assert_eq!(
            meta.published_at.unwrap().to_rfc3339(),
            "2026-03-15T00:00:00+00:00"
        );
        assert_eq!(meta.maintainers, vec!["dtolnay"]);
        assert_eq!(meta.downloads, Some(903219797));
        assert_eq!(
            meta.repository_url,
            Some("https://github.com/serde-rs/serde".to_string())
        );
    }

    // T-018-02: Package not found returns NotFound
    #[tokio::test]
    async fn package_not_found_returns_not_found() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/nonexistent-crate-xyz"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        let result = registry.get_metadata("nonexistent-crate-xyz", None).await;

        match result {
            Err(RegistryError::NotFound(name)) => {
                assert_eq!(name, "nonexistent-crate-xyz");
            }
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    // T-018-03: Rate limited returns RateLimited
    #[tokio::test]
    async fn rate_limited_returns_rate_limited() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/serde"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        let result = registry.get_metadata("serde", None).await;

        match result {
            Err(RegistryError::RateLimited) => {}
            other => panic!("expected RateLimited, got {:?}", other),
        }
    }

    // T-018-04: Malformed JSON returns ParseError
    #[tokio::test]
    async fn malformed_json_returns_parse_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/serde"))
            .respond_with(ResponseTemplate::new(200).set_body_string("this is not json"))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        let result = registry.get_metadata("serde", None).await;

        match result {
            Err(RegistryError::ParseError(_)) => {}
            other => panic!("expected ParseError, got {:?}", other),
        }
    }

    // T-018-05: User-Agent header is sent
    #[tokio::test]
    async fn user_agent_header_is_sent() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/serde"))
            .and(header(
                "user-agent",
                "dep-scan/0.2.0 (https://github.com/tkdtaylor/dep-scan)",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(serde_json()))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        // If the User-Agent header is not sent, wiremock will not match and return 404/500
        let result = registry.get_metadata("serde", None).await;
        assert!(
            result.is_ok(),
            "Request should succeed when User-Agent matches"
        );
    }

    // T-018-06: Custom base URL is used
    #[tokio::test]
    async fn custom_base_url_is_used() {
        let server = MockServer::start().await;
        let custom_url = server.uri();
        assert!(
            custom_url.contains("127.0.0.1"),
            "wiremock should bind locally"
        );

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/serde"))
            .respond_with(ResponseTemplate::new(200).set_body_string(serde_json()))
            .expect(1) // Verify exactly one request is made to the mock
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(custom_url);
        let meta = registry.get_metadata("serde", None).await.unwrap();

        assert_eq!(meta.name, "serde");
        // The expect(1) on the mock will panic on drop if the request was not received
    }

    // T-018-07: Downloads count is extracted
    #[tokio::test]
    async fn downloads_count_is_extracted() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/serde"))
            .respond_with(ResponseTemplate::new(200).set_body_string(serde_json()))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        let meta = registry.get_metadata("serde", None).await.unwrap();

        assert_eq!(meta.downloads, Some(903219797));
    }

    // T-018-08: Maintainer is extracted from published_by
    #[tokio::test]
    async fn maintainer_extracted_from_published_by() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/serde"))
            .respond_with(ResponseTemplate::new(200).set_body_string(serde_json()))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        let meta = registry.get_metadata("serde", None).await.unwrap();

        assert_eq!(meta.maintainers, vec!["dtolnay"]);
    }

    // Additional: version with no published_by returns empty maintainers
    #[tokio::test]
    async fn no_published_by_returns_empty_maintainers() {
        let json = r#"{
            "crate": {
                "name": "old-crate",
                "max_version": "0.1.0",
                "description": "An old crate",
                "downloads": 100,
                "repository": "",
                "created_at": "2020-01-01T00:00:00.000000+00:00"
            },
            "versions": [
                {
                    "num": "0.1.0",
                    "created_at": "2020-01-01T00:00:00.000000+00:00",
                    "published_by": null
                }
            ]
        }"#;

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/old-crate"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        let meta = registry.get_metadata("old-crate", None).await.unwrap();

        assert!(meta.maintainers.is_empty());
        // Empty repository should become None
        assert!(meta.repository_url.is_none());
    }

    // Additional: requesting a specific version
    #[tokio::test]
    async fn fetch_specific_version() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/serde"))
            .respond_with(ResponseTemplate::new(200).set_body_string(serde_json()))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        let meta = registry
            .get_metadata("serde", Some("1.0.227"))
            .await
            .unwrap();

        assert_eq!(meta.version, "1.0.227");
        assert_eq!(
            meta.published_at.unwrap().to_rfc3339(),
            "2026-02-01T00:00:00+00:00"
        );
    }

    // Additional: requesting a non-existent version
    #[tokio::test]
    async fn fetch_nonexistent_version_returns_not_found() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates/serde"))
            .respond_with(ResponseTemplate::new(200).set_body_string(serde_json()))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        let result = registry.get_metadata("serde", Some("99.99.99")).await;

        match result {
            Err(RegistryError::NotFound(msg)) => {
                assert!(msg.contains("serde@99.99.99"));
            }
            other => panic!("expected NotFound, got: {:?}", other),
        }
    }

    // T-029-08: crates.io client extracts cksum as sha256:<hex>
    #[tokio::test]
    async fn crates_extracts_cksum_as_sha256_hex() {
        let json = r#"{
            "crate": {
                "name": "mylib",
                "max_version": "1.0.0",
                "description": "A library",
                "downloads": 42,
                "repository": "https://github.com/example/mylib",
                "created_at": "2024-01-01T00:00:00.000000+00:00"
            },
            "versions": [
                {
                    "num": "1.0.0",
                    "created_at": "2024-01-01T00:00:00.000000+00:00",
                    "cksum": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "published_by": {
                        "login": "alice",
                        "name": "Alice"
                    }
                }
            ]
        }"#;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/crates/mylib"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json))
            .mount(&server)
            .await;

        let registry = CratesRegistry::new(server.uri());
        let meta = registry.get_metadata("mylib", None).await.unwrap();

        assert_eq!(
            meta.content_hash,
            Some(
                "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    .to_string()
            )
        );
    }

    // -------------------------------------------------------------------------
    // T-082 — trustpub_data recognition
    // -------------------------------------------------------------------------

    // T-082-01 + T-082-02: CrateVersion deserialises trustpub_data (with extra fields)
    #[test]
    fn t082_01_02_trustpub_data_deserialises_with_extra_fields() {
        // Includes extra forward-compatible fields (run_id, sha) — must not break.
        let json = r#"{
            "num": "0.4.2",
            "created_at": "2026-01-01T00:00:00.000000+00:00",
            "published_by": null,
            "trustpub_data": {
                "provider": "github",
                "repository": "rust-random/getrandom",
                "run_id": "22617675559",
                "sha": "4d826731b20a09e69cca91c66aea57ab3cf00072"
            }
        }"#;

        let ver: CrateVersion = serde_json::from_str(json).expect("should deserialise");
        assert!(ver.published_by.is_none());
        let tp = ver.trustpub_data.expect("trustpub_data should be Some");
        assert_eq!(tp.provider, "github");
        assert_eq!(tp.repository, "rust-random/getrandom");
    }

    // T-082-03: Traditional published_by-only publish still extracts the login
    #[test]
    fn t082_03_traditional_published_by_extracts_login() {
        let json = r#"{
            "num": "1.0.0",
            "created_at": "2024-01-01T00:00:00.000000+00:00",
            "published_by": { "login": "dtolnay", "name": "David Tolnay" }
        }"#;

        let ver: CrateVersion = serde_json::from_str(json).expect("should deserialise");
        let ids = ver.maintainer_identities();
        assert_eq!(ids, vec!["dtolnay"]);
    }

    // T-082-04: trustpub-only publish synthesises stable label
    #[test]
    fn t082_04_trustpub_only_synthesises_stable_label() {
        let json = r#"{
            "num": "0.4.2",
            "created_at": "2026-01-01T00:00:00.000000+00:00",
            "published_by": null,
            "trustpub_data": {
                "provider": "github",
                "repository": "rust-random/getrandom",
                "run_id": "22617675559",
                "sha": "4d826731b20a09e69cca91c66aea57ab3cf00072"
            }
        }"#;

        let ver: CrateVersion = serde_json::from_str(json).expect("should deserialise");
        let ids = ver.maintainer_identities();
        assert_eq!(ids, vec!["trustpub:github:rust-random/getrandom"]);
    }

    // T-082-05: Both present → prefer published_by
    #[test]
    fn t082_05_both_present_prefers_published_by() {
        let json = r#"{
            "num": "0.4.2",
            "created_at": "2026-01-01T00:00:00.000000+00:00",
            "published_by": { "login": "josephlr" },
            "trustpub_data": {
                "provider": "github",
                "repository": "rust-random/getrandom"
            }
        }"#;

        let ver: CrateVersion = serde_json::from_str(json).expect("should deserialise");
        let ids = ver.maintainer_identities();
        assert_eq!(ids, vec!["josephlr"]);
    }

    // T-082-06: Neither present → empty Vec
    #[test]
    fn t082_06_neither_present_returns_empty() {
        let json = r#"{
            "num": "0.0.1",
            "created_at": "2015-01-01T00:00:00.000000+00:00",
            "published_by": null
        }"#;

        let ver: CrateVersion = serde_json::from_str(json).expect("should deserialise");
        let ids = ver.maintainer_identities();
        assert!(ids.is_empty());
    }

    // T-082-07: Same trustpub repo across versions → same identity
    #[test]
    fn t082_07_same_trustpub_repo_produces_same_identity() {
        let v1_json = r#"{
            "num": "0.4.0",
            "created_at": "2025-06-01T00:00:00.000000+00:00",
            "published_by": null,
            "trustpub_data": {
                "provider": "github",
                "repository": "rust-random/getrandom",
                "run_id": "11111111111",
                "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        }"#;
        let v2_json = r#"{
            "num": "0.4.2",
            "created_at": "2026-01-01T00:00:00.000000+00:00",
            "published_by": null,
            "trustpub_data": {
                "provider": "github",
                "repository": "rust-random/getrandom",
                "run_id": "22617675559",
                "sha": "4d826731b20a09e69cca91c66aea57ab3cf00072"
            }
        }"#;

        let v1: CrateVersion = serde_json::from_str(v1_json).expect("should deserialise");
        let v2: CrateVersion = serde_json::from_str(v2_json).expect("should deserialise");
        assert_eq!(v1.maintainer_identities(), v2.maintainer_identities());
    }

    // T-082-08: Different trustpub repo between versions → different identity
    #[test]
    fn t082_08_different_trustpub_repo_produces_different_identity() {
        let v1_json = r#"{
            "num": "0.4.0",
            "created_at": "2025-06-01T00:00:00.000000+00:00",
            "published_by": null,
            "trustpub_data": {
                "provider": "github",
                "repository": "rust-random/getrandom"
            }
        }"#;
        let v2_json = r#"{
            "num": "0.4.2",
            "created_at": "2026-01-01T00:00:00.000000+00:00",
            "published_by": null,
            "trustpub_data": {
                "provider": "github",
                "repository": "malicious-actor/getrandom-fork"
            }
        }"#;

        let v1: CrateVersion = serde_json::from_str(v1_json).expect("should deserialise");
        let v2: CrateVersion = serde_json::from_str(v2_json).expect("should deserialise");
        // Different identities → MaintainerChangePolicy would detect a changeover
        assert_ne!(v1.maintainer_identities(), v2.maintainer_identities());
        assert_eq!(
            v1.maintainer_identities(),
            vec!["trustpub:github:rust-random/getrandom"]
        );
        assert_eq!(
            v2.maintainer_identities(),
            vec!["trustpub:github:malicious-actor/getrandom-fork"]
        );
    }
}

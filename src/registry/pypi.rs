use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::{Registry, RegistryError};
use crate::types::PackageMetadata;

/// Digests map for a PyPI release file.
#[derive(Debug, Deserialize, Default)]
struct PyPiDigests {
    sha256: Option<String>,
}

/// Serde model for the PyPI JSON API response.
#[derive(Debug, Deserialize)]
struct PyPiResponse {
    info: PyPiInfo,
    #[serde(default)]
    releases: HashMap<String, Vec<PyPiRelease>>,
}

/// The `info` section of the PyPI JSON API response.
#[derive(Debug, Deserialize)]
struct PyPiInfo {
    name: String,
    version: String,
    summary: Option<String>,
    author: Option<String>,
    maintainer: Option<String>,
    home_page: Option<String>,
    project_urls: Option<HashMap<String, String>>,
}

/// A single release file entry within a version's release list.
#[derive(Debug, Deserialize)]
struct PyPiRelease {
    #[serde(default)]
    upload_time_iso_8601: Option<String>,
    /// Package type: "sdist", "bdist_wheel", etc.
    #[serde(default)]
    packagetype: Option<String>,
    /// Digest map for this release file.
    #[serde(default)]
    digests: PyPiDigests,
}

/// Client for fetching package metadata from the PyPI JSON API.
///
/// The base URL is configurable so tests can point at a wiremock server
/// and production usage can point at an internal mirror.
pub struct PyPiRegistry {
    base_url: String,
    client: reqwest::Client,
}

impl PyPiRegistry {
    /// Create a new PyPI registry client with the given base URL.
    ///
    /// The base URL should not include a trailing slash, e.g. `"https://pypi.org"`.
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    /// Build the URL for fetching a package's metadata.
    fn package_url(&self, name: &str) -> String {
        format!("{}/pypi/{}/json", self.base_url, name)
    }

    /// Extract the repository URL from project_urls or home_page.
    fn extract_repository_url(info: &PyPiInfo) -> Option<String> {
        if let Some(ref urls) = info.project_urls {
            // Try common key names in preference order
            for key in &["Source", "Source Code", "Repository", "Homepage"] {
                if let Some(url) = urls.get(*key) {
                    return Some(url.clone());
                }
            }
        }
        info.home_page.clone().filter(|s| !s.is_empty())
    }

    /// Build the maintainers list from author and maintainer fields.
    fn extract_maintainers(info: &PyPiInfo) -> Vec<String> {
        let mut maintainers = Vec::new();
        if let Some(ref author) = info.author
            && !author.is_empty()
        {
            maintainers.push(author.clone());
        }
        if let Some(ref maintainer) = info.maintainer
            && !maintainer.is_empty()
        {
            maintainers.push(maintainer.clone());
        }
        maintainers
    }

    /// Extract the content hash from a version's release file list.
    ///
    /// Prefers the `sha256` digest of the sdist; falls back to the first wheel
    /// if no sdist is present. Returns `None` if no `digests.sha256` is available.
    fn extract_content_hash(release_files: &[PyPiRelease]) -> Option<String> {
        // Try sdist first
        if let Some(sdist) = release_files
            .iter()
            .find(|r| r.packagetype.as_deref() == Some("sdist"))
            && let Some(ref sha) = sdist.digests.sha256
        {
            return Some(format!("sha256:{sha}"));
        }
        // Fall back to first wheel
        if let Some(wheel) = release_files
            .iter()
            .find(|r| r.packagetype.as_deref() == Some("bdist_wheel"))
            && let Some(ref sha) = wheel.digests.sha256
        {
            return Some(format!("sha256:{sha}"));
        }
        None
    }

    /// Parse an ISO 8601 timestamp string into a `DateTime<Utc>`.
    fn parse_upload_time(timestamp: &str) -> Option<DateTime<Utc>> {
        // PyPI returns timestamps like "2023-05-22T15:12:44.145Z"
        timestamp.parse::<DateTime<Utc>>().ok()
    }

    /// Extract the upload time for a specific version from the releases map.
    fn extract_upload_time(
        releases: &HashMap<String, Vec<PyPiRelease>>,
        version: &str,
    ) -> Option<DateTime<Utc>> {
        let release_files = releases.get(version)?;
        // Find the earliest upload_time among files for this version
        release_files
            .iter()
            .filter_map(|r| r.upload_time_iso_8601.as_deref())
            .filter_map(Self::parse_upload_time)
            .min()
    }
}

impl Registry for PyPiRegistry {
    async fn get_metadata(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<PackageMetadata, RegistryError> {
        let url = self.package_url(name);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        match response.status().as_u16() {
            404 => return Err(RegistryError::NotFound(name.to_string())),
            429 => return Err(RegistryError::RateLimited),
            s if !(200..300).contains(&s) => {
                return Err(RegistryError::NetworkError(format!(
                    "unexpected HTTP status: {}",
                    s
                )));
            }
            _ => {}
        }

        let body = response
            .text()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        let pypi_response: PyPiResponse =
            serde_json::from_str(&body).map_err(|e| RegistryError::ParseError(e.to_string()))?;

        // Determine which version to report
        let resolved_version = version.unwrap_or(&pypi_response.info.version);

        // If a specific version was requested, verify it exists in releases
        if version.is_some() && !pypi_response.releases.contains_key(resolved_version) {
            return Err(RegistryError::NotFound(format!(
                "{}@{}",
                name, resolved_version
            )));
        }

        let published_at = Self::extract_upload_time(&pypi_response.releases, resolved_version);

        let maintainers = Self::extract_maintainers(&pypi_response.info);
        let repository_url = Self::extract_repository_url(&pypi_response.info);

        // Extract content hash from the sdist (preferred) or first wheel.
        let content_hash = pypi_response
            .releases
            .get(resolved_version)
            .and_then(|files| Self::extract_content_hash(files));

        Ok(PackageMetadata {
            name: pypi_response.info.name,
            version: resolved_version.to_string(),
            description: pypi_response.info.summary.filter(|s| !s.is_empty()),
            published_at,
            maintainers,
            downloads: None, // PyPI JSON API does not include download counts
            repository_url,
            content_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Realistic PyPI JSON fixture for the "requests" package.
    fn pypi_requests_json() -> &'static str {
        r#"{
            "info": {
                "name": "requests",
                "version": "2.31.0",
                "summary": "Python HTTP for Humans.",
                "author": "Kenneth Reitz",
                "author_email": "me@kennethreitz.org",
                "maintainer": "",
                "maintainer_email": "",
                "home_page": "https://requests.readthedocs.io",
                "project_urls": {
                    "Source": "https://github.com/psf/requests",
                    "Documentation": "https://requests.readthedocs.io"
                }
            },
            "releases": {
                "2.31.0": [
                    {
                        "filename": "requests-2.31.0-py3-none-any.whl",
                        "upload_time_iso_8601": "2023-05-22T15:12:44.145Z"
                    },
                    {
                        "filename": "requests-2.31.0.tar.gz",
                        "upload_time_iso_8601": "2023-05-22T15:12:45.000Z"
                    }
                ],
                "2.30.0": [
                    {
                        "filename": "requests-2.30.0.tar.gz",
                        "upload_time_iso_8601": "2023-05-03T11:30:00.000Z"
                    }
                ]
            }
        }"#
    }

    // T-006-01: Fetch metadata for existing package
    #[tokio::test]
    async fn fetch_metadata_for_existing_package() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(pypi_requests_json()))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let metadata = registry.get_metadata("requests", None).await.unwrap();

        assert_eq!(metadata.name, "requests");
        assert_eq!(metadata.version, "2.31.0");
        assert_eq!(
            metadata.description,
            Some("Python HTTP for Humans.".to_string())
        );
        assert!(metadata.published_at.is_some());
        assert!(!metadata.maintainers.is_empty());
        assert_eq!(
            metadata.repository_url,
            Some("https://github.com/psf/requests".to_string())
        );
    }

    // T-006-02: Package not found returns NotFound
    #[tokio::test]
    async fn package_not_found_returns_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/nonexistent-pkg/json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let result = registry.get_metadata("nonexistent-pkg", None).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::NotFound(name) => assert_eq!(name, "nonexistent-pkg"),
            other => panic!("expected NotFound, got: {:?}", other),
        }
    }

    // T-006-03: Rate limited returns RateLimited
    #[tokio::test]
    async fn rate_limited_returns_rate_limited() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let result = registry.get_metadata("requests", None).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::RateLimited => {} // expected
            other => panic!("expected RateLimited, got: {:?}", other),
        }
    }

    // T-006-04: Malformed JSON returns ParseError
    #[tokio::test]
    async fn malformed_json_returns_parse_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string("this is not valid json {{{"))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let result = registry.get_metadata("requests", None).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::ParseError(_) => {} // expected
            other => panic!("expected ParseError, got: {:?}", other),
        }
    }

    // T-006-05: Extracts upload_time correctly from releases
    #[tokio::test]
    async fn extracts_upload_time_correctly() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(pypi_requests_json()))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let metadata = registry.get_metadata("requests", None).await.unwrap();

        let published = metadata.published_at.expect("should have published_at");
        // The earliest upload_time for 2.31.0 is "2023-05-22T15:12:44.145Z"
        assert_eq!(published.to_rfc3339(), "2023-05-22T15:12:44.145+00:00");
    }

    // T-006-06: Extracts author/maintainer
    #[tokio::test]
    async fn extracts_author_and_maintainer() {
        // Use a fixture where both author and maintainer are populated
        let json_with_both = r#"{
            "info": {
                "name": "some-package",
                "version": "1.0.0",
                "summary": "A package",
                "author": "Author Name",
                "author_email": "",
                "maintainer": "Maintainer Name",
                "maintainer_email": "",
                "home_page": "",
                "project_urls": null
            },
            "releases": {
                "1.0.0": [
                    {
                        "filename": "some-package-1.0.0.tar.gz",
                        "upload_time_iso_8601": "2024-01-01T00:00:00.000Z"
                    }
                ]
            }
        }"#;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/some-package/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json_with_both))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let metadata = registry.get_metadata("some-package", None).await.unwrap();

        assert_eq!(metadata.maintainers.len(), 2);
        assert_eq!(metadata.maintainers[0], "Author Name");
        assert_eq!(metadata.maintainers[1], "Maintainer Name");
    }

    // T-006-07: Custom base URL is used
    #[tokio::test]
    async fn custom_base_url_is_used() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/flask/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{
                        "info": {
                            "name": "flask",
                            "version": "3.0.0",
                            "summary": "A microframework",
                            "author": "Armin Ronacher",
                            "author_email": "",
                            "maintainer": "",
                            "maintainer_email": "",
                            "home_page": "",
                            "project_urls": null
                        },
                        "releases": {
                            "3.0.0": [
                                {
                                    "filename": "flask-3.0.0.tar.gz",
                                    "upload_time_iso_8601": "2023-09-30T12:00:00.000Z"
                                }
                            ]
                        }
                    }"#,
            ))
            .expect(1) // Expect exactly one request
            .mount(&server)
            .await;

        // The registry should hit {server.uri()}/pypi/flask/json
        let registry = PyPiRegistry::new(server.uri());
        let metadata = registry.get_metadata("flask", None).await.unwrap();

        assert_eq!(metadata.name, "flask");
        assert_eq!(metadata.version, "3.0.0");
        // wiremock will verify that exactly 1 request was received at the expected path
    }

    // T-006-08: Handles package with no releases
    #[tokio::test]
    async fn handles_package_with_no_releases() {
        let json_no_releases = r#"{
            "info": {
                "name": "empty-pkg",
                "version": "0.0.0",
                "summary": "A package with no releases",
                "author": "Someone",
                "author_email": "",
                "maintainer": "",
                "maintainer_email": "",
                "home_page": "",
                "project_urls": null
            },
            "releases": {}
        }"#;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/empty-pkg/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json_no_releases))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let metadata = registry.get_metadata("empty-pkg", None).await.unwrap();

        // When there are no releases, we still return metadata but published_at is None
        assert_eq!(metadata.name, "empty-pkg");
        assert_eq!(metadata.version, "0.0.0");
        assert!(metadata.published_at.is_none());
    }

    // Additional: requesting a specific version
    #[tokio::test]
    async fn fetch_specific_version() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(pypi_requests_json()))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let metadata = registry
            .get_metadata("requests", Some("2.30.0"))
            .await
            .unwrap();

        assert_eq!(metadata.version, "2.30.0");
        let published = metadata.published_at.expect("should have published_at");
        assert_eq!(published.to_rfc3339(), "2023-05-03T11:30:00+00:00");
    }

    // Additional: requesting a non-existent version
    #[tokio::test]
    async fn fetch_nonexistent_version_returns_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(pypi_requests_json()))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let result = registry.get_metadata("requests", Some("99.99.99")).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::NotFound(msg) => {
                assert!(msg.contains("requests@99.99.99"));
            }
            other => panic!("expected NotFound, got: {:?}", other),
        }
    }

    // Additional: author-only (no maintainer) -> maintainers has just the author
    #[tokio::test]
    async fn author_only_maintainers_list() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(pypi_requests_json()))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let metadata = registry.get_metadata("requests", None).await.unwrap();

        // The fixture has author "Kenneth Reitz" and empty maintainer
        assert_eq!(metadata.maintainers, vec!["Kenneth Reitz"]);
    }

    // Additional: repository_url falls back to home_page when project_urls is null
    #[tokio::test]
    async fn repository_url_falls_back_to_home_page() {
        let json = r#"{
            "info": {
                "name": "old-pkg",
                "version": "1.0.0",
                "summary": "Old package",
                "author": "Old Author",
                "author_email": "",
                "maintainer": "",
                "maintainer_email": "",
                "home_page": "https://example.com/old-pkg",
                "project_urls": null
            },
            "releases": {
                "1.0.0": [
                    {
                        "filename": "old-pkg-1.0.0.tar.gz",
                        "upload_time_iso_8601": "2020-01-01T00:00:00.000Z"
                    }
                ]
            }
        }"#;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/old-pkg/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let metadata = registry.get_metadata("old-pkg", None).await.unwrap();

        assert_eq!(
            metadata.repository_url,
            Some("https://example.com/old-pkg".to_string())
        );
    }

    // T-029-05: PyPI client extracts sdist digest
    #[tokio::test]
    async fn pypi_extracts_sdist_sha256() {
        let json = r#"{
            "info": {
                "name": "mypackage",
                "version": "1.0.0",
                "summary": "A test package",
                "author": "Author",
                "author_email": "",
                "maintainer": "",
                "maintainer_email": "",
                "home_page": "",
                "project_urls": null
            },
            "releases": {
                "1.0.0": [
                    {
                        "filename": "mypackage-1.0.0.tar.gz",
                        "packagetype": "sdist",
                        "upload_time_iso_8601": "2024-01-01T00:00:00.000Z",
                        "digests": { "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" }
                    },
                    {
                        "filename": "mypackage-1.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "upload_time_iso_8601": "2024-01-01T00:01:00.000Z",
                        "digests": { "sha256": "0000000000000000000000000000000000000000000000000000000000000000" }
                    }
                ]
            }
        }"#;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/mypackage/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let meta = registry.get_metadata("mypackage", None).await.unwrap();

        // Should prefer sdist sha256
        assert_eq!(
            meta.content_hash,
            Some(
                "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    .to_string()
            )
        );
    }

    // T-029-06: PyPI client falls back to first wheel when no sdist
    #[tokio::test]
    async fn pypi_falls_back_to_wheel_when_no_sdist() {
        let json = r#"{
            "info": {
                "name": "mypackage",
                "version": "2.0.0",
                "summary": "Wheel only package",
                "author": "Author",
                "author_email": "",
                "maintainer": "",
                "maintainer_email": "",
                "home_page": "",
                "project_urls": null
            },
            "releases": {
                "2.0.0": [
                    {
                        "filename": "mypackage-2.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "upload_time_iso_8601": "2024-06-01T00:00:00.000Z",
                        "digests": { "sha256": "ffff000000000000000000000000000000000000000000000000000000001234" }
                    }
                ]
            }
        }"#;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/mypackage/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let meta = registry.get_metadata("mypackage", None).await.unwrap();

        assert_eq!(
            meta.content_hash,
            Some(
                "sha256:ffff000000000000000000000000000000000000000000000000000000001234"
                    .to_string()
            )
        );
    }

    // T-029-07: PyPI client tolerates missing digests
    #[tokio::test]
    async fn pypi_tolerates_missing_digests() {
        let json = r#"{
            "info": {
                "name": "mypackage",
                "version": "3.0.0",
                "summary": "No digests",
                "author": "Author",
                "author_email": "",
                "maintainer": "",
                "maintainer_email": "",
                "home_page": "",
                "project_urls": null
            },
            "releases": {
                "3.0.0": [
                    {
                        "filename": "mypackage-3.0.0.tar.gz",
                        "packagetype": "sdist",
                        "upload_time_iso_8601": "2024-01-01T00:00:00.000Z",
                        "digests": {}
                    }
                ]
            }
        }"#;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/mypackage/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json))
            .mount(&server)
            .await;

        let registry = PyPiRegistry::new(server.uri());
        let meta = registry.get_metadata("mypackage", None).await.unwrap();

        assert_eq!(
            meta.content_hash, None,
            "content_hash should be None when no sha256 digest is available"
        );
    }
}

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;

use super::{Registry, RegistryError};
use crate::types::PackageMetadata;

/// Go module proxy client.
///
/// Fetches package metadata from a Go module proxy (default: proxy.golang.org).
/// The Go checksum database (sum.golang.org) is now handled by `SumDbClient`
/// in `registry::go_sumdb` (task 034), called once from `main.rs` to avoid
/// duplicate HTTP calls.
pub struct GoRegistry {
    base_url: String,
    /// Retained for backward compatibility with the `GoRegistry::new` constructor;
    /// the actual sumdb lookup is now performed by `SumDbClient` in main.rs.
    #[allow(dead_code)]
    sum_db_url: String,
    client: Client,
}

/// JSON response from the Go module proxy `{module}/@v/{version}.info` endpoint.
#[derive(Debug, Deserialize)]
struct GoVersionInfo {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Time")]
    time: String,
}

/// Encode a Go module path for use in proxy URLs.
///
/// The Go module proxy uses case-encoded paths where uppercase letters
/// are replaced with `!` followed by the lowercase letter.
/// For example, `github.com/Azure/go-autorest` becomes
/// `github.com/!azure/go-autorest`.
pub fn encode_module_path(module: &str) -> String {
    module
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                format!("!{}", c.to_ascii_lowercase())
            } else {
                c.to_string()
            }
        })
        .collect()
}

impl GoRegistry {
    /// Create a new Go module proxy client with configurable proxy and sum DB URLs.
    ///
    /// - `base_url`: root URL of the Go module proxy (e.g. `https://proxy.golang.org`). No trailing slash.
    /// - `sum_db_url`: root URL of the Go checksum database (e.g. `https://sum.golang.org`). No trailing slash.
    pub fn new(base_url: String, sum_db_url: String) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let sum_db_url = sum_db_url.trim_end_matches('/').to_string();
        Self {
            base_url,
            sum_db_url,
            client: Client::new(),
        }
    }

    /// Fetch the version list for a module from the proxy.
    ///
    /// Returns the list of version strings parsed from the plain-text response.
    async fn fetch_version_list(&self, module: &str) -> Result<Vec<String>, RegistryError> {
        let encoded = encode_module_path(module);
        let url = format!("{}/{}/@v/list", self.base_url, encoded);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        match response.status().as_u16() {
            404 => return Err(RegistryError::NotFound(module.to_string())),
            410 => return Err(RegistryError::NotFound(module.to_string())),
            200 => {}
            status => {
                return Err(RegistryError::NetworkError(format!(
                    "unexpected status code: {status}"
                )));
            }
        }

        let body = response
            .text()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        let versions: Vec<String> = body
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .map(|line| line.to_string())
            .collect();

        Ok(versions)
    }

    /// Fetch version info (version string and publish time) from the proxy.
    async fn fetch_version_info(
        &self,
        module: &str,
        version: &str,
    ) -> Result<GoVersionInfo, RegistryError> {
        let encoded = encode_module_path(module);
        let url = format!("{}/{}/@v/{}.info", self.base_url, encoded, version);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        match response.status().as_u16() {
            404 => return Err(RegistryError::NotFound(module.to_string())),
            410 => return Err(RegistryError::NotFound(module.to_string())),
            200 => {}
            status => {
                return Err(RegistryError::NetworkError(format!(
                    "unexpected status code: {status}"
                )));
            }
        }

        let body = response
            .text()
            .await
            .map_err(|e| RegistryError::NetworkError(e.to_string()))?;

        let info: GoVersionInfo =
            serde_json::from_str(&body).map_err(|e| RegistryError::ParseError(e.to_string()))?;

        Ok(info)
    }
}

impl Registry for GoRegistry {
    async fn get_metadata(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<PackageMetadata, RegistryError> {
        // Determine which version to use
        let resolved_version = match version {
            Some(v) => v.to_string(),
            None => {
                // Fetch version list and use the last one (highest/latest)
                let versions = self.fetch_version_list(name).await?;
                if versions.is_empty() {
                    return Err(RegistryError::NotFound(name.to_string()));
                }
                versions.last().unwrap().clone()
            }
        };

        // Fetch version info for publish time
        let info = self.fetch_version_info(name, &resolved_version).await?;

        // Parse the Time field as RFC3339
        let published_at = info
            .time
            .parse::<DateTime<Utc>>()
            .map_err(|e| RegistryError::ParseError(format!("invalid Time field: {e}")))?;

        // Note: the h1: content hash is obtained from the Go checksum database
        // (sum.golang.org) by `SumDbClient` in main.rs when `check_go_sumdb`
        // is enabled.  The `content_hash` field is populated there from the
        // `GoSumDbResult::Entry` to avoid making two identical HTTP calls to
        // the sumdb.  When `check_go_sumdb` is disabled, `content_hash`
        // remains `None`.

        Ok(PackageMetadata {
            name: name.to_string(),
            version: info.version,
            description: None, // Go proxy doesn't provide descriptions
            published_at: Some(published_at),
            maintainers: vec![],  // Go proxy doesn't provide maintainer info
            downloads: None,      // Go proxy doesn't provide download counts
            repository_url: None, // Could infer from module path but keeping simple
            content_hash: None,   // Populated from GoSumDbResult in main.rs (task 034)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // T-019-01: Fetch metadata for existing module
    #[tokio::test]
    async fn fetch_metadata_for_existing_module() {
        let server = MockServer::start().await;

        // Version list — last line is the latest
        Mock::given(method("GET"))
            .and(path("/github.com/test/module/@v/list"))
            .respond_with(ResponseTemplate::new(200).set_body_string("v1.9.0\nv1.9.1\n"))
            .mount(&server)
            .await;

        // Version info for v1.9.1
        Mock::given(method("GET"))
            .and(path("/github.com/test/module/@v/v1.9.1.info"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"Version":"v1.9.1","Time":"2023-06-15T10:30:00Z"}"#),
            )
            .mount(&server)
            .await;

        let registry = GoRegistry::new(server.uri(), server.uri());
        let meta = registry
            .get_metadata("github.com/test/module", None)
            .await
            .unwrap();

        assert_eq!(meta.name, "github.com/test/module");
        assert_eq!(meta.version, "v1.9.1");
        assert!(meta.published_at.is_some());
        assert_eq!(
            meta.published_at.unwrap().to_rfc3339(),
            "2023-06-15T10:30:00+00:00"
        );
    }

    // T-019-02: Module not found returns NotFound
    #[tokio::test]
    async fn module_not_found_returns_not_found() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/github.com/nonexistent/module/@v/list"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let registry = GoRegistry::new(server.uri(), server.uri());
        let result = registry
            .get_metadata("github.com/nonexistent/module", None)
            .await;

        match result {
            Err(RegistryError::NotFound(name)) => {
                assert_eq!(name, "github.com/nonexistent/module");
            }
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    // T-019-03: Gone (410) returns NotFound
    #[tokio::test]
    async fn gone_410_returns_not_found() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/github.com/retracted/module/@v/list"))
            .respond_with(ResponseTemplate::new(410))
            .mount(&server)
            .await;

        let registry = GoRegistry::new(server.uri(), server.uri());
        let result = registry
            .get_metadata("github.com/retracted/module", None)
            .await;

        match result {
            Err(RegistryError::NotFound(name)) => {
                assert_eq!(name, "github.com/retracted/module");
            }
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    // T-019-04: Module path encoding (uppercase → !lowercase)
    #[tokio::test]
    async fn module_path_is_encoded() {
        let server = MockServer::start().await;

        // "Azure" → "!azure" in the URL path
        Mock::given(method("GET"))
            .and(path("/github.com/!azure/go-autorest/@v/list"))
            .respond_with(ResponseTemplate::new(200).set_body_string("v14.2.0\n"))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/github.com/!azure/go-autorest/@v/v14.2.0.info"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"Version":"v14.2.0","Time":"2022-01-10T08:00:00Z"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let registry = GoRegistry::new(server.uri(), server.uri());
        let meta = registry
            .get_metadata("github.com/Azure/go-autorest", None)
            .await
            .unwrap();

        assert_eq!(meta.name, "github.com/Azure/go-autorest");
        assert_eq!(meta.version, "v14.2.0");
        // wiremock expect(1) will verify the correct encoded paths were used
    }

    // T-019-05: Empty version list returns NotFound
    #[tokio::test]
    async fn empty_version_list_returns_not_found() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/github.com/empty/module/@v/list"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        let registry = GoRegistry::new(server.uri(), server.uri());
        let result = registry.get_metadata("github.com/empty/module", None).await;

        match result {
            Err(RegistryError::NotFound(name)) => {
                assert_eq!(name, "github.com/empty/module");
            }
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    // T-019-06: Custom base URL is used
    #[tokio::test]
    async fn custom_base_url_is_used() {
        let server = MockServer::start().await;
        let custom_url = server.uri();
        assert!(
            custom_url.contains("127.0.0.1"),
            "wiremock should bind locally"
        );

        Mock::given(method("GET"))
            .and(path("/github.com/gin-gonic/gin/@v/list"))
            .respond_with(ResponseTemplate::new(200).set_body_string("v1.9.1\n"))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/github.com/gin-gonic/gin/@v/v1.9.1.info"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"Version":"v1.9.1","Time":"2023-05-01T12:00:00Z"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let registry = GoRegistry::new(custom_url, server.uri());
        let meta = registry
            .get_metadata("github.com/gin-gonic/gin", None)
            .await
            .unwrap();

        assert_eq!(meta.name, "github.com/gin-gonic/gin");
        // expect(1) on both mocks will verify the custom URL was hit
    }

    // T-019-07: Maintainers and downloads are None/empty
    #[tokio::test]
    async fn maintainers_and_downloads_are_none() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/github.com/test/module/@v/list"))
            .respond_with(ResponseTemplate::new(200).set_body_string("v1.0.0\n"))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/github.com/test/module/@v/v1.0.0.info"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"Version":"v1.0.0","Time":"2023-01-15T10:30:00Z"}"#),
            )
            .mount(&server)
            .await;

        let registry = GoRegistry::new(server.uri(), server.uri());
        let meta = registry
            .get_metadata("github.com/test/module", None)
            .await
            .unwrap();

        assert!(meta.maintainers.is_empty());
        assert!(meta.downloads.is_none());
        assert!(meta.description.is_none());
        assert!(meta.repository_url.is_none());
    }

    // Additional: encode_module_path unit test
    #[test]
    fn encode_module_path_handles_uppercase() {
        assert_eq!(
            encode_module_path("github.com/Azure/go-autorest"),
            "github.com/!azure/go-autorest"
        );
        assert_eq!(
            encode_module_path("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
        // No uppercase → unchanged
        assert_eq!(
            encode_module_path("github.com/gin-gonic/gin"),
            "github.com/gin-gonic/gin"
        );
    }

    // Additional: network error
    #[tokio::test]
    async fn network_error_returns_network_error() {
        let registry = GoRegistry::new(
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = registry.get_metadata("github.com/test/module", None).await;

        match result {
            Err(RegistryError::NetworkError(_)) => {}
            other => panic!("expected NetworkError, got {:?}", other),
        }
    }

    // Additional: JSON parse error on version info
    #[tokio::test]
    async fn malformed_version_info_returns_parse_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/github.com/test/module/@v/list"))
            .respond_with(ResponseTemplate::new(200).set_body_string("v1.0.0\n"))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/github.com/test/module/@v/v1.0.0.info"))
            .respond_with(ResponseTemplate::new(200).set_body_string("this is not json"))
            .mount(&server)
            .await;

        let registry = GoRegistry::new(server.uri(), server.uri());
        let result = registry.get_metadata("github.com/test/module", None).await;

        match result {
            Err(RegistryError::ParseError(_)) => {}
            other => panic!("expected ParseError, got {:?}", other),
        }
    }

    // Additional: specific version request skips the list call
    #[tokio::test]
    async fn fetch_specific_version_skips_list() {
        let server = MockServer::start().await;

        // No list mock — should not be called
        Mock::given(method("GET"))
            .and(path("/github.com/test/module/@v/v2.0.0.info"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"Version":"v2.0.0","Time":"2024-03-01T00:00:00Z"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let registry = GoRegistry::new(server.uri(), server.uri());
        let meta = registry
            .get_metadata("github.com/test/module", Some("v2.0.0"))
            .await
            .unwrap();

        assert_eq!(meta.version, "v2.0.0");
        assert_eq!(
            meta.published_at.unwrap().to_rfc3339(),
            "2024-03-01T00:00:00+00:00"
        );
    }

    // T-029-09: Go module h1 hash comes from the Go checksum database.
    //
    // NOTE (task 034 refactor): `GoRegistry::get_metadata` no longer fetches the
    // sumdb directly to avoid duplicate HTTP calls. The h1 hash is now extracted
    // from `GoSumDbResult::Entry` in `main.rs` via `SumDbClient` (a single fetch).
    // This test verifies that the sumdb lookup via `SumDbClient` returns the
    // correct h1 hash from the lookup response.
    #[tokio::test]
    async fn go_sumdb_client_extracts_h1_hash() {
        use crate::policy::go_sumdb::GoSumDbResult;
        use crate::registry::go_sumdb::SumDbClient;

        let sumdb_server = MockServer::start().await;

        // Full sumdb lookup body with signed note (parser requires it)
        let sum_db_body = concat!(
            "github.com/test/hashmodule v1.2.3 h1:c29zZWtyb3BlcnR5\n",
            "github.com/test/hashmodule v1.2.3/go.mod h1:AAAA\n",
            "\n",
            "go.sum database tree\n",
            "12345\n",
            "c29zZWtyb3BlcnR5\n",
            "\n",
            "\u{2014} sum.golang.org ZZZZ\n",
        );

        Mock::given(method("GET"))
            .and(path("/lookup/github.com/test/hashmodule@v1.2.3"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sum_db_body))
            .mount(&sumdb_server)
            .await;

        let client = SumDbClient::new(sumdb_server.uri());
        let result = client
            .fetch_entry("github.com/test/hashmodule", "v1.2.3")
            .await;

        match result {
            GoSumDbResult::Entry(entry) => {
                assert_eq!(
                    entry.h1_module, "h1:c29zZWtyb3BlcnR5",
                    "T-029-09: content_hash should be the h1 hash from the sum DB"
                );
            }
            other => panic!("T-029-09: expected Entry, got {:?}", other),
        }
    }
}

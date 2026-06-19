// SPDX-License-Identifier: Apache-2.0
//! Go checksum database lookup client (task 034).
//!
//! Fetches the signed lookup response from `sum.golang.org/lookup/<module>@<version>`
//! and returns a `GoSumDbResult` for use by the `GoSumDbPolicy`.
//!
//! The URL is configurable (see `go_sum_db_url` in `RegistryConfig`) so that
//! tests can point it at a wiremock server.  `GOSUMDB=off` from the
//! environment is intentionally ignored — dep-scan uses its own config knob.

use reqwest::Client;

use crate::policy::go_sumdb::{GoSumDbResult, parse_lookup_response};
use crate::registry::go::encode_module_path;

/// Client for fetching signed lookup entries from the Go checksum database.
pub struct SumDbClient {
    base_url: String,
    client: Client,
}

impl SumDbClient {
    /// Create a new `SumDbClient` with the given base URL.
    ///
    /// `base_url` is the root URL of the sumdb (e.g. `"https://sum.golang.org"`).
    /// No trailing slash.
    pub fn new(base_url: String) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            base_url,
            client: Client::new(),
        }
    }

    /// Fetch the signed lookup entry for `module@version`.
    ///
    /// Returns:
    /// - `GoSumDbResult::NotInSumDb` on 404.
    /// - `GoSumDbResult::NetworkError` on connection / HTTP error.
    /// - `GoSumDbResult::ParseError` if the body is malformed.
    /// - `GoSumDbResult::Entry(SumDbEntry)` on success.
    ///
    /// This method does NOT verify the Ed25519 signature — that is done by
    /// `GoSumDbPolicy::evaluate`.
    pub async fn fetch_entry(&self, module: &str, version: &str) -> GoSumDbResult {
        let encoded = encode_module_path(module);
        let url = format!("{}/lookup/{}@{}", self.base_url, encoded, version);

        let response = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                return GoSumDbResult::NetworkError(e.to_string());
            }
        };

        let status = response.status().as_u16();
        let body = match response.text().await {
            Ok(b) => b,
            Err(e) => {
                return GoSumDbResult::NetworkError(format!("failed to read response body: {e}"));
            }
        };

        match parse_lookup_response(status, &body, module, version) {
            Ok(None) => GoSumDbResult::NotInSumDb,
            Ok(Some(entry)) => GoSumDbResult::Entry(entry),
            Err(e) => GoSumDbResult::ParseError(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_sumdb_body(module: &str, version: &str) -> String {
        format!(
            concat!(
                "{module} {version} h1:aaaa\n",
                "{module} {version}/go.mod h1:bbbb\n",
                "\n",
                "go.sum database tree\n",
                "12345\n",
                "c29zZWtyb3BlcnR5\n",
                "\n",
                "\u{2014} sum.golang.org ZZZZ\n",
            ),
            module = module,
            version = version
        )
    }

    // T-034-02 (network): 404 returns NotInSumDb
    #[tokio::test]
    async fn fetch_entry_404_returns_not_in_sumdb() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/lookup/github.com/foo/bar@v1.2.3"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = SumDbClient::new(server.uri());
        let result = client.fetch_entry("github.com/foo/bar", "v1.2.3").await;

        assert!(
            matches!(result, GoSumDbResult::NotInSumDb),
            "404 should return NotInSumDb, got {:?}",
            result
        );
    }

    // T-034-03 (network): 500 returns NetworkError or ParseError (fail-closed)
    #[tokio::test]
    async fn fetch_entry_500_returns_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/lookup/github.com/foo/bar@v1.2.3"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&server)
            .await;

        let client = SumDbClient::new(server.uri());
        let result = client.fetch_entry("github.com/foo/bar", "v1.2.3").await;

        assert!(
            matches!(result, GoSumDbResult::ParseError(_)),
            "500 should return ParseError, got {:?}",
            result
        );
    }

    // T-034-01 (network): well-formed response returns Entry
    #[tokio::test]
    async fn fetch_entry_well_formed_returns_entry() {
        let server = MockServer::start().await;
        let body = make_sumdb_body("github.com/foo/bar", "v1.2.3");

        Mock::given(method("GET"))
            .and(path("/lookup/github.com/foo/bar@v1.2.3"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&body))
            .mount(&server)
            .await;

        let client = SumDbClient::new(server.uri());
        let result = client.fetch_entry("github.com/foo/bar", "v1.2.3").await;

        match result {
            GoSumDbResult::Entry(entry) => {
                assert_eq!(entry.h1_module, "h1:aaaa");
                assert_eq!(entry.h1_gomod, "h1:bbbb");
                assert!(entry.signed_tree_head.contains("go.sum database tree"));
            }
            other => panic!("expected Entry, got {:?}", other),
        }
    }

    // T-034-21 (network): configurable sumdb URL works
    #[tokio::test]
    async fn fetch_entry_uses_configured_url() {
        let server = MockServer::start().await;
        let body = make_sumdb_body("github.com/gin-gonic/gin", "v1.9.1");

        Mock::given(method("GET"))
            .and(path("/lookup/github.com/gin-gonic/gin@v1.9.1"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&body))
            .expect(1) // verifies the configured URL was used, not sum.golang.org
            .mount(&server)
            .await;

        let client = SumDbClient::new(server.uri());
        let result = client
            .fetch_entry("github.com/gin-gonic/gin", "v1.9.1")
            .await;

        assert!(
            matches!(result, GoSumDbResult::Entry(_)),
            "expected Entry, got {:?}",
            result
        );
        // expect(1) on the mock verifies the correct URL was contacted
    }

    // T-034-04 (network): malformed body returns ParseError
    #[tokio::test]
    async fn fetch_entry_malformed_body_returns_parse_error() {
        let server = MockServer::start().await;
        // Body has only hash lines, no signed note
        let body = "github.com/foo/bar v1.2.3 h1:aaaa\ngithub.com/foo/bar v1.2.3/go.mod h1:bbbb\n";

        Mock::given(method("GET"))
            .and(path("/lookup/github.com/foo/bar@v1.2.3"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = SumDbClient::new(server.uri());
        let result = client.fetch_entry("github.com/foo/bar", "v1.2.3").await;

        assert!(
            matches!(result, GoSumDbResult::ParseError(_)),
            "malformed body should return ParseError, got {:?}",
            result
        );
    }

    // Network error (unreachable server)
    #[tokio::test]
    async fn fetch_entry_network_error_returns_network_error() {
        let client = SumDbClient::new("http://127.0.0.1:1".to_string());
        let result = client.fetch_entry("github.com/foo/bar", "v1.2.3").await;

        assert!(
            matches!(result, GoSumDbResult::NetworkError(_)),
            "unreachable server should return NetworkError, got {:?}",
            result
        );
    }
}

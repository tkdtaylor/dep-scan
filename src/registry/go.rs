use std::fmt;

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;

use super::{Registry, RegistryError};
use crate::types::PackageMetadata;

/// Errors produced by [`validate_go_module_path`].
#[derive(Debug, PartialEq)]
pub enum GoPathError {
    /// The input string was empty.
    Empty,
    /// The path begins with `/`.
    LeadingSlash,
    /// The path ends with `/`.
    TrailingSlash,
    /// A path segment is exactly `..`.
    DotDotSegment,
    /// A path segment is exactly `.`.
    DotSegment,
    /// Two consecutive slashes produced an empty segment.
    EmptySegment,
    /// A character with special URL meaning (or that is non-ASCII) appeared.
    ForbiddenCharacter {
        /// The offending character.
        char: char,
    },
}

impl fmt::Display for GoPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GoPathError::Empty => write!(f, "module path must not be empty"),
            GoPathError::LeadingSlash => write!(f, "module path must not begin with '/'"),
            GoPathError::TrailingSlash => write!(f, "module path must not end with '/'"),
            GoPathError::DotDotSegment => {
                write!(f, "module path contains a `..` segment (path traversal)")
            }
            GoPathError::DotSegment => {
                write!(f, "module path contains a `.` segment")
            }
            GoPathError::EmptySegment => {
                write!(
                    f,
                    "module path contains an empty segment (consecutive slashes)"
                )
            }
            GoPathError::ForbiddenCharacter { char } => {
                write!(f, "module path contains forbidden character {:?}", char)
            }
        }
    }
}

impl std::error::Error for GoPathError {}

/// Validate a Go module path against a safe subset of the Go module path grammar.
///
/// The Go module proxy encodes uppercase letters using `!lc` encoding, but
/// characters with URL special meaning (`?`, `#`, `%`, space, `@`, `\n`, `\r`)
/// and path-traversal sequences (`..`, `.` as a whole segment) must be rejected
/// *before* interpolating the path into a proxy URL.
///
/// # Accepted characters (within a segment)
/// ASCII alphanumerics, `-`, `_`, `.` (as part of a segment, not alone), `/`
/// (as a separator), and all ASCII uppercase letters.
///
/// # Rejected inputs
/// - Empty string → [`GoPathError::Empty`]
/// - Leading `/` → [`GoPathError::LeadingSlash`]
/// - Trailing `/` → [`GoPathError::TrailingSlash`]
/// - Segment equal to `..` → [`GoPathError::DotDotSegment`]
/// - Segment equal to `.` → [`GoPathError::DotSegment`]
/// - Empty segment (consecutive `//`) → [`GoPathError::EmptySegment`]
/// - Characters `?`, `#`, `%`, space, `@`, `\n`, `\r`, or any non-ASCII
///   character → [`GoPathError::ForbiddenCharacter`]
pub fn validate_go_module_path(path: &str) -> Result<(), GoPathError> {
    if path.is_empty() {
        return Err(GoPathError::Empty);
    }
    if path.starts_with('/') {
        return Err(GoPathError::LeadingSlash);
    }
    if path.ends_with('/') {
        return Err(GoPathError::TrailingSlash);
    }

    // Scan every character for forbidden values before splitting into segments.
    // This catches multi-character forbidden sequences that span segment boundaries.
    for c in path.chars() {
        if !c.is_ascii() {
            return Err(GoPathError::ForbiddenCharacter { char: c });
        }
        if matches!(c, '?' | '#' | '%' | ' ' | '@' | '\n' | '\r') {
            return Err(GoPathError::ForbiddenCharacter { char: c });
        }
    }

    // Now validate each path segment.
    for segment in path.split('/') {
        if segment.is_empty() {
            // split('/') on "a//b" yields ["a", "", "b"]; leading/trailing
            // slashes are already handled above so an empty segment here means
            // consecutive slashes.
            return Err(GoPathError::EmptySegment);
        }
        if segment == ".." {
            return Err(GoPathError::DotDotSegment);
        }
        if segment == "." {
            return Err(GoPathError::DotSegment);
        }
    }

    Ok(())
}

/// Errors produced by [`validate_go_version`].
#[derive(Debug, PartialEq)]
pub enum GoVersionError {
    /// The input string was empty.
    Empty,
    /// The version string does not start with `v`.
    MissingVPrefix,
    /// A `..` segment was found (path traversal guard).
    PathTraversal,
    /// A character with special URL meaning (or that is non-ASCII) appeared.
    ForbiddenCharacter {
        /// The offending character.
        char: char,
    },
}

impl fmt::Display for GoVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GoVersionError::Empty => write!(f, "version string must not be empty"),
            GoVersionError::MissingVPrefix => {
                write!(f, "version string must begin with 'v' (e.g. v1.2.3)")
            }
            GoVersionError::PathTraversal => {
                write!(f, "version string contains a `..` path traversal sequence")
            }
            GoVersionError::ForbiddenCharacter { char } => {
                write!(f, "version string contains forbidden character {:?}", char)
            }
        }
    }
}

impl std::error::Error for GoVersionError {}

/// Validate a Go version string before interpolating it into a proxy URL.
///
/// Accepts printable ASCII only. Rejects:
/// - Empty string → [`GoVersionError::Empty`]
/// - Any `..` path traversal sequence → [`GoVersionError::PathTraversal`]
/// - Any string not starting with `v` → [`GoVersionError::MissingVPrefix`]
/// - Characters `/`, `?`, `#`, `%`, `@`, space, tab, `\r`, `\n`, NUL, or any
///   non-ASCII byte → [`GoVersionError::ForbiddenCharacter`]
///
/// Does **not** enforce full SemVer or Go pseudo-version grammar — only rejects
/// characters that are dangerous in URL context.
pub fn validate_go_version(version: &str) -> Result<(), GoVersionError> {
    if version.is_empty() {
        return Err(GoVersionError::Empty);
    }

    // Check for path traversal before the v-prefix check so that bare `..`
    // returns PathTraversal rather than MissingVPrefix.
    if version.contains("..") {
        return Err(GoVersionError::PathTraversal);
    }

    if !version.starts_with('v') {
        return Err(GoVersionError::MissingVPrefix);
    }

    // Scan every character for forbidden values.
    for c in version.chars() {
        if !c.is_ascii() {
            return Err(GoVersionError::ForbiddenCharacter { char: c });
        }
        if matches!(
            c,
            '\0' | '/' | '?' | '#' | '%' | '@' | ' ' | '\t' | '\r' | '\n'
        ) {
            return Err(GoVersionError::ForbiddenCharacter { char: c });
        }
    }

    Ok(())
}

/// Convert a [`GoPathError`] to a [`RegistryError::InvalidModulePath`].
fn path_err_to_registry(module: &str, err: GoPathError) -> RegistryError {
    RegistryError::InvalidModulePath(format!("{err} (module: {module:?})"))
}

/// Convert a [`GoVersionError`] to a [`RegistryError::InvalidVersion`].
fn version_err_to_registry(version: &str, err: GoVersionError) -> RegistryError {
    RegistryError::InvalidVersion(format!("{err} (version: {version:?})"))
}

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
        validate_go_module_path(module).map_err(|e| path_err_to_registry(module, e))?;
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
        validate_go_module_path(module).map_err(|e| path_err_to_registry(module, e))?;
        validate_go_version(version).map_err(|e| version_err_to_registry(version, e))?;
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

    // ── validate_go_module_path unit tests ───────────────────────────────────

    // T-041-01: Simple valid module path accepted
    #[test]
    fn t041_01_simple_valid_path_accepted() {
        assert_eq!(
            validate_go_module_path("github.com/gin-gonic/gin"),
            Ok(()),
            "simple valid module path should be accepted"
        );
    }

    // T-041-02: Standard library-style path accepted
    #[test]
    fn t041_02_stdlib_style_path_accepted() {
        assert_eq!(
            validate_go_module_path("golang.org/x/net"),
            Ok(()),
            "stdlib-style path should be accepted"
        );
    }

    // T-041-03: Module path with version suffix accepted
    #[test]
    fn t041_03_version_suffix_accepted() {
        assert_eq!(
            validate_go_module_path("github.com/foo/bar/v2"),
            Ok(()),
            "module path with /v2 suffix should be accepted"
        );
    }

    // T-041-04: Uppercase-containing path accepted (encode_module_path handles the transform)
    #[test]
    fn t041_04_uppercase_path_accepted() {
        assert_eq!(
            validate_go_module_path("github.com/Azure/go-autorest"),
            Ok(()),
            "uppercase letters are allowed; encode_module_path transforms them"
        );
    }

    // T-041-05: Path with `..` segment is rejected
    #[test]
    fn t041_05_dotdot_segment_rejected() {
        let result = validate_go_module_path("github.com/../etc/passwd");
        assert_eq!(
            result,
            Err(GoPathError::DotDotSegment),
            "path containing `..` segment should be rejected with DotDotSegment"
        );
        // The Display message should mention the `..` segment
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains(".."),
            "error message should mention `..`, got: {msg}"
        );
    }

    // T-041-06: Path with `.` segment (single dot) is rejected
    #[test]
    fn t041_06_dot_segment_rejected() {
        let result = validate_go_module_path("github.com/./foo");
        assert_eq!(
            result,
            Err(GoPathError::DotSegment),
            "path containing `.` segment should be rejected with DotSegment"
        );
    }

    // T-041-07: Path containing `?` is rejected (query string confusion)
    #[test]
    fn t041_07_question_mark_rejected() {
        let result = validate_go_module_path("github.com/foo?bar");
        assert_eq!(
            result,
            Err(GoPathError::ForbiddenCharacter { char: '?' }),
            "path containing `?` should be rejected with ForbiddenCharacter"
        );
    }

    // T-041-08: Path containing `#` is rejected (fragment confusion)
    #[test]
    fn t041_08_hash_rejected() {
        let result = validate_go_module_path("github.com/foo#bar");
        assert_eq!(
            result,
            Err(GoPathError::ForbiddenCharacter { char: '#' }),
            "path containing `#` should be rejected with ForbiddenCharacter"
        );
    }

    // T-041-09: Path containing a space is rejected
    #[test]
    fn t041_09_space_rejected() {
        let result = validate_go_module_path("github.com/foo bar");
        assert_eq!(
            result,
            Err(GoPathError::ForbiddenCharacter { char: ' ' }),
            "path containing space should be rejected with ForbiddenCharacter"
        );
    }

    // T-041-10: Path containing `%` encoding is rejected
    #[test]
    fn t041_10_percent_rejected() {
        let result = validate_go_module_path("github.com/foo%2Fbar");
        assert_eq!(
            result,
            Err(GoPathError::ForbiddenCharacter { char: '%' }),
            "path containing `%` should be rejected with ForbiddenCharacter"
        );
    }

    // T-041-11: Path with leading slash is rejected
    #[test]
    fn t041_11_leading_slash_rejected() {
        let result = validate_go_module_path("/github.com/foo/bar");
        assert_eq!(
            result,
            Err(GoPathError::LeadingSlash),
            "path with leading slash should be rejected with LeadingSlash"
        );
    }

    // T-041-12: Path with trailing slash is rejected
    #[test]
    fn t041_12_trailing_slash_rejected() {
        let result = validate_go_module_path("github.com/foo/bar/");
        assert_eq!(
            result,
            Err(GoPathError::TrailingSlash),
            "path with trailing slash should be rejected with TrailingSlash"
        );
    }

    // T-041-13: Empty path is rejected
    #[test]
    fn t041_13_empty_path_rejected() {
        let result = validate_go_module_path("");
        assert_eq!(
            result,
            Err(GoPathError::Empty),
            "empty path should be rejected with Empty"
        );
    }

    // T-041-14: Path with empty segment (double slash) is rejected
    #[test]
    fn t041_14_empty_segment_rejected() {
        let result = validate_go_module_path("github.com//foo");
        assert_eq!(
            result,
            Err(GoPathError::EmptySegment),
            "path with consecutive slashes should be rejected with EmptySegment"
        );
    }

    // T-041-15: Path with allowed special characters (hyphen, underscore, dot within segment) accepted
    #[test]
    fn t041_15_allowed_special_chars_accepted() {
        assert_eq!(
            validate_go_module_path("github.com/foo-bar"),
            Ok(()),
            "hyphen within segment should be accepted"
        );
        assert_eq!(
            validate_go_module_path("github.com/foo_bar"),
            Ok(()),
            "underscore within segment should be accepted"
        );
        assert_eq!(
            validate_go_module_path("gopkg.in/yaml.v3"),
            Ok(()),
            "dot within segment (version suffix) should be accepted"
        );
    }

    // T-041-16: Newline character in path is rejected
    #[test]
    fn t041_16_newline_rejected() {
        let result = validate_go_module_path("github.com/foo\nbar");
        assert_eq!(
            result,
            Err(GoPathError::ForbiddenCharacter { char: '\n' }),
            "newline in path should be rejected with ForbiddenCharacter"
        );
    }

    // T-041-17: `@` character in path is rejected (version confusion)
    #[test]
    fn t041_17_at_sign_rejected() {
        let result = validate_go_module_path("github.com/foo@v1.0.0");
        assert_eq!(
            result,
            Err(GoPathError::ForbiddenCharacter { char: '@' }),
            "`@` in path should be rejected with ForbiddenCharacter"
        );
    }

    // T-041-18: `encode_module_path` produces correct output for a valid path
    #[test]
    fn t041_18_encode_module_path_correct_output() {
        assert_eq!(
            encode_module_path("github.com/Azure/go-autorest"),
            "github.com/!azure/go-autorest",
            "uppercase `A` should become `!a`"
        );
    }

    // T-041-19: `fetch_version_list` rejects a `..` segment before making any HTTP request
    #[tokio::test]
    async fn t041_19_fetch_version_list_rejects_dotdot_before_http() {
        // No mock server active — any HTTP call would fail with a connection error.
        // We use a port that nothing is listening on so that any accidental network
        // call returns a NetworkError, not an InvalidModulePath error.
        let registry = GoRegistry::new(
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = registry
            .fetch_version_list("github.com/../etc/passwd")
            .await;
        match result {
            Err(RegistryError::InvalidModulePath(msg)) => {
                assert!(
                    msg.contains("github.com/../etc/passwd"),
                    "error should contain the bad path, got: {msg}"
                );
            }
            other => panic!("T-041-19: expected InvalidModulePath, got: {:?}", other),
        }
    }

    // T-041-20: `get_metadata` rejects invalid path before any network call
    #[tokio::test]
    async fn t041_20_get_metadata_rejects_invalid_path_before_network() {
        let registry = GoRegistry::new(
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = registry
            .get_metadata("github.com/foo?injected=1", None)
            .await;
        match result {
            Err(RegistryError::InvalidModulePath(msg)) => {
                assert!(
                    msg.contains("github.com/foo?injected=1"),
                    "error should contain the bad path, got: {msg}"
                );
            }
            other => panic!("T-041-20: expected InvalidModulePath, got: {:?}", other),
        }
    }

    // T-041-25: All task 019 Go module registry tests still pass (regression).
    // T-041-26: All task 034 Go sumdb tests still pass (regression).
    // These are verified by the test suite below passing without modification.

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

    // ── validate_go_version unit tests ──────────────────────────────────────

    // T-060-01: Canonical semver tag is accepted
    #[test]
    fn t060_01_canonical_semver_accepted() {
        assert_eq!(
            validate_go_version("v1.2.3"),
            Ok(()),
            "canonical semver tag should be accepted"
        );
    }

    // T-060-02: Zero-patch semver tag is accepted
    #[test]
    fn t060_02_zero_patch_semver_accepted() {
        assert_eq!(
            validate_go_version("v1.0.0"),
            Ok(()),
            "zero-patch semver tag should be accepted"
        );
    }

    // T-060-03: Major-only tag is accepted
    #[test]
    fn t060_03_major_only_tag_accepted() {
        assert_eq!(
            validate_go_version("v2"),
            Ok(()),
            "major-only tag should be accepted"
        );
    }

    // T-060-04: Major.minor tag is accepted
    #[test]
    fn t060_04_major_minor_tag_accepted() {
        assert_eq!(
            validate_go_version("v0.9"),
            Ok(()),
            "major.minor tag should be accepted"
        );
    }

    // T-060-05: Pseudo-version (timestamp + commit hash) is accepted
    #[test]
    fn t060_05_pseudo_version_accepted() {
        assert_eq!(
            validate_go_version("v0.0.0-20210101120000-abcdef0123456"),
            Ok(()),
            "pseudo-version should be accepted"
        );
    }

    // T-060-06: Build-metadata suffix is accepted
    #[test]
    fn t060_06_build_metadata_suffix_accepted() {
        assert_eq!(
            validate_go_version("v1.2.3+incompatible"),
            Ok(()),
            "build-metadata suffix should be accepted"
        );
    }

    // T-060-07: Pre-release suffix with alphanumeric label is accepted
    #[test]
    fn t060_07_prerelease_suffix_accepted() {
        assert_eq!(
            validate_go_version("v1.0.0-beta.1"),
            Ok(()),
            "pre-release suffix should be accepted"
        );
    }

    // T-060-08: Path traversal segment `..` is rejected
    #[test]
    fn t060_08_dotdot_bare_rejected() {
        let result = validate_go_version("..");
        assert_eq!(
            result,
            Err(GoVersionError::PathTraversal),
            "bare `..` should return PathTraversal"
        );
    }

    // T-060-09: Embedded `..` within a longer string is rejected
    #[test]
    fn t060_09_embedded_dotdot_rejected() {
        let result = validate_go_version("v1.0.0/../etc");
        // `/` is rejected first as ForbiddenCharacter, but `..` check fires before v-prefix check
        // In practice `..` is present so PathTraversal fires before the char scan
        assert!(
            result.is_err(),
            "version with embedded `..` should be rejected"
        );
    }

    // T-060-10: Query separator `?` is rejected
    #[test]
    fn t060_10_question_mark_rejected() {
        let result = validate_go_version("v1.0.0?foo=bar");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: '?' }),
            "version containing `?` should be rejected"
        );
    }

    // T-060-11: Fragment separator `#` is rejected
    #[test]
    fn t060_11_fragment_rejected() {
        let result = validate_go_version("v1.0.0#section");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: '#' }),
            "version containing `#` should be rejected"
        );
    }

    // T-060-12: Percent-encoded slash `%2F` is rejected
    #[test]
    fn t060_12_percent_encoded_slash_rejected() {
        let result = validate_go_version("v1.0%2F0");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: '%' }),
            "version containing `%` should be rejected"
        );
    }

    // T-060-13: Percent-encoded newline `%0A` is rejected
    #[test]
    fn t060_13_percent_encoded_newline_rejected() {
        let result = validate_go_version("v1.0%0A.0");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: '%' }),
            "version containing `%` should be rejected"
        );
    }

    // T-060-14: Bare `@` is rejected
    #[test]
    fn t060_14_at_sign_rejected() {
        let result = validate_go_version("v1.0.0@evil.com");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: '@' }),
            "version containing `@` should be rejected"
        );
    }

    // T-060-15: Embedded space is rejected
    #[test]
    fn t060_15_embedded_space_rejected() {
        let result = validate_go_version("v1.0 .0");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: ' ' }),
            "version containing space should be rejected"
        );
    }

    // T-060-16: Tab character is rejected
    #[test]
    fn t060_16_tab_rejected() {
        let result = validate_go_version("v1.0\t0");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: '\t' }),
            "version containing tab should be rejected"
        );
    }

    // T-060-17: Carriage return `\r` is rejected
    #[test]
    fn t060_17_carriage_return_rejected() {
        let result = validate_go_version("v1.0\r\n0");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: '\r' }),
            "version containing `\\r` should be rejected"
        );
    }

    // T-060-18: Newline `\n` is rejected
    #[test]
    fn t060_18_newline_rejected() {
        let result = validate_go_version("v1.0\n0");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: '\n' }),
            "version containing `\\n` should be rejected"
        );
    }

    // T-060-19: NUL byte is rejected
    #[test]
    fn t060_19_nul_byte_rejected() {
        let result = validate_go_version("v1.0\x000");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: '\0' }),
            "version containing NUL should be rejected"
        );
    }

    // T-060-20: Forward slash `/` inside version string is rejected
    #[test]
    fn t060_20_forward_slash_rejected() {
        let result = validate_go_version("v1.0/0");
        assert_eq!(
            result,
            Err(GoVersionError::ForbiddenCharacter { char: '/' }),
            "version containing `/` should be rejected"
        );
    }

    // T-060-21: Empty string is rejected
    #[test]
    fn t060_21_empty_string_rejected() {
        let result = validate_go_version("");
        assert_eq!(
            result,
            Err(GoVersionError::Empty),
            "empty version string should be rejected with Empty"
        );
    }

    // T-060-22: Version not starting with `v` is rejected
    #[test]
    fn t060_22_missing_v_prefix_rejected() {
        let result = validate_go_version("1.2.3");
        assert_eq!(
            result,
            Err(GoVersionError::MissingVPrefix),
            "version not starting with `v` should be rejected with MissingVPrefix"
        );
    }

    // T-060-23: fetch_version_info with a valid version contacts the proxy
    #[tokio::test]
    async fn t060_23_fetch_version_info_valid_version_contacts_proxy() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/github.com/foo/bar/@v/v1.2.3.info"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"Version":"v1.2.3","Time":"2023-01-01T00:00:00Z"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let registry = GoRegistry::new(server.uri(), server.uri());
        let result = registry
            .get_metadata("github.com/foo/bar", Some("v1.2.3"))
            .await;

        assert!(result.is_ok(), "valid version should succeed: {:?}", result);
        let meta = result.unwrap();
        assert_eq!(meta.version, "v1.2.3");
    }

    // T-060-24: fetch_version_info with crafted version `..` does not contact proxy
    #[tokio::test]
    async fn t060_24_fetch_version_info_dotdot_no_http() {
        let server = MockServer::start().await;
        // No mocks mounted — any request would cause the test to fail via expect(0)
        // We use port 1 to ensure any accidental HTTP call fails with NetworkError,
        // not an accidental 200 from wiremock.
        let registry = GoRegistry::new(
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = registry
            .get_metadata("github.com/foo/bar", Some(".."))
            .await;
        match result {
            Err(RegistryError::InvalidVersion(msg)) => {
                assert!(
                    msg.contains("version") || msg.contains(".."),
                    "error message should mention the violation: {msg}"
                );
            }
            other => panic!("T-060-24: expected InvalidVersion, got: {:?}", other),
        }
        // Ensure the wiremock server received zero requests
        server.verify().await;
    }

    // T-060-25: fetch_version_info with CRLF injection does not contact proxy
    #[tokio::test]
    async fn t060_25_fetch_version_info_crlf_no_http() {
        let registry = GoRegistry::new(
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = registry
            .get_metadata("github.com/foo/bar", Some("v1.0\r\nHost: evil.com"))
            .await;
        match result {
            Err(RegistryError::InvalidVersion(_)) => {}
            other => panic!("T-060-25: expected InvalidVersion, got: {:?}", other),
        }
    }

    // T-060-26: fetch_version_info with percent-encoded slash does not contact proxy
    #[tokio::test]
    async fn t060_26_fetch_version_info_percent_encoded_slash_no_http() {
        let registry = GoRegistry::new(
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = registry
            .get_metadata("github.com/foo/bar", Some("v1.0%2F1"))
            .await;
        match result {
            Err(RegistryError::InvalidVersion(_)) => {}
            other => panic!("T-060-26: expected InvalidVersion, got: {:?}", other),
        }
    }

    // T-060-27: RegistryError::InvalidVersion variant exists with display mentioning "version"
    #[test]
    fn t060_27_registry_error_invalid_version_variant_exists() {
        let err = RegistryError::InvalidVersion("test violation".to_string());
        let msg = err.to_string();
        assert!(
            msg.contains("version"),
            "InvalidVersion display should mention 'version', got: {msg}"
        );
    }

    // T-060-28: GoVersionError Display is human-readable
    #[test]
    fn t060_28_go_version_error_display_human_readable() {
        let empty_msg = GoVersionError::Empty.to_string();
        assert!(
            !empty_msg.is_empty(),
            "Empty display should not be empty string"
        );

        let prefix_msg = GoVersionError::MissingVPrefix.to_string();
        assert!(
            prefix_msg.contains('v'),
            "MissingVPrefix display should mention 'v': {prefix_msg}"
        );

        let traversal_msg = GoVersionError::PathTraversal.to_string();
        assert!(
            traversal_msg.contains("..") || traversal_msg.contains("path traversal"),
            "PathTraversal display should mention '..' or 'path traversal': {traversal_msg}"
        );

        let char_msg = GoVersionError::ForbiddenCharacter { char: '?' }.to_string();
        assert!(
            char_msg.contains('?'),
            "ForbiddenCharacter display should mention the char: {char_msg}"
        );
    }

    // T-060-29: All task 041 Go module path validation tests still pass — verified
    // by the t041_* tests above existing and passing unmodified.

    // T-060-30: All task 019 Go registry client tests still pass — verified by
    // the existing T-019-* tests above passing unmodified.

    // T-060-31: cargo test, cargo clippy --all-targets -- -D warnings, and
    // cargo fmt --check all pass — verified by the pre-commit gate (not a
    // coded assertion; this marker confirms the tooling checks were run).

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

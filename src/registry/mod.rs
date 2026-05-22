pub mod crates;
pub mod go;
pub mod npm;
pub mod npm_attestation;
pub mod pypi;

use std::fmt;
use std::str::FromStr;

use crate::types::PackageMetadata;

/// Identifies which package registry to query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryType {
    Npm,
    PyPI,
    Crates,
    Go,
}

impl fmt::Display for RegistryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryType::Npm => write!(f, "npm"),
            RegistryType::PyPI => write!(f, "pypi"),
            RegistryType::Crates => write!(f, "crates"),
            RegistryType::Go => write!(f, "go"),
        }
    }
}

/// Error returned when parsing an unknown registry type string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRegistryTypeError(String);

impl fmt::Display for ParseRegistryTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown registry type: {}", self.0)
    }
}

impl std::error::Error for ParseRegistryTypeError {}

impl FromStr for RegistryType {
    type Err = ParseRegistryTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "npm" => Ok(RegistryType::Npm),
            "pypi" => Ok(RegistryType::PyPI),
            "crates" | "crates.io" => Ok(RegistryType::Crates),
            "go" | "gomod" => Ok(RegistryType::Go),
            other => Err(ParseRegistryTypeError(other.to_string())),
        }
    }
}

/// Errors that can occur when communicating with a package registry.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The requested package (or version) was not found.
    #[error("package not found: {0}")]
    NotFound(String),

    /// The registry returned a rate-limit response.
    #[error("rate limited by registry")]
    RateLimited,

    /// A network-level error prevented communication with the registry.
    #[error("network error: {0}")]
    NetworkError(String),

    /// The registry response could not be parsed into the expected format.
    #[error("failed to parse registry response: {0}")]
    ParseError(String),
}

/// Trait for querying package metadata from a registry.
///
/// Implementations provide the concrete HTTP client logic for a specific
/// registry (npm, PyPI, etc.). The trait uses native async fn in trait
/// (stabilized in Rust 1.75+).
pub trait Registry: Send + Sync {
    /// Fetch metadata for a package, optionally at a specific version.
    ///
    /// If `version` is `None`, the registry client should return the latest version.
    fn get_metadata(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> impl std::future::Future<Output = Result<PackageMetadata, RegistryError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-004-04: RegistryType display: Npm -> "npm", PyPI -> "pypi"
    #[test]
    fn registry_type_display() {
        assert_eq!(RegistryType::Npm.to_string(), "npm");
        assert_eq!(RegistryType::PyPI.to_string(), "pypi");
    }

    // T-017-01: Display for new variants
    #[test]
    fn registry_type_display_crates_and_go() {
        assert_eq!(RegistryType::Crates.to_string(), "crates");
        assert_eq!(RegistryType::Go.to_string(), "go");
    }

    // T-004-05: RegistryError variants each have meaningful Display message
    #[test]
    fn registry_error_display_messages() {
        let not_found = RegistryError::NotFound("lodash".to_string());
        assert_eq!(not_found.to_string(), "package not found: lodash");

        let rate_limited = RegistryError::RateLimited;
        assert_eq!(rate_limited.to_string(), "rate limited by registry");

        let network_err = RegistryError::NetworkError("connection refused".to_string());
        assert_eq!(network_err.to_string(), "network error: connection refused");

        let parse_err = RegistryError::ParseError("invalid JSON".to_string());
        assert_eq!(
            parse_err.to_string(),
            "failed to parse registry response: invalid JSON"
        );
    }

    // T-004-06: RegistryType from string parsing
    #[test]
    fn registry_type_from_str() {
        assert_eq!("npm".parse::<RegistryType>(), Ok(RegistryType::Npm));
        assert_eq!("pypi".parse::<RegistryType>(), Ok(RegistryType::PyPI));
        // Case-insensitive
        assert_eq!("NPM".parse::<RegistryType>(), Ok(RegistryType::Npm));
        assert_eq!("PyPI".parse::<RegistryType>(), Ok(RegistryType::PyPI));
        // Invalid
        let err = "invalid".parse::<RegistryType>();
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err().to_string(),
            "unknown registry type: invalid"
        );
    }

    // T-017-02: FromStr for new variants
    #[test]
    fn registry_type_from_str_crates_and_go() {
        assert_eq!("crates".parse::<RegistryType>(), Ok(RegistryType::Crates));
        assert_eq!(
            "crates.io".parse::<RegistryType>(),
            Ok(RegistryType::Crates)
        );
        assert_eq!("go".parse::<RegistryType>(), Ok(RegistryType::Go));
        assert_eq!("gomod".parse::<RegistryType>(), Ok(RegistryType::Go));
        // Case insensitive
        assert_eq!("CRATES".parse::<RegistryType>(), Ok(RegistryType::Crates));
        assert_eq!(
            "CRATES.IO".parse::<RegistryType>(),
            Ok(RegistryType::Crates)
        );
        assert_eq!("Go".parse::<RegistryType>(), Ok(RegistryType::Go));
        assert_eq!("GOMOD".parse::<RegistryType>(), Ok(RegistryType::Go));
    }

    // T-017-03: Existing variants still work
    #[test]
    fn registry_type_existing_variants_still_work() {
        assert_eq!("npm".parse::<RegistryType>(), Ok(RegistryType::Npm));
        assert_eq!("pypi".parse::<RegistryType>(), Ok(RegistryType::PyPI));
    }

    // T-017-07: PartialEq works for all variants
    #[test]
    fn registry_type_partial_eq() {
        assert_eq!(RegistryType::Crates, RegistryType::Crates);
        assert_eq!(RegistryType::Go, RegistryType::Go);
        assert_ne!(RegistryType::Go, RegistryType::Npm);
        assert_ne!(RegistryType::Crates, RegistryType::PyPI);
    }
}

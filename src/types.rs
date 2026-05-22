use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Information about a known vulnerability affecting a package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilityInfo {
    /// Vulnerability identifier (e.g. CVE-2024-XXXX, GHSA-XXXX).
    pub id: String,
    /// Human-readable summary of the vulnerability.
    pub summary: Option<String>,
    /// Severity level (e.g. "critical", "high", "medium", "low").
    pub severity: Option<String>,
    /// Alternative identifiers for the same vulnerability.
    pub aliases: Vec<String>,
    /// Versions in which the vulnerability is fixed.
    pub fixed_versions: Vec<String>,
}

/// An install script found in a package (e.g. npm preinstall, postinstall).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstallScript {
    /// Script hook name (e.g. "preinstall", "postinstall").
    pub name: String,
    /// The script content.
    pub content: String,
}

/// Enriched scan context passed to all policies.
///
/// Wraps the core `PackageMetadata` with additional data gathered during
/// the scanning pipeline (vulnerabilities, install scripts, maintainer
/// history, etc.). Every policy receives the same `ScanContext`.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Enrichment fields used by upcoming policies (vulnerability, scripts, maintainer)
pub struct ScanContext {
    /// Core package metadata from the registry.
    pub metadata: PackageMetadata,
    /// Known vulnerabilities affecting this package version.
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    /// Install scripts found in the package.
    pub install_scripts: Vec<InstallScript>,
    /// Previous maintainers, if maintainer history is available.
    pub previous_maintainers: Option<Vec<String>>,
    /// Pre-fetched npm provenance attestation bundles (task 032).
    ///
    /// `None` means the attestation endpoint was not queried (e.g. non-npm package
    /// or the npm_provenance policy is disabled).
    /// `Some(vec![])` means the endpoint returned 404 (no attestations published).
    /// `Some(bundles)` contains one or more parsed attestation bundles.
    pub npm_attestations: Option<Vec<crate::registry::npm_attestation::AttestationBundle>>,
    /// Network or parse error that occurred while fetching attestations, if any.
    ///
    /// When set, the provenance policy must surface this as an error rather
    /// than silently treating it as "no attestations".
    pub npm_attestation_fetch_error: Option<String>,
    /// Pre-fetched PyPI provenance attestation bundle (task 033 — PEP 740).
    ///
    /// `None` means the provenance URL was not queried (e.g. non-PyPI package
    /// or the pypi_provenance policy is disabled).
    /// `Some(None)` means no provenance attestation was published for this file.
    /// `Some(Some(bundle))` contains the parsed attestation bundle.
    pub pypi_attestation: Option<Option<crate::registry::npm_attestation::AttestationBundle>>,
    /// Network or parse error that occurred while fetching the PyPI provenance
    /// attestation, if any.
    ///
    /// When set, the provenance policy must surface this as a Block (fail-closed).
    pub pypi_provenance_fetch_error: Option<String>,
    /// Verified Fulcio OIDC subject identity from a valid npm or PyPI provenance
    /// attestation, populated by `main.rs` after policy evaluation for
    /// persisting to `scanned_packages.provenance_identity`.
    pub provenance_identity: Option<String>,
}

impl ScanContext {
    /// Create a `ScanContext` from metadata with empty enrichment fields.
    pub fn from_metadata(metadata: PackageMetadata) -> Self {
        Self {
            metadata,
            vulnerabilities: Vec::new(),
            install_scripts: Vec::new(),
            previous_maintainers: None,
            npm_attestations: None,
            npm_attestation_fetch_error: None,
            pypi_attestation: None,
            pypi_provenance_fetch_error: None,
            provenance_identity: None,
        }
    }
}

/// Metadata about a package retrieved from a registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackageMetadata {
    /// The package name (e.g. "lodash", "requests").
    pub name: String,

    /// The resolved version string (e.g. "4.17.21").
    pub version: String,

    /// Human-readable description of the package.
    pub description: Option<String>,

    /// When this version was published to the registry.
    pub published_at: Option<DateTime<Utc>>,

    /// List of maintainer usernames or emails.
    pub maintainers: Vec<String>,

    /// Total download count (interpretation varies by registry).
    pub downloads: Option<u64>,

    /// URL of the source repository (e.g. GitHub link).
    pub repository_url: Option<String>,

    /// Registry-published content digest, formatted as `<algo>:<hex>` (e.g. `sha512:<hex>`).
    ///
    /// Populated from the registry's own published digest at scan time:
    /// - npm: `dist.integrity` (preferred, SRI base64→hex) or `dist.shasum` fallback
    /// - PyPI: `digests.sha256` of the sdist, else the first wheel
    /// - crates.io: `cksum`
    /// - Go: `h1:` hash from the checksum database
    ///
    /// `None` means no digest was available from the registry response.
    pub content_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // T-029-01: PackageMetadata.content_hash defaults to None
    #[test]
    fn content_hash_defaults_to_none() {
        let meta = PackageMetadata {
            name: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            published_at: None,
            maintainers: vec![],
            downloads: None,
            repository_url: None,
            content_hash: None,
        };
        assert!(
            meta.content_hash.is_none(),
            "content_hash should default to None"
        );
    }

    // T-004-01: PackageMetadata construction with all fields populated
    #[test]
    fn metadata_with_all_fields() {
        let published = Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap();
        let meta = PackageMetadata {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            description: Some("A modern JavaScript utility library".to_string()),
            published_at: Some(published),
            maintainers: vec!["jdalton".to_string(), "mathias".to_string()],
            downloads: Some(50_000_000),
            repository_url: Some("https://github.com/lodash/lodash".to_string()),
            content_hash: None,
        };

        assert_eq!(meta.name, "lodash");
        assert_eq!(meta.version, "4.17.21");
        assert_eq!(
            meta.description,
            Some("A modern JavaScript utility library".to_string())
        );
        assert_eq!(meta.published_at, Some(published));
        assert_eq!(meta.maintainers.len(), 2);
        assert_eq!(meta.maintainers[0], "jdalton");
        assert_eq!(meta.maintainers[1], "mathias");
        assert_eq!(meta.downloads, Some(50_000_000));
        assert_eq!(
            meta.repository_url,
            Some("https://github.com/lodash/lodash".to_string())
        );
    }

    // T-004-02: PackageMetadata with optional fields as None
    #[test]
    fn metadata_with_optional_fields_none() {
        let meta = PackageMetadata {
            name: "unknown-pkg".to_string(),
            version: "0.1.0".to_string(),
            description: None,
            published_at: None,
            maintainers: vec![],
            downloads: None,
            repository_url: None,
            content_hash: None,
        };

        assert_eq!(meta.name, "unknown-pkg");
        assert_eq!(meta.version, "0.1.0");
        assert!(meta.description.is_none());
        assert!(meta.published_at.is_none());
        assert!(meta.maintainers.is_empty());
        assert!(meta.downloads.is_none());
        assert!(meta.repository_url.is_none());
    }

    // T-004-03: PackageMetadata serialization round-trip
    #[test]
    fn metadata_serialization_round_trip() {
        let published = Utc.with_ymd_and_hms(2025, 6, 1, 8, 30, 0).unwrap();
        let original = PackageMetadata {
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            description: Some("Python HTTP for Humans".to_string()),
            published_at: Some(published),
            maintainers: vec!["kennethreitz".to_string()],
            downloads: Some(1_000_000),
            repository_url: Some("https://github.com/psf/requests".to_string()),
            content_hash: None,
        };

        let json = serde_json::to_string(&original).expect("serialize to JSON");
        let deserialized: PackageMetadata =
            serde_json::from_str(&json).expect("deserialize from JSON");

        assert_eq!(original, deserialized);
    }

    // T-010-01: ScanContext construction with minimal data
    #[test]
    fn scan_context_from_metadata_minimal() {
        let meta = PackageMetadata {
            name: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            published_at: None,
            maintainers: vec![],
            downloads: None,
            repository_url: None,
            content_hash: None,
        };

        let ctx = ScanContext::from_metadata(meta.clone());

        assert_eq!(ctx.metadata, meta);
        assert!(ctx.vulnerabilities.is_empty());
        assert!(ctx.install_scripts.is_empty());
        assert!(ctx.previous_maintainers.is_none());
    }

    // T-010-02: ScanContext construction with full enrichment
    #[test]
    fn scan_context_with_full_enrichment() {
        let published = Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap();
        let meta = PackageMetadata {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            description: Some("A modern JavaScript utility library".to_string()),
            published_at: Some(published),
            maintainers: vec!["jdalton".to_string()],
            downloads: Some(50_000_000),
            repository_url: Some("https://github.com/lodash/lodash".to_string()),
            content_hash: None,
        };

        let ctx = ScanContext {
            metadata: meta.clone(),
            vulnerabilities: vec![VulnerabilityInfo {
                id: "CVE-2021-23337".to_string(),
                summary: Some("Prototype pollution in lodash".to_string()),
                severity: Some("high".to_string()),
                aliases: vec!["GHSA-35jh-r3h4-6jhm".to_string()],
                fixed_versions: vec!["4.17.21".to_string()],
            }],
            install_scripts: vec![InstallScript {
                name: "postinstall".to_string(),
                content: "echo hello".to_string(),
            }],
            previous_maintainers: Some(vec!["old-maintainer".to_string()]),
            npm_attestations: None,
            npm_attestation_fetch_error: None,
            pypi_attestation: None,
            pypi_provenance_fetch_error: None,
            provenance_identity: None,
        };

        assert_eq!(ctx.metadata, meta);
        assert_eq!(ctx.vulnerabilities.len(), 1);
        assert_eq!(ctx.vulnerabilities[0].id, "CVE-2021-23337");
        assert_eq!(ctx.vulnerabilities[0].severity, Some("high".to_string()));
        assert_eq!(ctx.vulnerabilities[0].aliases.len(), 1);
        assert_eq!(ctx.vulnerabilities[0].fixed_versions.len(), 1);
        assert_eq!(ctx.install_scripts.len(), 1);
        assert_eq!(ctx.install_scripts[0].name, "postinstall");
        assert_eq!(ctx.install_scripts[0].content, "echo hello");
        assert_eq!(
            ctx.previous_maintainers,
            Some(vec!["old-maintainer".to_string()])
        );
    }
}

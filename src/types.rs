use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

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
        };

        let json = serde_json::to_string(&original).expect("serialize to JSON");
        let deserialized: PackageMetadata =
            serde_json::from_str(&json).expect("deserialize from JSON");

        assert_eq!(original, deserialized);
    }
}

use super::{Policy, PolicyResult};
use crate::types::ScanContext;

/// Policy that warns when a package has very few downloads.
///
/// Low download counts may indicate a newly published package with limited
/// community review, which increases supply-chain risk. This policy only
/// warns (never blocks) because not all registries provide download counts.
pub struct PopularityPolicy {
    /// Minimum number of downloads to pass without warning.
    pub min_downloads: u64,
}

impl PopularityPolicy {
    /// Create a new `PopularityPolicy` with the given minimum download threshold.
    pub fn new(min_downloads: u64) -> Self {
        Self { min_downloads }
    }
}

impl Policy for PopularityPolicy {
    fn name(&self) -> &str {
        "popularity"
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        match ctx.metadata.downloads {
            None => PolicyResult::Pass, // Not all registries provide download counts
            Some(count) if count >= self.min_downloads => PolicyResult::Pass,
            Some(count) => PolicyResult::Warn(format!(
                "Package '{}' has only {} downloads (minimum: {})",
                ctx.metadata.name, count, self.min_downloads
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PackageMetadata;

    /// Helper to build a ScanContext with a specific download count.
    fn make_context(name: &str, downloads: Option<u64>) -> ScanContext {
        let meta = PackageMetadata {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: None,
            published_at: None,
            maintainers: vec![],
            downloads,
            repository_url: None,
        };
        ScanContext::from_metadata(meta)
    }

    // T-022-01: High download count passes
    #[test]
    fn high_downloads_passes() {
        let policy = PopularityPolicy::new(1000);
        let ctx = make_context("popular-pkg", Some(1_000_000));
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-022-02: Low download count warns
    #[test]
    fn low_downloads_warns() {
        let policy = PopularityPolicy::new(1000);
        let ctx = make_context("obscure-pkg", Some(42));
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(reason) => {
                assert!(
                    reason.contains("obscure-pkg"),
                    "Warn should mention package name, got: {reason}"
                );
                assert!(
                    reason.contains("42"),
                    "Warn should mention actual download count, got: {reason}"
                );
                assert!(
                    reason.contains("1000"),
                    "Warn should mention minimum threshold, got: {reason}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-022-03: No download data passes
    #[test]
    fn no_download_data_passes() {
        let policy = PopularityPolicy::new(1000);
        let ctx = make_context("unknown-pkg", None);
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-022-04: Configurable threshold
    #[test]
    fn custom_threshold_warns() {
        let policy = PopularityPolicy::new(50);
        let ctx = make_context("low-pop-pkg", Some(42));
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Warn(_)),
            "42 downloads should warn with threshold 50"
        );
    }

    // Edge case: downloads exactly at threshold passes
    #[test]
    fn downloads_at_threshold_passes() {
        let policy = PopularityPolicy::new(1000);
        let ctx = make_context("threshold-pkg", Some(1000));
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // Edge case: zero downloads warns
    #[test]
    fn zero_downloads_warns() {
        let policy = PopularityPolicy::new(1000);
        let ctx = make_context("empty-pkg", Some(0));
        assert!(matches!(policy.evaluate(&ctx), PolicyResult::Warn(_)));
    }

    // Verify policy name
    #[test]
    fn policy_name_is_popularity() {
        let policy = PopularityPolicy::new(1000);
        assert_eq!(policy.name(), "popularity");
    }
}

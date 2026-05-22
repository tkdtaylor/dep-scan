use chrono::{TimeDelta, Utc};

use super::{Policy, PolicyResult};
use crate::types::ScanContext;

/// Policy that blocks packages published too recently.
///
/// Newly published packages have not been widely reviewed and are more likely
/// to contain malicious code injected through account takeover or typosquatting.
#[derive(Debug, Clone)]
pub struct AgePolicy {
    /// Minimum age a package must have before it is allowed.
    pub min_age: TimeDelta,
}

impl AgePolicy {
    /// Create a new `AgePolicy` with the given minimum age.
    pub fn new(min_age: TimeDelta) -> Self {
        Self { min_age }
    }
}

impl Policy for AgePolicy {
    fn name(&self) -> &str {
        "age"
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        let Some(published_at) = ctx.metadata.published_at else {
            return PolicyResult::Warn(format!(
                "Package '{}' has no published date — cannot verify age",
                ctx.metadata.name
            ));
        };

        let age = Utc::now() - published_at;

        if age >= self.min_age {
            PolicyResult::Pass
        } else {
            let age_hours = age.num_hours();
            let min_hours = self.min_age.num_hours();
            PolicyResult::Block(format!(
                "Package '{}' is only {} hours old (minimum: {} hours)",
                ctx.metadata.name, age_hours, min_hours
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};

    use super::*;
    use crate::types::PackageMetadata;

    /// Helper to build a ScanContext with a specific published_at.
    fn make_context(name: &str, published_at: Option<chrono::DateTime<Utc>>) -> ScanContext {
        let meta = PackageMetadata {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: None,
            published_at,
            maintainers: vec![],
            downloads: None,
            repository_url: None,
            content_hash: None,
        };
        ScanContext::from_metadata(meta)
    }

    // T-008-01: Package 72h old with 48h min_age -> Pass
    #[test]
    fn package_older_than_min_age_passes() {
        let policy = AgePolicy::new(TimeDelta::hours(48));
        let published = Utc::now() - TimeDelta::hours(72);
        let ctx = make_context("safe-pkg", Some(published));

        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-008-02: Package 1h old with 48h min_age -> Block with reason
    #[test]
    fn package_younger_than_min_age_is_blocked() {
        let policy = AgePolicy::new(TimeDelta::hours(48));
        let published = Utc::now() - TimeDelta::hours(1);
        let ctx = make_context("new-pkg", Some(published));

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("new-pkg"),
                    "Block reason should mention package name"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-008-03: Package exactly at 48h threshold -> Pass (>= passes)
    #[test]
    fn package_exactly_at_threshold_passes() {
        let policy = AgePolicy::new(TimeDelta::hours(48));
        let published = Utc::now() - TimeDelta::hours(48);
        let ctx = make_context("threshold-pkg", Some(published));

        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-008-04: Missing published_at -> Warn with reason
    #[test]
    fn missing_published_at_warns() {
        let policy = AgePolicy::new(TimeDelta::hours(48));
        let ctx = make_context("mystery-pkg", None);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(reason) => {
                assert!(
                    reason.contains("mystery-pkg"),
                    "Warn reason should mention package name"
                );
                assert!(
                    reason.contains("no published date") || reason.contains("missing"),
                    "Warn reason should explain the issue"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-008-05: Zero min_age, 1 second old -> Pass
    #[test]
    fn zero_min_age_passes_everything() {
        let policy = AgePolicy::new(TimeDelta::zero());
        let published = Utc::now() - TimeDelta::seconds(1);
        let ctx = make_context("brand-new-pkg", Some(published));

        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-008-06: Custom min_age=168h (1 week), 3 days old -> Block
    #[test]
    fn custom_min_age_one_week_blocks_three_day_old() {
        let policy = AgePolicy::new(TimeDelta::hours(168));
        let published = Utc::now() - TimeDelta::days(3);
        let ctx = make_context("recent-pkg", Some(published));

        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "3-day-old package should be blocked by 1-week policy"
        );
    }

    // T-008-07: Block message includes package name and actual age
    #[test]
    fn block_message_includes_name_and_age() {
        let policy = AgePolicy::new(TimeDelta::hours(48));
        let published = Utc::now() - TimeDelta::hours(1);
        let ctx = make_context("suspicious-pkg", Some(published));

        let result = policy.evaluate(&ctx);
        match result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("suspicious-pkg"),
                    "Message should include package name, got: {reason}"
                );
                assert!(
                    reason.contains("1 hours old") || reason.contains("1 hour"),
                    "Message should include actual age, got: {reason}"
                );
                assert!(
                    reason.contains("48 hours"),
                    "Message should include minimum age, got: {reason}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-010-03: AgePolicy works with ScanContext (72h old -> Pass)
    #[test]
    fn age_policy_with_scan_context_pass() {
        let policy = AgePolicy::new(TimeDelta::hours(48));
        assert_eq!(policy.name(), "age");

        let published = Utc::now() - TimeDelta::hours(72);
        let ctx = make_context("old-pkg", Some(published));
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-010-04: AgePolicy blocks via ScanContext (1h old -> Block)
    #[test]
    fn age_policy_with_scan_context_block() {
        let policy = AgePolicy::new(TimeDelta::hours(48));
        let published = Utc::now() - TimeDelta::hours(1);
        let ctx = make_context("evil-pkg", Some(published));

        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "1h-old package should be blocked by 48h policy"
        );
    }
}

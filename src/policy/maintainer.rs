use std::collections::HashSet;

use super::{Policy, PolicyResult};
use crate::types::ScanContext;

/// Policy that detects suspicious maintainer changes.
///
/// Compares the current maintainers against previously cached maintainers.
/// - First scan (no history): passes.
/// - No change: passes.
/// - Partial change (additions or removals): warns.
/// - Complete changeover (all old maintainers replaced): blocks.
pub struct MaintainerChangePolicy;

impl Policy for MaintainerChangePolicy {
    fn name(&self) -> &str {
        "maintainer_change"
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        let current = &ctx.metadata.maintainers;

        match &ctx.previous_maintainers {
            None => {
                // First scan -- no history, pass
                PolicyResult::Pass
            }
            Some(previous) => {
                let prev_set: HashSet<&str> = previous.iter().map(|s| s.as_str()).collect();
                let curr_set: HashSet<&str> = current.iter().map(|s| s.as_str()).collect();

                let added: Vec<&str> = curr_set.difference(&prev_set).copied().collect();
                let removed: Vec<&str> = prev_set.difference(&curr_set).copied().collect();

                if added.is_empty() && removed.is_empty() {
                    PolicyResult::Pass
                } else if !prev_set.is_empty() && prev_set.intersection(&curr_set).count() == 0 {
                    // Complete changeover -- all old maintainers replaced
                    PolicyResult::Block(format!(
                        "Complete maintainer changeover for '{}': removed [{}], added [{}]",
                        ctx.metadata.name,
                        removed.join(", "),
                        added.join(", ")
                    ))
                } else {
                    // Partial change
                    let mut parts = Vec::new();
                    if !added.is_empty() {
                        parts.push(format!("added [{}]", added.join(", ")));
                    }
                    if !removed.is_empty() {
                        parts.push(format!("removed [{}]", removed.join(", ")));
                    }
                    PolicyResult::Warn(format!(
                        "Maintainers of '{}' changed: {}",
                        ctx.metadata.name,
                        parts.join(", ")
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PackageMetadata, ScanContext};

    /// Helper to build a ScanContext with given maintainers and previous_maintainers.
    fn make_context(
        name: &str,
        current_maintainers: Vec<String>,
        previous: Option<Vec<String>>,
    ) -> ScanContext {
        let meta = PackageMetadata {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: None,
            published_at: None,
            maintainers: current_maintainers,
            downloads: None,
            repository_url: None,
        };
        ScanContext {
            metadata: meta,
            vulnerabilities: Vec::new(),
            install_scripts: Vec::new(),
            previous_maintainers: previous,
        }
    }

    // T-014-04: First scan (no history) passes
    #[test]
    fn first_scan_no_history_passes() {
        let policy = MaintainerChangePolicy;
        let ctx = make_context("lodash", vec!["alice".to_string(), "bob".to_string()], None);
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-014-05: No change passes
    #[test]
    fn no_change_passes() {
        let policy = MaintainerChangePolicy;
        let ctx = make_context(
            "lodash",
            vec!["alice".to_string(), "bob".to_string()],
            Some(vec!["alice".to_string(), "bob".to_string()]),
        );
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-014-06: Maintainer added warns
    #[test]
    fn maintainer_added_warns() {
        let policy = MaintainerChangePolicy;
        let ctx = make_context(
            "lodash",
            vec!["alice".to_string(), "bob".to_string()],
            Some(vec!["alice".to_string()]),
        );
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(msg) => {
                assert!(
                    msg.contains("bob"),
                    "Warn should mention added maintainer 'bob', got: {msg}"
                );
                assert!(
                    msg.contains("added"),
                    "Warn should mention 'added', got: {msg}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-014-07: Maintainer removed warns
    #[test]
    fn maintainer_removed_warns() {
        let policy = MaintainerChangePolicy;
        let ctx = make_context(
            "lodash",
            vec!["alice".to_string()],
            Some(vec!["alice".to_string(), "bob".to_string()]),
        );
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(msg) => {
                assert!(
                    msg.contains("bob"),
                    "Warn should mention removed maintainer 'bob', got: {msg}"
                );
                assert!(
                    msg.contains("removed"),
                    "Warn should mention 'removed', got: {msg}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-014-08: Complete changeover blocks
    #[test]
    fn complete_changeover_blocks() {
        let policy = MaintainerChangePolicy;
        let ctx = make_context(
            "lodash",
            vec!["charlie".to_string(), "dave".to_string()],
            Some(vec!["alice".to_string(), "bob".to_string()]),
        );
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(msg) => {
                assert!(
                    msg.contains("Complete maintainer changeover"),
                    "Block should mention complete changeover, got: {msg}"
                );
                assert!(
                    msg.contains("alice") || msg.contains("bob"),
                    "Block should mention removed maintainers, got: {msg}"
                );
                assert!(
                    msg.contains("charlie") || msg.contains("dave"),
                    "Block should mention added maintainers, got: {msg}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-014-09: Order doesn't matter (same set different order -> Pass)
    #[test]
    fn order_does_not_matter() {
        let policy = MaintainerChangePolicy;
        let ctx = make_context(
            "lodash",
            vec!["alice".to_string(), "bob".to_string()],
            Some(vec!["bob".to_string(), "alice".to_string()]),
        );
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }
}

use std::collections::HashSet;

use super::{Policy, PolicyResult};
use crate::types::ScanContext;

/// Policy that detects suspicious maintainer changes.
///
/// Compares the current maintainers against previously cached maintainers.
/// - First scan (no history): passes (or warns if `first_seen_warning` is enabled
///   and the package has zero / unknown downloads).
/// - No change: passes.
/// - Partial change (additions or removals): warns.
/// - Complete changeover (all old maintainers replaced): blocks.
pub struct MaintainerChangePolicy {
    /// When `true`, a first observation of a package with zero or unknown download
    /// count emits a `Warn` verdict rather than a silent `Pass`.  Default: `false`.
    pub first_seen_warning: bool,
}

impl Policy for MaintainerChangePolicy {
    fn name(&self) -> &str {
        "maintainer_change"
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        let current = &ctx.metadata.maintainers;

        match &ctx.previous_maintainers {
            None => {
                // First scan -- no history.
                // Optionally warn when first_seen_warning is enabled and the
                // package has zero or unknown downloads (possible day-one publish).
                if self.first_seen_warning {
                    let downloads = ctx.metadata.downloads.unwrap_or(0);
                    if downloads == 0 {
                        return PolicyResult::Warn(format!(
                            "First observation of '{}': maintainer set recorded as baseline; \
                             package has zero known downloads — verify publisher identity",
                            ctx.metadata.name
                        ));
                    }
                }
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

    /// Helper to build a ScanContext with given maintainers, previous_maintainers,
    /// and an optional download count.
    fn make_context(
        name: &str,
        current_maintainers: Vec<String>,
        previous: Option<Vec<String>>,
    ) -> ScanContext {
        make_context_with_downloads(name, current_maintainers, previous, None)
    }

    fn make_context_with_downloads(
        name: &str,
        current_maintainers: Vec<String>,
        previous: Option<Vec<String>>,
        downloads: Option<u64>,
    ) -> ScanContext {
        let meta = PackageMetadata {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: None,
            published_at: None,
            maintainers: current_maintainers,
            downloads,
            repository_url: None,
            content_hash: None,
        };
        ScanContext {
            metadata: meta,
            vulnerabilities: Vec::new(),
            install_scripts: Vec::new(),
            previous_maintainers: previous,
            git_source: None,
            npm_attestations: None,
            npm_attestation_fetch_error: None,
            pypi_attestation: None,
            pypi_provenance_fetch_error: None,
            provenance_identity: None,
            go_sumdb_result: None,
        }
    }

    /// Return a policy with first_seen_warning disabled (matches legacy behavior).
    fn default_policy() -> MaintainerChangePolicy {
        MaintainerChangePolicy {
            first_seen_warning: false,
        }
    }

    // T-048-13 regression: all T-014 maintainer tests pass with default_policy()
    // (first_seen_warning = false preserves pre-task behavior).
    // T-014-04: First scan (no history) passes
    #[test]
    fn first_scan_no_history_passes() {
        let policy = default_policy();
        let ctx = make_context("lodash", vec!["alice".to_string(), "bob".to_string()], None);
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-014-05: No change passes
    #[test]
    fn no_change_passes() {
        let policy = default_policy();
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
        let policy = default_policy();
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
        let policy = default_policy();
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
        let policy = default_policy();
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
        let policy = default_policy();
        let ctx = make_context(
            "lodash",
            vec!["alice".to_string(), "bob".to_string()],
            Some(vec!["bob".to_string(), "alice".to_string()]),
        );
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // -------------------------------------------------------------------------
    // T-048 tests — first_seen_warning feature
    // -------------------------------------------------------------------------

    // T-048-01: First scan with many downloads passes when first_seen_warning is false
    #[test]
    fn t048_01_first_scan_high_downloads_passes_when_disabled() {
        // T-048-01
        let policy = MaintainerChangePolicy {
            first_seen_warning: false,
        };
        let ctx =
            make_context_with_downloads("lodash", vec!["alice".to_string()], None, Some(1_000_000));
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-048-02: First scan with zero downloads passes when first_seen_warning is false
    #[test]
    fn t048_02_first_scan_zero_downloads_passes_when_disabled() {
        // T-048-02
        let policy = MaintainerChangePolicy {
            first_seen_warning: false,
        };
        let ctx =
            make_context_with_downloads("newpkg", vec!["attacker".to_string()], None, Some(0));
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-048-03: First scan with None downloads passes when first_seen_warning is false
    #[test]
    fn t048_03_first_scan_none_downloads_passes_when_disabled() {
        // T-048-03
        let policy = MaintainerChangePolicy {
            first_seen_warning: false,
        };
        let ctx = make_context_with_downloads("newpkg", vec!["attacker".to_string()], None, None);
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-048-04: First scan with zero downloads warns when first_seen_warning is true
    #[test]
    fn t048_04_first_scan_zero_downloads_warns_when_enabled() {
        // T-048-04
        let policy = MaintainerChangePolicy {
            first_seen_warning: true,
        };
        let ctx =
            make_context_with_downloads("typosquat", vec!["attacker".to_string()], None, Some(0));
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(msg) => {
                assert!(
                    msg.contains("first observation") || msg.contains("First observation"),
                    "Warn should mention first observation, got: {msg}"
                );
                assert!(
                    msg.contains("zero") || msg.contains("zero known downloads"),
                    "Warn should mention zero downloads, got: {msg}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-048-05: First scan with None downloads warns when first_seen_warning is true
    #[test]
    fn t048_05_first_scan_none_downloads_warns_when_enabled() {
        // T-048-05
        let policy = MaintainerChangePolicy {
            first_seen_warning: true,
        };
        let ctx =
            make_context_with_downloads("typosquat", vec!["attacker".to_string()], None, None);
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(msg) => {
                assert!(
                    msg.contains("first observation") || msg.contains("First observation"),
                    "Warn should mention first observation, got: {msg}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-048-06: First scan with non-zero downloads passes even when first_seen_warning is true
    #[test]
    fn t048_06_first_scan_nonzero_downloads_passes_when_enabled() {
        // T-048-06
        let policy = MaintainerChangePolicy {
            first_seen_warning: true,
        };
        let ctx =
            make_context_with_downloads("popular", vec!["alice".to_string()], None, Some(5_000));
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-048-07: First scan with exactly 1 download passes when first_seen_warning is true
    #[test]
    fn t048_07_first_scan_one_download_passes_when_enabled() {
        // T-048-07
        let policy = MaintainerChangePolicy {
            first_seen_warning: true,
        };
        let ctx = make_context_with_downloads("newpkg", vec!["alice".to_string()], None, Some(1));
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-048-08: Second scan (previous maintainers present) is unaffected by first_seen_warning
    #[test]
    fn t048_08_second_scan_unaffected_by_first_seen_warning() {
        // T-048-08
        let policy = MaintainerChangePolicy {
            first_seen_warning: true,
        };
        let ctx = make_context_with_downloads(
            "lodash",
            vec!["alice".to_string()],
            Some(vec!["alice".to_string()]),
            Some(0),
        );
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-048-09: Complete changeover still blocks regardless of first_seen_warning
    #[test]
    fn t048_09_complete_changeover_blocks_with_flag_enabled() {
        // T-048-09
        let policy = MaintainerChangePolicy {
            first_seen_warning: true,
        };
        let ctx = make_context_with_downloads(
            "lodash",
            vec!["mallory".to_string()],
            Some(vec!["alice".to_string()]),
            Some(0),
        );
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "Expected Block for complete changeover, got {:?}",
            result
        );
    }

    // T-048-14: cargo test, cargo clippy --all-targets -- -D warnings, and cargo fmt --check
    // all pass. Verified by pre-commit gate in CI — not a runtime assertion.
}

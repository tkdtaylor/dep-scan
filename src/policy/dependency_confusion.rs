// SPDX-License-Identifier: Apache-2.0
use super::{Policy, PolicyResult};
use crate::types::ScanContext;

/// Policy that warns when a package name matches patterns typically used for
/// internal or private packages, indicating a potential dependency confusion attack.
///
/// Dependency confusion attacks exploit the fact that public registries may serve
/// a package whose name was intended to be internal-only. An attacker publishes
/// a malicious package under the internal name, and build systems may prefer
/// the public version.
#[derive(Debug, Clone)]
pub struct DependencyConfusionPolicy {
    /// Prefixes that indicate an internal/private package name.
    pub internal_prefixes: Vec<String>,
}

impl DependencyConfusionPolicy {
    /// Create a new policy with the given internal namespace prefixes.
    pub fn new(internal_prefixes: Vec<String>) -> Self {
        Self { internal_prefixes }
    }

    /// Create a new policy with the built-in default prefixes.
    #[allow(dead_code)] // Public API used by tests; main.rs reads prefixes from config
    pub fn with_defaults() -> Self {
        Self::new(vec![
            "internal-".to_string(),
            "private-".to_string(),
            "corp-".to_string(),
        ])
    }
}

impl Policy for DependencyConfusionPolicy {
    fn name(&self) -> &str {
        "dependency_confusion"
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        // REQ-098-03: dependency-confusion compares a registry name against
        // internal namespace prefixes. A git-sourced dependency is pinned to a
        // specific repository, not resolved by name from a public registry, so the
        // confusion attack does not apply — Pass.
        if ctx.git_source.is_some() {
            return PolicyResult::Pass;
        }

        let name = &ctx.metadata.name;

        // When internal_prefixes is empty the entire check is disabled.
        if self.internal_prefixes.is_empty() {
            return PolicyResult::Pass;
        }

        // Check for scoped package patterns (@ prefix)
        if name.starts_with('@') && name.contains('/') {
            // Scoped packages like @internal/utils may indicate private scope.
            // Only warn if the scope looks internal.
            let scope = name.split('/').next().unwrap_or("");
            if scope == "@internal" || scope == "@private" || scope == "@corp" {
                return PolicyResult::Warn(format!(
                    "Package '{}' uses scope '{}' which matches an internal namespace pattern \
                     — possible dependency confusion",
                    name, scope
                ));
            }
        }

        // Check against configurable prefixes
        for prefix in &self.internal_prefixes {
            if name.starts_with(prefix.as_str()) {
                return PolicyResult::Warn(format!(
                    "Package '{}' matches internal namespace pattern '{}' \
                     — possible dependency confusion",
                    name, prefix
                ));
            }
        }

        PolicyResult::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PackageMetadata;

    /// Helper to build a ScanContext with a given package name.
    fn make_context(name: &str) -> ScanContext {
        let meta = PackageMetadata {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: None,
            published_at: None,
            maintainers: vec![],
            downloads: None,
            repository_url: None,
            content_hash: None,
        };
        ScanContext::from_metadata(meta)
    }

    // T-015-01: "internal-utils" with default prefixes -> Warn
    #[test]
    fn internal_prefix_match_warns() {
        let policy = DependencyConfusionPolicy::with_defaults();
        let ctx = make_context("internal-utils");
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(reason) => {
                assert!(
                    reason.contains("internal namespace pattern"),
                    "Warn should mention internal namespace pattern, got: {reason}"
                );
                assert!(
                    reason.contains("internal-utils"),
                    "Warn should mention the package name, got: {reason}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-015-02: "private-api-client" -> Warn
    #[test]
    fn private_prefix_match_warns() {
        let policy = DependencyConfusionPolicy::with_defaults();
        let ctx = make_context("private-api-client");
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Warn(_)),
            "Expected Warn for 'private-api-client', got {:?}",
            result
        );
    }

    // T-015-03: "lodash" -> Pass
    #[test]
    fn normal_package_passes() {
        let policy = DependencyConfusionPolicy::with_defaults();
        let ctx = make_context("lodash");
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-015-04: Custom prefixes ["acme-", "myco-"], "acme-auth" -> Warn
    #[test]
    fn custom_prefix_match_warns() {
        let policy = DependencyConfusionPolicy::new(vec!["acme-".to_string(), "myco-".to_string()]);
        let ctx = make_context("acme-auth");
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(reason) => {
                assert!(
                    reason.contains("acme-"),
                    "Warn should mention the matching prefix, got: {reason}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-015-05: Custom prefixes ["acme-"], "lodash" -> Pass
    #[test]
    fn custom_prefix_non_match_passes() {
        let policy = DependencyConfusionPolicy::new(vec!["acme-".to_string()]);
        let ctx = make_context("lodash");
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-015-06: "@internal/utils" -> Warn (scoped package)
    #[test]
    fn scoped_package_internal_warns() {
        let policy = DependencyConfusionPolicy::with_defaults();
        let ctx = make_context("@internal/utils");
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(reason) => {
                assert!(
                    reason.contains("@internal"),
                    "Warn should mention the scope, got: {reason}"
                );
                assert!(
                    reason.contains("internal namespace pattern"),
                    "Warn should mention internal namespace pattern, got: {reason}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-015-07: Empty prefix list -> Pass for anything
    #[test]
    fn empty_prefix_list_passes_everything() {
        let policy = DependencyConfusionPolicy::new(vec![]);
        let ctx = make_context("internal-utils");
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // Additional: policy name is correct
    #[test]
    fn policy_name_is_dependency_confusion() {
        let policy = DependencyConfusionPolicy::with_defaults();
        assert_eq!(policy.name(), "dependency_confusion");
    }

    // Additional: @corp scoped package warns
    #[test]
    fn scoped_package_corp_warns() {
        let policy = DependencyConfusionPolicy::with_defaults();
        let ctx = make_context("@corp/shared-lib");
        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Warn(_)),
            "Expected Warn for '@corp/shared-lib', got {:?}",
            result
        );
    }

    // Additional: @public scoped package passes (not internal scope)
    #[test]
    fn scoped_package_public_passes() {
        let policy = DependencyConfusionPolicy::with_defaults();
        let ctx = make_context("@babel/core");
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // Additional: empty prefix list also disables scope check
    #[test]
    fn empty_prefix_scoped_internal_also_passes() {
        let policy = DependencyConfusionPolicy::new(vec![]);
        let ctx = make_context("@internal/utils");
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "Empty prefix list should disable all checks including scope check"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

use super::{Policy, PolicyResult};
use crate::types::ScanContext;

/// How the mutable-ref policy responds when a git dependency is pinned to a
/// mutable ref (branch name, tag, short hash, or empty string).
///
/// Matches the `mutable_git_ref` key in the `[policies]` section of
/// `.dep-scan.toml`.  Default is `Warn` (non-regressive per ADR 002).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MutableRefSeverity {
    /// Emit a warning for mutable refs (default).
    #[default]
    Warn,
    /// Block installs that reference a mutable ref.
    Block,
    /// Disable the mutable-ref policy entirely.
    Off,
}

/// Classification of a git ref as either pinned (immutable) or mutable.
///
/// A pinned ref is exactly a 40-hex (SHA-1) or 64-hex (SHA-256) commit hash.
/// Every other value — branch names, tag names, short hashes, SemVer tags,
/// empty string — is considered mutable, because git tags can be force-pushed
/// and short hashes are non-unique.
#[derive(Debug, Clone, PartialEq)]
pub enum RefKind {
    /// A full 40-hex (SHA-1) or 64-hex (SHA-256) commit hash: immutable.
    Pinned,
    /// Anything else: mutable (branch name, tag name, short hash, empty).
    Mutable,
}

/// Classify a git ref string as `Pinned` or `Mutable`.
///
/// Returns `RefKind::Pinned` if and only if `ref_` consists of exactly 40 or
/// 64 hex characters (case-insensitive: `[0-9a-fA-F]`).  Every other value
/// (including empty string, short hashes, branch names, SemVer tags) returns
/// `RefKind::Mutable`.
pub fn classify_ref(ref_: &str) -> RefKind {
    let n = ref_.len();
    if n != 40 && n != 64 {
        return RefKind::Mutable;
    }
    if ref_.chars().all(|c| c.is_ascii_hexdigit()) {
        RefKind::Pinned
    } else {
        RefKind::Mutable
    }
}

/// Policy that warns (or blocks) when a git dependency is pinned to a mutable
/// ref rather than a full commit SHA.
///
/// This policy is a no-op for registry-sourced dependencies: if
/// `ctx.git_source` is `None`, it returns `Pass` immediately.
///
/// For git-sourced dependencies the policy inspects the ref via
/// [`classify_ref`]:
/// - `Pinned` → always `Pass`.
/// - `Mutable` → `Warn` (default), `Block` (opt-in), or `Pass` (off) based on
///   [`MutableRefSeverity`].
///
/// The check is purely over the ref string — no network calls, no filesystem
/// access.
#[derive(Debug, Clone)]
pub struct MutableRefPolicy {
    /// Severity for mutable refs.
    pub severity: MutableRefSeverity,
}

impl MutableRefPolicy {
    /// Create a new `MutableRefPolicy` with the given severity.
    pub fn new(severity: MutableRefSeverity) -> Self {
        Self { severity }
    }
}

impl Policy for MutableRefPolicy {
    fn name(&self) -> &str {
        "mutable_ref"
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        // No git source information: this is a registry dep → pass immediately.
        let Some((ref _url, ref ref_)) = ctx.git_source else {
            return PolicyResult::Pass;
        };

        // Pinned commit SHA → always pass.
        if classify_ref(ref_) == RefKind::Pinned {
            return PolicyResult::Pass;
        }

        // Mutable ref: apply severity.
        match self.severity {
            MutableRefSeverity::Off => PolicyResult::Pass,
            MutableRefSeverity::Warn => {
                let msg = if ref_.is_empty() {
                    "git dependency has no ref specified (mutable — no ref is equivalent to HEAD)"
                        .to_string()
                } else {
                    format!(
                        "git dependency uses a mutable ref '{ref_}' — pin to a full commit SHA to prevent branch-flip attacks"
                    )
                };
                PolicyResult::Warn(msg)
            }
            MutableRefSeverity::Block => {
                let msg = if ref_.is_empty() {
                    "git dependency has no ref specified (mutable — no ref is equivalent to HEAD)"
                        .to_string()
                } else {
                    format!(
                        "git dependency uses a mutable ref '{ref_}' — pin to a full commit SHA to prevent branch-flip attacks"
                    )
                };
                PolicyResult::Block(msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PackageMetadata, ScanContext};

    /// Build a `ScanContext` for a registry-sourced dependency (no git source).
    fn registry_ctx(name: &str) -> ScanContext {
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

    /// Build a `ScanContext` for a git-sourced dependency with the given ref.
    fn git_ctx(name: &str, url: &str, ref_: &str) -> ScanContext {
        let mut ctx = registry_ctx(name);
        ctx.git_source = Some((url.to_string(), ref_.to_string()));
        ctx
    }

    // --- classify_ref tests ---

    // T-094-01: 40-hex SHA-1 commit is classified as pinned
    #[test]
    fn t094_01_sha1_is_pinned() {
        assert_eq!(
            classify_ref("a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b5"),
            RefKind::Pinned,
            "T-094-01: 40-hex SHA-1 must be Pinned"
        );
    }

    // T-094-02: 64-hex SHA-256 commit is classified as pinned
    #[test]
    fn t094_02_sha256_is_pinned() {
        assert_eq!(
            classify_ref("a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b5a3b5c7d9e1f2a3b5c7d9e1f2"),
            RefKind::Pinned,
            "T-094-02: 64-hex SHA-256 must be Pinned"
        );
    }

    // T-094-03: Branch name `main` is classified as mutable
    #[test]
    fn t094_03_main_is_mutable() {
        assert_eq!(
            classify_ref("main"),
            RefKind::Mutable,
            "T-094-03: 'main' must be Mutable"
        );
    }

    // T-094-04: Branch name `master` is classified as mutable
    #[test]
    fn t094_04_master_is_mutable() {
        assert_eq!(
            classify_ref("master"),
            RefKind::Mutable,
            "T-094-04: 'master' must be Mutable"
        );
    }

    // T-094-05: Branch name with slashes `feature/my-branch` is classified as mutable
    #[test]
    fn t094_05_slash_branch_is_mutable() {
        assert_eq!(
            classify_ref("feature/my-branch"),
            RefKind::Mutable,
            "T-094-05: 'feature/my-branch' must be Mutable"
        );
    }

    // T-094-06: Short hash (7 hex chars) is classified as mutable
    #[test]
    fn t094_06_short_hash_is_mutable() {
        assert_eq!(
            classify_ref("abc1234"),
            RefKind::Mutable,
            "T-094-06: 7-char short hash must be Mutable"
        );
    }

    // T-094-07: SemVer tag `v1.2.3` is classified as mutable
    #[test]
    fn t094_07_semver_tag_is_mutable() {
        assert_eq!(
            classify_ref("v1.2.3"),
            RefKind::Mutable,
            "T-094-07: SemVer tag 'v1.2.3' must be Mutable"
        );
    }

    // T-094-08: Empty ref is classified as mutable
    #[test]
    fn t094_08_empty_ref_is_mutable() {
        assert_eq!(
            classify_ref(""),
            RefKind::Mutable,
            "T-094-08: empty ref must be Mutable"
        );
    }

    // T-094-09: 39-hex string (one char short of SHA-1) is classified as mutable
    #[test]
    fn t094_09_thirty_nine_hex_is_mutable() {
        assert_eq!(
            classify_ref("a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b"),
            RefKind::Mutable,
            "T-094-09: 39-hex string must be Mutable (only exact 40 or 64 counts as Pinned)"
        );
    }

    // T-094-10: Mixed-case hex in a 40-char string is classified as pinned
    #[test]
    fn t094_10_uppercase_sha1_is_pinned() {
        assert_eq!(
            classify_ref("A3B5C7D9E1F2A3B5C7D9E1F2A3B5C7D9E1F2A3B5"),
            RefKind::Pinned,
            "T-094-10: uppercase 40-hex string must be Pinned (case-insensitive)"
        );
    }

    // --- Policy verdict tests ---

    // T-094-11: Mutable ref produces Warn with message naming the ref
    #[test]
    fn t094_11_mutable_ref_warn_default() {
        let policy = MutableRefPolicy::new(MutableRefSeverity::Warn);
        let ctx = git_ctx("pkg", "https://github.com/user/repo", "main");
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(msg) => {
                assert!(
                    msg.contains("main"),
                    "T-094-11: Warn message must contain the ref 'main', got: {msg:?}"
                );
                assert!(
                    msg.contains("mutable"),
                    "T-094-11: Warn message must mention mutability, got: {msg:?}"
                );
            }
            other => panic!("T-094-11: Expected Warn, got {:?}", other),
        }
    }

    // T-094-12: Pinned ref produces Pass
    #[test]
    fn t094_12_pinned_ref_passes() {
        let policy = MutableRefPolicy::new(MutableRefSeverity::Warn);
        let ctx = git_ctx(
            "pkg",
            "https://github.com/user/repo",
            "a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b5",
        );
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "T-094-12: pinned 40-hex ref must produce Pass"
        );
    }

    // T-094-13: Empty ref produces Warn with message
    #[test]
    fn t094_13_empty_ref_warns_with_message() {
        let policy = MutableRefPolicy::new(MutableRefSeverity::Warn);
        let ctx = git_ctx("pkg", "https://github.com/user/repo", "");
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(msg) => {
                assert!(
                    msg.contains("no ref specified"),
                    "T-094-13: Warn message must distinguish 'no ref specified', got: {msg:?}"
                );
            }
            other => panic!("T-094-13: Expected Warn for empty ref, got {:?}", other),
        }
    }

    // T-094-14: Policy is Pass for DependencySource::Registry deps (no git source)
    #[test]
    fn t094_14_registry_dep_passes() {
        let policy = MutableRefPolicy::new(MutableRefSeverity::Warn);
        let ctx = registry_ctx("lodash");
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "T-094-14: registry dep (no git source) must produce Pass"
        );
    }

    // T-094-15: mutable_git_ref = "block" produces Block for mutable ref
    #[test]
    fn t094_15_block_mode_produces_block_for_mutable_ref() {
        let policy = MutableRefPolicy::new(MutableRefSeverity::Block);
        let ctx = git_ctx("pkg", "https://github.com/user/repo", "main");
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(msg) => {
                assert!(
                    msg.contains("main"),
                    "T-094-15: Block message must contain the ref 'main', got: {msg:?}"
                );
            }
            other => panic!(
                "T-094-15: Expected Block with block severity, got {:?}",
                other
            ),
        }
    }

    // T-094-16: mutable_git_ref = "block" still passes pinned ref
    #[test]
    fn t094_16_block_mode_passes_pinned_ref() {
        let policy = MutableRefPolicy::new(MutableRefSeverity::Block);
        let ctx = git_ctx(
            "pkg",
            "https://github.com/user/repo",
            "a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b5",
        );
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "T-094-16: block mode must still pass a pinned 40-hex ref"
        );
    }

    // T-094-17: mutable_git_ref = "warn" is the default
    #[test]
    fn t094_17_default_severity_is_warn() {
        let severity = MutableRefSeverity::default();
        assert_eq!(
            severity,
            MutableRefSeverity::Warn,
            "T-094-17: default MutableRefSeverity must be Warn"
        );
    }

    // T-094-18: mutable_git_ref = "off" disables the policy
    #[test]
    fn t094_18_off_mode_passes_everything() {
        let policy = MutableRefPolicy::new(MutableRefSeverity::Off);
        let ctx = git_ctx("pkg", "https://github.com/user/repo", "main");
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "T-094-18: 'off' mode must pass all deps including mutable refs"
        );
    }

    // Additional: Policy name is "mutable_ref"
    #[test]
    fn policy_name_is_mutable_ref() {
        let policy = MutableRefPolicy::new(MutableRefSeverity::Warn);
        assert_eq!(policy.name(), "mutable_ref");
    }
}

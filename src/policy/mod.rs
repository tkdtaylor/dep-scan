pub mod age;
pub mod install_script;

use serde::Serialize;

use crate::types::ScanContext;

/// The outcome of evaluating a policy against a scan context.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum PolicyResult {
    /// The package passes the policy check.
    Pass,
    /// The package triggers a warning but is not blocked.
    Warn(String),
    /// The package is blocked by the policy.
    Block(String),
}

/// Trait for evaluating a security policy against a scan context.
///
/// Implementations inspect already-fetched metadata and enrichment data
/// and return a synchronous verdict. No network calls should happen
/// inside `evaluate`.
pub trait Policy: Send + Sync {
    /// The short name of this policy (e.g. "age", "typosquatting").
    fn name(&self) -> &str;

    /// Evaluate the policy against the given scan context.
    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult;
}

/// Per-policy evaluation detail, suitable for JSON output.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PolicyDetail {
    /// The name of the policy that produced this result.
    pub policy_name: String,
    /// The outcome: "pass", "warn", or "block".
    pub result: String,
    /// Human-readable reason (only present for warn/block).
    pub reason: Option<String>,
}

impl PolicyDetail {
    /// Create a `PolicyDetail` from a policy name and its evaluation result.
    pub fn from_result(policy_name: &str, result: &PolicyResult) -> Self {
        let (result_str, reason) = match result {
            PolicyResult::Pass => ("pass".to_string(), None),
            PolicyResult::Warn(msg) => ("warn".to_string(), Some(msg.clone())),
            PolicyResult::Block(msg) => ("block".to_string(), Some(msg.clone())),
        };
        Self {
            policy_name: policy_name.to_string(),
            result: result_str,
            reason,
        }
    }
}

/// Aggregate multiple policy details into an overall result.
///
/// Returns the worst-case outcome and corresponding reason:
/// - If any policy blocks, the aggregate is `("block", Some(reason))`.
/// - If any policy warns (and none block), the aggregate is `("warn", Some(reason))`.
/// - If all policies pass, the aggregate is `("pass", None)`.
pub fn aggregate_results(details: &[PolicyDetail]) -> (String, Option<String>) {
    // Check for any block first
    for d in details {
        if d.result == "block" {
            return ("block".to_string(), d.reason.clone());
        }
    }
    // Then check for any warn
    for d in details {
        if d.result == "warn" {
            return ("warn".to_string(), d.reason.clone());
        }
    }
    // All pass
    ("pass".to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-010-05: PolicyDetail captures policy name and result
    #[test]
    fn policy_detail_from_pass() {
        let detail = PolicyDetail::from_result("age", &PolicyResult::Pass);
        assert_eq!(detail.policy_name, "age");
        assert_eq!(detail.result, "pass");
        assert!(detail.reason.is_none());
    }

    #[test]
    fn policy_detail_from_block() {
        let detail = PolicyDetail::from_result(
            "age",
            &PolicyResult::Block("Package 'evil' is only 1 hours old".to_string()),
        );
        assert_eq!(detail.policy_name, "age");
        assert_eq!(detail.result, "block");
        assert_eq!(
            detail.reason,
            Some("Package 'evil' is only 1 hours old".to_string())
        );
    }

    #[test]
    fn policy_detail_from_warn() {
        let detail =
            PolicyDetail::from_result("age", &PolicyResult::Warn("No published date".to_string()));
        assert_eq!(detail.policy_name, "age");
        assert_eq!(detail.result, "warn");
        assert_eq!(detail.reason, Some("No published date".to_string()));
    }

    // T-010-06: Aggregate results — all pass returns pass
    #[test]
    fn aggregate_all_pass() {
        let details = vec![
            PolicyDetail {
                policy_name: "age".to_string(),
                result: "pass".to_string(),
                reason: None,
            },
            PolicyDetail {
                policy_name: "typosquatting".to_string(),
                result: "pass".to_string(),
                reason: None,
            },
            PolicyDetail {
                policy_name: "scripts".to_string(),
                result: "pass".to_string(),
                reason: None,
            },
        ];
        let (result, reason) = aggregate_results(&details);
        assert_eq!(result, "pass");
        assert!(reason.is_none());
    }

    // T-010-07: Aggregate results — any block returns block
    #[test]
    fn aggregate_any_block() {
        let details = vec![
            PolicyDetail {
                policy_name: "age".to_string(),
                result: "pass".to_string(),
                reason: None,
            },
            PolicyDetail {
                policy_name: "scripts".to_string(),
                result: "block".to_string(),
                reason: Some("malicious script detected".to_string()),
            },
            PolicyDetail {
                policy_name: "typosquatting".to_string(),
                result: "pass".to_string(),
                reason: None,
            },
        ];
        let (result, reason) = aggregate_results(&details);
        assert_eq!(result, "block");
        assert_eq!(reason, Some("malicious script detected".to_string()));
    }

    // T-010-08: Aggregate results — warn without block returns warn
    #[test]
    fn aggregate_warn_without_block() {
        let details = vec![
            PolicyDetail {
                policy_name: "age".to_string(),
                result: "pass".to_string(),
                reason: None,
            },
            PolicyDetail {
                policy_name: "scripts".to_string(),
                result: "warn".to_string(),
                reason: Some("suspicious pattern found".to_string()),
            },
            PolicyDetail {
                policy_name: "typosquatting".to_string(),
                result: "pass".to_string(),
                reason: None,
            },
        ];
        let (result, reason) = aggregate_results(&details);
        assert_eq!(result, "warn");
        assert_eq!(reason, Some("suspicious pattern found".to_string()));
    }

    // Aggregate with empty input
    #[test]
    fn aggregate_empty_input() {
        let details: Vec<PolicyDetail> = vec![];
        let (result, reason) = aggregate_results(&details);
        assert_eq!(result, "pass");
        assert!(reason.is_none());
    }

    // Block takes precedence over warn
    #[test]
    fn aggregate_block_takes_precedence_over_warn() {
        let details = vec![
            PolicyDetail {
                policy_name: "age".to_string(),
                result: "warn".to_string(),
                reason: Some("warning reason".to_string()),
            },
            PolicyDetail {
                policy_name: "scripts".to_string(),
                result: "block".to_string(),
                reason: Some("block reason".to_string()),
            },
        ];
        let (result, reason) = aggregate_results(&details);
        assert_eq!(result, "block");
        assert_eq!(reason, Some("block reason".to_string()));
    }
}

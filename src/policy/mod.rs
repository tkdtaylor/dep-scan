pub mod age;

use crate::types::PackageMetadata;

/// The outcome of evaluating a policy against package metadata.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyResult {
    /// The package passes the policy check.
    Pass,
    /// The package triggers a warning but is not blocked.
    Warn(String),
    /// The package is blocked by the policy.
    Block(String),
}

/// Trait for evaluating a security policy against package metadata.
///
/// Implementations inspect already-fetched metadata and return a synchronous
/// verdict. No network calls should happen inside `evaluate`.
pub trait Policy {
    fn evaluate(&self, metadata: &PackageMetadata) -> PolicyResult;
}

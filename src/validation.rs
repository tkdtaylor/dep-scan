//! Package name validation — guards against CLI flag injection.
//!
//! Any token supplied as a package name that begins with `-` is categorically
//! flag-like in every ecosystem dep-scan supports.  Passing such a token to
//! `npm install`, `cargo add`, `go get`, or `pip install` causes the underlying
//! tool to interpret it as a flag rather than a package name.
//!
//! This module implements a lightweight pre-flight check that runs **before**
//! any registry network call or subprocess invocation.

use std::fmt;

use crate::registry::RegistryType;

/// Errors returned by [`validate_package_name`] and [`validate_package_names`].
#[derive(Debug, PartialEq)]
pub enum ValidationError {
    /// The token starts with `-` and would be interpreted as a CLI flag by the
    /// underlying package manager.
    FlagLike {
        /// The offending token, preserved verbatim for error messages.
        token: String,
    },
    /// The token is empty or contains only whitespace.
    Empty,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::FlagLike { token } => write!(
                f,
                "invalid package name {:?}: package name must not start with '-' \
                 (this looks like a command-line flag that could redirect the \
                 underlying package manager to a hostile registry)",
                token
            ),
            ValidationError::Empty => write!(
                f,
                "invalid package name: package name must not be empty or \
                 consist only of whitespace"
            ),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate a single package name token.
///
/// # Accepted tokens
/// - Any non-empty string that does not start with `-`.
/// - Scoped npm packages (`@scope/pkg`) — the `@` prefix is not `-`.
/// - Go module paths (`github.com/foo/bar`) — the `/` and `.` are not `-`.
///
/// # Rejected tokens
/// - Tokens starting with `-` or `--` (single-dash or double-dash flag forms).
/// - Empty strings or strings that are entirely whitespace.
///
/// The `registry` parameter is accepted for API uniformity but is not currently
/// used — the leading-dash check is sufficient for all four ecosystems.
pub fn validate_package_name(name: &str, _registry: RegistryType) -> Result<(), ValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::Empty);
    }
    if name.starts_with('-') {
        return Err(ValidationError::FlagLike {
            token: name.to_string(),
        });
    }
    Ok(())
}

/// Validate a batch of package name tokens.
///
/// Iterates the slice in order and returns the first [`ValidationError`]
/// encountered.  The entire batch is rejected — no partial scans of the valid
/// tokens are performed.
///
/// Returns `Ok(())` only if every token in `names` is valid.
pub fn validate_package_names(
    names: &[String],
    registry: RegistryType,
) -> Result<(), ValidationError> {
    for name in names {
        validate_package_name(name, registry)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::RegistryType;

    // T-037-01: Leading dash rejected for all registries
    #[test]
    fn flag_like_double_dash_rejected() {
        let result = validate_package_name("--registry=http://evil", RegistryType::Npm);
        assert!(
            matches!(
                result,
                Err(ValidationError::FlagLike { ref token }) if token == "--registry=http://evil"
            ),
            "expected FlagLike error, got: {:?}",
            result
        );
        // The display message must mention "must not start with '-'"
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("package name must not start with '-'"),
            "error message missing expected text, got: {msg}"
        );
        // Verbatim token must appear in the message
        assert!(
            msg.contains("--registry=http://evil"),
            "error message should contain the bad token verbatim, got: {msg}"
        );
    }

    // T-037-02: Single-dash prefix rejected
    #[test]
    fn flag_like_single_dash_rejected() {
        let result = validate_package_name("-i", RegistryType::Npm);
        assert!(
            matches!(
                result,
                Err(ValidationError::FlagLike { ref token }) if token == "-i"
            ),
            "expected FlagLike {{token: \"-i\"}}, got: {:?}",
            result
        );
    }

    // T-037-03: Legitimate npm package accepted
    #[test]
    fn npm_package_express_accepted() {
        assert_eq!(
            validate_package_name("express", RegistryType::Npm),
            Ok(()),
            "plain npm package name should be accepted"
        );
    }

    // T-037-04: Scoped npm package accepted
    #[test]
    fn npm_scoped_package_accepted() {
        assert_eq!(
            validate_package_name("@babel/core", RegistryType::Npm),
            Ok(()),
            "scoped npm package @babel/core should be accepted"
        );
    }

    // T-037-05: Legitimate crates name accepted
    #[test]
    fn crates_package_serde_json_accepted() {
        assert_eq!(
            validate_package_name("serde_json", RegistryType::Crates),
            Ok(()),
            "crates package serde_json should be accepted"
        );
    }

    // T-037-06: Legitimate Go module path accepted
    #[test]
    fn go_module_path_accepted() {
        assert_eq!(
            validate_package_name("github.com/gin-gonic/gin", RegistryType::Go),
            Ok(()),
            "Go module path github.com/gin-gonic/gin should be accepted"
        );
    }

    // T-037-07: Empty string rejected
    #[test]
    fn empty_string_rejected() {
        let result = validate_package_name("", RegistryType::Npm);
        assert_eq!(
            result,
            Err(ValidationError::Empty),
            "empty string should be rejected with ValidationError::Empty"
        );
    }

    // T-037-08: Whitespace-only string rejected
    #[test]
    fn whitespace_only_rejected() {
        let result = validate_package_name("   ", RegistryType::Npm);
        assert!(
            result.is_err(),
            "whitespace-only string should be rejected, got: {:?}",
            result
        );
    }

    // T-037-09: Multiple packages — one bad token rejects the entire batch
    #[test]
    fn batch_rejects_on_first_bad_token() {
        let names = vec![
            "express".to_string(),
            "--global".to_string(),
            "lodash".to_string(),
        ];
        let result = validate_package_names(&names, RegistryType::Npm);
        assert!(
            matches!(
                result,
                Err(ValidationError::FlagLike { ref token }) if token == "--global"
            ),
            "expected FlagLike for '--global', got: {:?}",
            result
        );
    }

    // Additional: verify all four registries reject the same leading-dash token
    #[test]
    fn flag_rejected_across_all_registries() {
        for registry in [
            RegistryType::Npm,
            RegistryType::PyPI,
            RegistryType::Crates,
            RegistryType::Go,
        ] {
            let result = validate_package_name("--evil", registry);
            assert!(
                result.is_err(),
                "expected rejection for '--evil' on {registry}, got Ok"
            );
        }
    }

    // T-037-16: Error message includes the bad token verbatim
    #[test]
    fn error_message_contains_bad_token_verbatim() {
        let token = "--config-settings=build_backend=foo";
        let result = validate_package_name(token, RegistryType::PyPI);
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains(token),
            "error message should contain the token verbatim: {msg}"
        );
    }
}

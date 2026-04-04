use regex::Regex;

use super::{Policy, PolicyResult};
use crate::types::ScanContext;

/// Severity level for a detected obfuscation pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    /// Medium severity — generates a warning.
    Warn,
    /// High severity — blocks installation.
    Block,
}

/// A suspicious obfuscation pattern to look for in install scripts.
struct ObfuscationPattern {
    /// Human-readable name of the pattern.
    name: &'static str,
    /// The detection method for this pattern.
    detection: ObfuscationDetection,
    /// Severity level of the pattern.
    severity: Severity,
}

/// How an obfuscation pattern is detected in script content.
enum ObfuscationDetection {
    /// Simple substring match using `.contains()`.
    Contains(&'static str),
    /// Regular expression match (compiled lazily).
    Regex(&'static str),
}

/// Policy that analyzes install scripts for obfuscation patterns.
///
/// Detects encoded/hidden payloads such as long base64 strings, hex escape
/// chains, unicode escape chains, `fromCharCode` usage, `chr()` chains,
/// and string concatenation tricks used to build URLs or access env vars.
///
/// This is separate from `InstallScriptPolicy`, which focuses on dangerous
/// APIs like `eval()` and `exec()`. Obfuscation detection focuses on
/// encoding and concealment techniques.
pub struct ObfuscationPolicy;

impl ObfuscationPolicy {
    /// Build the list of obfuscation patterns to check against.
    fn patterns() -> Vec<ObfuscationPattern> {
        vec![
            // Block patterns (strong obfuscation signals)
            ObfuscationPattern {
                name: "long_base64",
                detection: ObfuscationDetection::Regex(r"[A-Za-z0-9+/=]{60,}"),
                severity: Severity::Block,
            },
            ObfuscationPattern {
                name: "hex_escape_chain",
                detection: ObfuscationDetection::Regex(r"(\\x[0-9a-fA-F]{2}){5,}"),
                severity: Severity::Block,
            },
            ObfuscationPattern {
                name: "unicode_escape_chain",
                detection: ObfuscationDetection::Regex(r"(\\u[0-9a-fA-F]{4}){4,}"),
                severity: Severity::Block,
            },
            ObfuscationPattern {
                name: "fromCharCode_chain",
                detection: ObfuscationDetection::Contains("fromCharCode"),
                severity: Severity::Block,
            },
            ObfuscationPattern {
                name: "chr_chain",
                detection: ObfuscationDetection::Regex(r"chr\(\d+\).*chr\(\d+\).*chr\(\d+\)"),
                severity: Severity::Block,
            },
            // Warn patterns (suspicious but ambiguous)
            ObfuscationPattern {
                name: "string_concat_url",
                detection: ObfuscationDetection::Regex(r#""ht"\s*\+\s*"tp"#),
                severity: Severity::Warn,
            },
            ObfuscationPattern {
                name: "env_concat",
                detection: ObfuscationDetection::Regex(r"process\.env\[.*\+"),
                severity: Severity::Warn,
            },
        ]
    }
}

impl Policy for ObfuscationPolicy {
    fn name(&self) -> &str {
        "obfuscation"
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        if ctx.install_scripts.is_empty() {
            return PolicyResult::Pass;
        }

        let patterns = Self::patterns();
        let mut worst_severity: Option<Severity> = None;
        let mut worst_message: Option<String> = None;

        for script in &ctx.install_scripts {
            for pattern in &patterns {
                let matched = match &pattern.detection {
                    ObfuscationDetection::Contains(needle) => script.content.contains(needle),
                    ObfuscationDetection::Regex(re_str) => {
                        if let Ok(re) = Regex::new(re_str) {
                            re.is_match(&script.content)
                        } else {
                            false
                        }
                    }
                };

                if matched {
                    let should_update = match worst_severity {
                        None => true,
                        Some(current) => pattern.severity > current,
                    };

                    if should_update {
                        worst_severity = Some(pattern.severity);
                        worst_message = Some(format!(
                            "Obfuscation pattern '{}' found in '{}' script of package '{}'",
                            pattern.name, script.name, ctx.metadata.name
                        ));
                    }

                    // If we already found a Block, no need to check more patterns
                    if pattern.severity == Severity::Block {
                        break;
                    }
                }
            }

            // Early exit if we've already found a Block
            if worst_severity == Some(Severity::Block) {
                break;
            }
        }

        match (worst_severity, worst_message) {
            (Some(Severity::Block), Some(msg)) => PolicyResult::Block(msg),
            (Some(Severity::Warn), Some(msg)) => PolicyResult::Warn(msg),
            _ => PolicyResult::Pass,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{InstallScript, PackageMetadata, ScanContext};

    /// Helper to create a ScanContext with the given install scripts.
    fn make_context(scripts: Vec<InstallScript>) -> ScanContext {
        let meta = PackageMetadata {
            name: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            published_at: None,
            maintainers: vec![],
            downloads: None,
            repository_url: None,
        };
        ScanContext {
            metadata: meta,
            vulnerabilities: vec![],
            install_scripts: scripts,
            previous_maintainers: None,
        }
    }

    // T-021-01: Clean script passes
    #[test]
    fn clean_script_passes() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "echo hello && npm run build".to_string(),
        }]);

        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-021-02: Long base64 string blocks
    #[test]
    fn long_base64_string_blocks() {
        let policy = ObfuscationPolicy;
        // 80-char base64 string
        let base64_payload =
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NQ==";
        assert!(base64_payload.len() >= 60);
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!("var data = '{base64_payload}';"),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("long_base64"),
                    "Block reason should mention 'long_base64', got: {reason}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-021-03: Hex escape chain blocks
    #[test]
    fn hex_escape_chain_blocks() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "preinstall".to_string(),
            content: r"\x68\x74\x74\x70\x3a\x2f\x2f".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("hex_escape_chain"),
                    "Block reason should mention 'hex_escape_chain', got: {reason}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-021-04: Unicode escape chain detected
    #[test]
    fn unicode_escape_chain_detected() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: r"\u0068\u0074\u0074\u0070".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("unicode_escape_chain"),
                    "Block reason should mention 'unicode_escape_chain', got: {reason}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-021-05: String concatenation building URL warns
    #[test]
    fn string_concat_url_warns() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: r#"var u = "ht" + "tp" + "://" + "evil" + ".com""#.to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(reason) => {
                assert!(
                    reason.contains("string_concat_url"),
                    "Warn reason should mention 'string_concat_url', got: {reason}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-021-06: fromCharCode chain blocks
    #[test]
    fn from_char_code_chain_blocks() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "String.fromCharCode(104,116,116,112)".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("fromCharCode_chain"),
                    "Block reason should mention 'fromCharCode_chain', got: {reason}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-021-07: No install scripts passes (empty)
    #[test]
    fn no_install_scripts_passes() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![]);

        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-021-08: Policy name is "obfuscation"
    #[test]
    fn policy_name_is_obfuscation() {
        let policy = ObfuscationPolicy;
        assert_eq!(policy.name(), "obfuscation");
    }

    // T-021-09: chr() chain blocks
    #[test]
    fn chr_chain_blocks() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "chr(104).chr(116).chr(116)".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("chr_chain"),
                    "Block reason should mention 'chr_chain', got: {reason}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-021-10: env_concat warns
    #[test]
    fn env_concat_warns() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: r#"process.env["HO" + "ME"]"#.to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(reason) => {
                assert!(
                    reason.contains("env_concat"),
                    "Warn reason should mention 'env_concat', got: {reason}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-021-11: Block takes precedence over warn
    #[test]
    fn block_takes_precedence_over_warn() {
        let policy = ObfuscationPolicy;
        // Script has both a long base64 (block) and a string concat URL (warn)
        let base64_payload =
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NQ==";
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!(r#"var d = "{base64_payload}"; var u = "ht" + "tp""#),
        }]);

        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "Block should take precedence over Warn, got: {:?}",
            result
        );
    }
}

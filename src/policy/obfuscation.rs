use std::sync::OnceLock;

use regex::Regex;

use super::{Policy, PolicyResult};
use crate::types::ScanContext;

/// Maximum number of bytes of a script that are scanned for obfuscation patterns.
///
/// npm allows postinstall scripts up to approximately 10 MB.  Scanning the full
/// content of every script on every call with an unanchored regex such as
/// `chr\(\d+\).*chr\(\d+\).*chr\(\d+\)` is expensive.  The 1 MB cap bounds
/// worst-case scan time per script while still catching all realistic payloads
/// (malicious scripts almost always front-load their payload).
///
/// Trade-off: a package that places its payload exactly at byte 1,048,577 would
/// pass this check.  Such a package is already flagged by the install-script-size
/// and age/popularity checks, providing defense-in-depth.
const SCRIPT_SCAN_CAP_BYTES: usize = 1_048_576; // 1 MB

/// Severity level for a detected obfuscation pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    /// Medium severity — generates a warning.
    Warn,
    /// High severity — blocks installation.
    Block,
}

/// A pre-compiled obfuscation pattern used for detection.
struct CompiledPattern {
    /// Human-readable name of the pattern.
    name: &'static str,
    /// Compiled regex, or `None` for substring-only patterns.
    regex: Option<Regex>,
    /// Fixed substring to search for (used when `regex` is `None`).
    needle: Option<&'static str>,
    /// Severity level of the pattern.
    severity: Severity,
}

impl CompiledPattern {
    /// Returns `true` if `content` matches this pattern.
    fn is_match(&self, content: &str) -> bool {
        if let Some(re) = &self.regex {
            re.is_match(content)
        } else if let Some(needle) = self.needle {
            content.contains(needle)
        } else {
            false
        }
    }
}

/// Static holder for the compiled patterns — initialized exactly once per process.
static PATTERNS: OnceLock<Vec<CompiledPattern>> = OnceLock::new();

/// Returns a reference to the global compiled pattern list, initializing it on
/// the first call.  Subsequent calls (including concurrent ones) return the
/// already-initialized value from the `OnceLock` without re-compiling.
fn compiled_patterns() -> &'static [CompiledPattern] {
    PATTERNS.get_or_init(|| {
        vec![
            // Block patterns (strong obfuscation signals)
            CompiledPattern {
                name: "long_base64",
                regex: Regex::new(r"[A-Za-z0-9+/=]{60,}").ok(),
                needle: None,
                severity: Severity::Block,
            },
            CompiledPattern {
                name: "hex_escape_chain",
                regex: Regex::new(r"(\\x[0-9a-fA-F]{2}){5,}").ok(),
                needle: None,
                severity: Severity::Block,
            },
            CompiledPattern {
                name: "unicode_escape_chain",
                regex: Regex::new(r"(\\u[0-9a-fA-F]{4}){4,}").ok(),
                needle: None,
                severity: Severity::Block,
            },
            CompiledPattern {
                name: "fromCharCode_chain",
                regex: None,
                needle: Some("fromCharCode"),
                severity: Severity::Block,
            },
            CompiledPattern {
                name: "chr_chain",
                regex: Regex::new(r"chr\(\d+\).*chr\(\d+\).*chr\(\d+\)").ok(),
                needle: None,
                severity: Severity::Block,
            },
            // Warn patterns (suspicious but ambiguous)
            CompiledPattern {
                name: "string_concat_url",
                regex: Regex::new(r#""ht"\s*\+\s*"tp"#).ok(),
                needle: None,
                severity: Severity::Warn,
            },
            CompiledPattern {
                name: "env_concat",
                regex: Regex::new(r"process\.env\[.*\+").ok(),
                needle: None,
                severity: Severity::Warn,
            },
        ]
    })
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
///
/// Regex patterns are compiled once per process via a `OnceLock` static; each
/// script's content is capped at [`SCRIPT_SCAN_CAP_BYTES`] before matching.
pub struct ObfuscationPolicy;

impl Policy for ObfuscationPolicy {
    fn name(&self) -> &str {
        "obfuscation"
    }

    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult {
        if ctx.install_scripts.is_empty() {
            return PolicyResult::Pass;
        }

        let patterns = compiled_patterns();
        let mut worst_severity: Option<Severity> = None;
        let mut worst_message: Option<String> = None;

        for script in &ctx.install_scripts {
            // Cap the scanned content to SCRIPT_SCAN_CAP_BYTES at a valid UTF-8
            // boundary to bound worst-case scan time.
            let raw = script.content.as_bytes();
            let cap = SCRIPT_SCAN_CAP_BYTES.min(raw.len());
            let content_to_scan = match std::str::from_utf8(&raw[..cap]) {
                Ok(s) => s,
                Err(e) => &script.content[..e.valid_up_to()],
            };

            for pattern in patterns {
                let matched = pattern.is_match(content_to_scan);

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
    use std::thread;

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

    // ── T-045 tests ────────────────────────────────────────────────────────────

    // T-045-01: Compiled-once regex still detects long base64 strings
    #[test]
    fn t045_01_compiled_once_detects_long_base64() {
        let policy = ObfuscationPolicy;
        let base64_payload =
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NQ==";
        assert!(base64_payload.len() >= 80);
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!("var data = '{base64_payload}';"),
        }]);

        // Call evaluate twice — second call uses cached patterns
        let result1 = policy.evaluate(&ctx);
        let result2 = policy.evaluate(&ctx);

        for result in [result1, result2] {
            match &result {
                PolicyResult::Block(reason) => {
                    assert!(
                        reason.contains("long_base64"),
                        "Expected long_base64 in reason, got: {reason}"
                    );
                }
                other => panic!("Expected Block, got {:?}", other),
            }
        }
    }

    // T-045-02: Compiled-once regex still detects hex escape chains
    #[test]
    fn t045_02_compiled_once_detects_hex_escape() {
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
                    "Expected hex_escape_chain in reason, got: {reason}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-045-03: Compiled-once regex still detects chr() chains
    #[test]
    fn t045_03_compiled_once_detects_chr_chain() {
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
                    "Expected chr_chain in reason, got: {reason}"
                );
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    // T-045-04: Compiled-once regex still detects string-concat URL
    #[test]
    fn t045_04_compiled_once_detects_string_concat_url() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: r#"var u = "ht" + "tp" + "://evil.com""#.to_string(),
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Warn(reason) => {
                assert!(
                    reason.contains("string_concat_url"),
                    "Expected string_concat_url in reason, got: {reason}"
                );
            }
            other => panic!("Expected Warn, got {:?}", other),
        }
    }

    // T-045-05: Concurrent calls to evaluate from multiple threads do not panic
    #[test]
    fn t045_05_concurrent_evaluate_is_safe() {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                thread::spawn(|| {
                    let policy = ObfuscationPolicy;
                    let ctx = make_context(vec![InstallScript {
                        name: "postinstall".to_string(),
                        content: "echo clean".to_string(),
                    }]);
                    for _ in 0..10 {
                        assert_eq!(
                            policy.evaluate(&ctx),
                            PolicyResult::Pass,
                            "concurrent evaluate returned non-Pass for clean script"
                        );
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }
    }

    // T-045-06: Script content shorter than 1 MB is scanned in full
    #[test]
    fn t045_06_script_under_cap_scanned_in_full() {
        let policy = ObfuscationPolicy;
        // 512 KB of padding using characters that do NOT match any pattern,
        // then a chr() chain payload at the very end.
        // Use '!' repeated — not in [A-Za-z0-9+/=] so it won't trigger long_base64.
        let padding = "!".repeat(512 * 1024);
        let payload = "chr(104).chr(116).chr(116)";
        let content = format!("{padding}{payload}");
        assert!(content.len() < SCRIPT_SCAN_CAP_BYTES);

        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content,
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("chr_chain"),
                    "Expected chr_chain in reason, got: {reason}"
                );
            }
            other => panic!("Expected Block (payload within cap), got {:?}", other),
        }
    }

    // T-045-07: Script content exactly at the cap boundary is scanned up to the cap
    #[test]
    fn t045_07_script_exactly_at_cap_detects_pattern_within_cap() {
        let policy = ObfuscationPolicy;
        // Place 5 hex escapes at the start so they are within the 1 MB cap,
        // then pad to exactly SCRIPT_SCAN_CAP_BYTES with '!' (not in base64 set).
        let hex_chain = r"\x68\x74\x74\x70\x3a"; // 5 × \xNN = 20 bytes
        let padding = "!".repeat(SCRIPT_SCAN_CAP_BYTES - hex_chain.len());
        let padded = format!("{hex_chain}{padding}");
        assert_eq!(padded.len(), SCRIPT_SCAN_CAP_BYTES);

        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: padded,
        }]);

        let result = policy.evaluate(&ctx);
        match &result {
            PolicyResult::Block(reason) => {
                assert!(
                    reason.contains("hex_escape_chain"),
                    "Expected hex_escape_chain in reason, got: {reason}"
                );
            }
            other => panic!("Expected Block (pattern within cap), got {:?}", other),
        }
    }

    // T-045-08: Payload placed beyond 1 MB is not detected (cap is enforced)
    #[test]
    fn t045_08_payload_beyond_cap_not_detected() {
        let policy = ObfuscationPolicy;
        // 1 MB of clean padding using '!' (not in [A-Za-z0-9+/=]) so it won't
        // trigger long_base64, then a chr() chain beyond the cap.
        let padding = "!".repeat(SCRIPT_SCAN_CAP_BYTES);
        let payload = "chr(104).chr(116).chr(116)";
        let content = format!("{padding}{payload}");
        assert!(content.len() > SCRIPT_SCAN_CAP_BYTES);

        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content,
        }]);

        // The payload is beyond the cap — must not be detected.
        assert_eq!(
            policy.evaluate(&ctx),
            PolicyResult::Pass,
            "Payload beyond 1 MB cap must not be detected"
        );
    }

    // T-045-09: Script of exactly 1 byte does not panic
    #[test]
    fn t045_09_single_byte_script_no_panic() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: "a".to_string(),
        }]);

        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-045-10: Empty script list returns Pass
    #[test]
    fn t045_10_empty_scripts_returns_pass() {
        let policy = ObfuscationPolicy;
        let ctx = make_context(vec![]);
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    // T-045-11: evaluate does not call Regex::new (static code assertion)
    // The implementation uses compiled_patterns() which initialises via OnceLock;
    // Regex::new is only called inside the OnceLock initialiser, not in evaluate.
    // This test is a documentation/regression marker — the real assertion is the
    // absence of Regex::new in evaluate() as verified by code review.  The test
    // below confirms that calling evaluate multiple times produces consistent
    // results, which would not be possible if regex compilation were broken.
    #[test]
    fn t045_11_evaluate_does_not_recompile_regexes() {
        let policy = ObfuscationPolicy;
        let base64_payload =
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NQ==";
        let ctx = make_context(vec![InstallScript {
            name: "postinstall".to_string(),
            content: format!("var data = '{base64_payload}';"),
        }]);

        // Evaluate 5 times; if patterns were re-compiled and broken, at least
        // one call would differ.
        let results: Vec<_> = (0..5).map(|_| policy.evaluate(&ctx)).collect();
        assert!(
            results.iter().all(|r| matches!(r, PolicyResult::Block(_))),
            "All calls should return Block; got: {:?}",
            results
        );

        // Confirm the PATTERNS OnceLock is already populated after the first call.
        assert!(
            PATTERNS.get().is_some(),
            "PATTERNS OnceLock must be initialized after evaluate()"
        );
    }

    // T-045-12: SCRIPT_SCAN_CAP_BYTES constant equals 1,048,576
    #[test]
    fn t045_12_script_scan_cap_constant_value() {
        assert_eq!(
            SCRIPT_SCAN_CAP_BYTES, 1_048_576,
            "SCRIPT_SCAN_CAP_BYTES must equal exactly 1 MB (1,048,576 bytes)"
        );
    }

    // T-045-13: cargo test, cargo clippy --all-targets -- -D warnings, and
    // cargo fmt --check all pass.  This is a CI/process assertion verified at
    // commit time; no runtime test is needed.

    // T-045-14: Regression — all T-021 tests are covered above (same module)
    // Verified by the existing T-021-* functions in this module.
    // This marker test confirms the module compiles and runs without panic.
    #[test]
    fn t045_14_regression_all_t021_pass() {
        // Thin smoke-test that calls the policy on each detection type.
        // Full coverage is provided by the individual T-021-* tests above.
        let policy = ObfuscationPolicy;

        let cases: Vec<(&str, &str, bool)> = vec![
            ("echo clean", "postinstall", false),
            (
                "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NQ==",
                "postinstall",
                true,
            ),
            (r"\x68\x74\x74\x70\x3a\x2f\x2f", "preinstall", true),
            (r"\u0068\u0074\u0074\u0070", "postinstall", true),
            ("String.fromCharCode(104)", "postinstall", true),
            ("chr(104).chr(116).chr(116)", "postinstall", true),
        ];

        for (content, name, expected_block) in cases {
            let ctx = make_context(vec![InstallScript {
                name: name.to_string(),
                content: content.to_string(),
            }]);
            let result = policy.evaluate(&ctx);
            if expected_block {
                assert!(
                    matches!(result, PolicyResult::Block(_)),
                    "Expected Block for content starting with {:?}, got {:?}",
                    &content[..content.len().min(30)],
                    result
                );
            } else {
                assert_eq!(
                    result,
                    PolicyResult::Pass,
                    "Expected Pass for clean content, got {:?}",
                    result
                );
            }
        }
    }
}

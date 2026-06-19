// SPDX-License-Identifier: Apache-2.0
use std::fmt;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table (default)
    Native,
    /// Bespoke JSON array (legacy; same as pre-083 `--json`)
    Json,
    /// OSV-schema-compatible JSON (consumable by OSV-Scanner, Trivy, Grype)
    Osv,
    /// CycloneDX 1.4+ JSON SBOM of the scanned dependency set, verdicts attached
    #[value(name = "cyclonedx")]
    CycloneDx,
    /// SPDX 2.3+ JSON SBOM of the scanned dependency set, verdicts attached
    Spdx,
    /// OpenVEX document (presence-only: affected / fixed / under_investigation)
    Vex,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Native => write!(f, "native"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Osv => write!(f, "osv"),
            OutputFormat::CycloneDx => write!(f, "cyclonedx"),
            OutputFormat::Spdx => write!(f, "spdx"),
            OutputFormat::Vex => write!(f, "vex"),
        }
    }
}

/// A cross-platform CLI tool that scans dependencies for supply chain attacks before installation
#[derive(Parser, Debug)]
#[command(name = "dep-scan", version, about)]
pub struct Cli {
    /// Path to configuration file
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(long, short, global = true)]
    pub verbose: bool,

    /// Suppress non-essential output
    #[arg(long, short, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Check one or more packages for supply chain risks
    Check {
        /// Package name(s) to check
        #[arg(required_unless_present = "lockfile")]
        packages: Vec<String>,

        /// Registry to check against (e.g. npm, pypi, crates-io)
        #[arg(long)]
        registry: Option<String>,

        /// Output format (native, json, osv, cyclonedx, spdx, vex)
        #[arg(long, default_value_t = OutputFormat::Native, conflicts_with = "json")]
        format: OutputFormat,

        /// Output results as JSON [deprecated: use --format json]
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// Path to a lockfile to scan (package-lock.json, requirements.txt, Cargo.lock, go.sum)
        #[arg(long)]
        lockfile: Option<PathBuf>,

        /// Override lockfile format detection (npm, pypi, crates, go)
        #[arg(long)]
        lockfile_type: Option<String>,

        /// Emit interchange output (osv/cyclonedx/spdx/vex) UNSIGNED, with an
        /// explicit unsigned marker, instead of a signed DSSE envelope.
        /// Never affects the `native` or `json` paths.
        #[arg(long)]
        allow_unsigned: bool,

        /// Enable transitive dependency scanning, overriding the config-file
        /// `[transitive] enabled` value.  Use `--no-transitive` to disable.
        /// When neither flag is given, the config-file value is used (default: false).
        #[arg(long, overrides_with = "no_transitive")]
        transitive: bool,

        /// Disable transitive dependency scanning, overriding the config-file
        /// `[transitive] enabled` value.
        #[arg(long, overrides_with = "transitive")]
        no_transitive: bool,
    },

    /// Install packages (wrapping the underlying package manager)
    Install {
        /// Package name(s) to install
        #[arg(required = true)]
        packages: Vec<String>,

        /// Registry / package manager to use (npm, pypi, crates, go)
        #[arg(long, required = true)]
        registry: String,

        /// Output format (native, json, osv, cyclonedx, spdx, vex)
        #[arg(long, default_value_t = OutputFormat::Native, conflicts_with = "json")]
        format: OutputFormat,

        /// Output results as JSON [deprecated: use --format json]
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// Proceed with installation despite policy violations
        #[arg(long)]
        force: bool,

        /// Emit interchange output (osv/cyclonedx/spdx/vex) UNSIGNED, with an
        /// explicit unsigned marker, instead of a signed DSSE envelope.
        /// Never affects the `native` or `json` paths.
        #[arg(long)]
        allow_unsigned: bool,
    },

    /// Manage dep-scan configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Manage the operator signing key
    ///
    /// Reads the private key from `signing.key_path` (configured in
    /// .dep-scan.toml) and performs signing-related operations such as
    /// exporting the public half in PEM/SPKI format for distribution to
    /// consumers.
    Signing {
        #[command(subcommand)]
        action: SigningAction,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum ConfigAction {
    /// Show current configuration
    Show,
    /// Initialize a new configuration file
    Init,
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum SigningAction {
    /// Export the operator's Ed25519 public key as PEM SPKI to stdout
    ///
    /// Reads the private signing key from `signing.key_path` (set in
    /// .dep-scan.toml) and prints the corresponding public key in
    /// PEM-encoded SubjectPublicKeyInfo (SPKI) format, preceded by a
    /// `# key-id:` comment line. The key-id is the lowercase hex SHA-256
    /// of the 32-byte raw public key and matches the `keyid` field embedded
    /// in DSSE envelopes produced by `dep-scan check --format osv`.
    ///
    /// Output is pipe/redirect friendly:
    ///   dep-scan signing export-pubkey > pubkey.pem
    ///
    /// No network calls are made. No private key material appears in output.
    ExportPubkey,
}

/// Resolve the effective output format, accounting for the deprecated `--json` alias.
///
/// If `json_flag` is `true` (the user passed `--json`), the result is always
/// `OutputFormat::Json` regardless of `format`.  Otherwise `format` is returned
/// as-is.  Clap's `conflicts_with` ensures both cannot be supplied simultaneously,
/// so the only case where `json_flag` is `true` and `format != Native` is
/// theoretically impossible at runtime.
pub fn resolve_format(format: OutputFormat, json_flag: bool) -> OutputFormat {
    if json_flag {
        OutputFormat::Json
    } else {
        format
    }
}

/// Resolve the effective transitive-scanning flag from the two CLI booleans.
///
/// - `--transitive` (only) → `Some(true)`: enable, overriding config.
/// - `--no-transitive` (only) → `Some(false)`: disable, overriding config.
/// - Neither flag → `None`: config-file value is authoritative.
/// - Both flags simultaneously: clap's `overrides_with` ensures only the last
///   one wins, so this function always receives at most one `true`.
///
/// Task 108 calls this helper and applies the result over `config.transitive.enabled`.
pub fn resolve_transitive(transitive: bool, no_transitive: bool) -> Option<bool> {
    if transitive {
        Some(true)
    } else if no_transitive {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // T-002-01: CLI parses check subcommand with package names
    #[test]
    fn parse_check_with_package_names() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "express"]);
        match cli.command {
            Command::Check { packages, .. } => {
                assert_eq!(packages, vec!["lodash", "express"]);
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-002-02: CLI parses check with --registry flag
    #[test]
    fn parse_check_with_registry() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "--registry", "npm"]);
        match cli.command {
            Command::Check { registry, .. } => {
                assert_eq!(registry, Some("npm".to_string()));
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-002-03: CLI parses check with --json flag (deprecated alias for --format json)
    // T-083-09: `--json` is still accepted (deprecated alias)
    #[test]
    fn parse_check_with_json() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "--json"]);
        match cli.command {
            Command::Check { json, format, .. } => {
                assert!(json, "deprecated --json flag should be true");
                // Resolve the effective format: --json is a deprecated alias for --format json
                let effective = resolve_format(format, json);
                assert_eq!(
                    effective,
                    OutputFormat::Json,
                    "--json must resolve to OutputFormat::Json"
                );
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-002-04: CLI parses global --config flag
    #[test]
    fn parse_global_config_flag() {
        let cli = Cli::parse_from([
            "dep-scan",
            "--config",
            "/path/to/config.toml",
            "check",
            "lodash",
        ]);
        assert_eq!(cli.config, Some(PathBuf::from("/path/to/config.toml")));
    }

    // T-002-05: CLI parses global --verbose flag
    #[test]
    fn parse_global_verbose_flag() {
        let cli = Cli::parse_from(["dep-scan", "--verbose", "check", "lodash"]);
        assert!(cli.verbose);
    }

    // T-002-06: CLI parses config show subcommand
    #[test]
    fn parse_config_show() {
        let cli = Cli::parse_from(["dep-scan", "config", "show"]);
        match cli.command {
            Command::Config { action } => {
                assert_eq!(action, ConfigAction::Show);
            }
            _ => panic!("expected Config command"),
        }
    }

    // T-002-07: CLI parses config init subcommand
    #[test]
    fn parse_config_init() {
        let cli = Cli::parse_from(["dep-scan", "config", "init"]);
        match cli.command {
            Command::Config { action } => {
                assert_eq!(action, ConfigAction::Init);
            }
            _ => panic!("expected Config command"),
        }
    }

    // T-024-01: Install CLI parses packages and registry
    #[test]
    fn parse_install_with_packages_and_registry() {
        let cli = Cli::parse_from(["dep-scan", "install", "express", "--registry", "npm"]);
        match cli.command {
            Command::Install {
                packages,
                registry,
                force,
                ..
            } => {
                assert_eq!(packages, vec!["express"]);
                assert_eq!(registry, "npm");
                assert!(!force);
            }
            _ => panic!("expected Install command"),
        }
    }

    // T-024-02: Install CLI parses --force flag
    #[test]
    fn parse_install_with_force_flag() {
        let cli = Cli::parse_from([
            "dep-scan",
            "install",
            "evil-pkg",
            "--registry",
            "npm",
            "--force",
        ]);
        match cli.command {
            Command::Install {
                packages,
                registry,
                force,
                ..
            } => {
                assert_eq!(packages, vec!["evil-pkg"]);
                assert_eq!(registry, "npm");
                assert!(force);
            }
            _ => panic!("expected Install command"),
        }
    }

    // T-083-01: Default format is `native`
    #[test]
    fn t083_01_default_format_is_native() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash"]);
        match cli.command {
            Command::Check { format, .. } => {
                assert_eq!(
                    format,
                    OutputFormat::Native,
                    "T-083-01: default format must be Native"
                );
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-083-02: `--format native` is accepted and equals the default
    #[test]
    fn t083_02_format_native_accepted() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "--format", "native"]);
        match cli.command {
            Command::Check { format, .. } => {
                assert_eq!(
                    format,
                    OutputFormat::Native,
                    "T-083-02: --format native must equal Native"
                );
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-083-03: `--format json` is accepted
    #[test]
    fn t083_03_format_json_accepted() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "--format", "json"]);
        match cli.command {
            Command::Check { format, .. } => {
                assert_eq!(
                    format,
                    OutputFormat::Json,
                    "T-083-03: --format json must equal Json"
                );
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-083-04: `--format osv` is accepted
    #[test]
    fn t083_04_format_osv_accepted() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "--format", "osv"]);
        match cli.command {
            Command::Check { format, .. } => {
                assert_eq!(
                    format,
                    OutputFormat::Osv,
                    "T-083-04: --format osv must equal Osv"
                );
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-083-05: `--format cyclonedx` is accepted by the parser
    #[test]
    fn t083_05_format_cyclonedx_accepted() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "--format", "cyclonedx"]);
        match cli.command {
            Command::Check { format, .. } => {
                assert_eq!(
                    format,
                    OutputFormat::CycloneDx,
                    "T-083-05: --format cyclonedx must equal CycloneDx"
                );
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-083-06: `--format spdx` is accepted by the parser
    #[test]
    fn t083_06_format_spdx_accepted() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "--format", "spdx"]);
        match cli.command {
            Command::Check { format, .. } => {
                assert_eq!(
                    format,
                    OutputFormat::Spdx,
                    "T-083-06: --format spdx must equal Spdx"
                );
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-083-07: `--format vex` is accepted by the parser
    #[test]
    fn t083_07_format_vex_accepted() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "--format", "vex"]);
        match cli.command {
            Command::Check { format, .. } => {
                assert_eq!(
                    format,
                    OutputFormat::Vex,
                    "T-083-07: --format vex must equal Vex"
                );
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-083-08: Unknown format value is rejected by clap
    #[test]
    fn t083_08_unknown_format_rejected() {
        let result = Cli::try_parse_from(["dep-scan", "check", "lodash", "--format", "sarif"]);
        assert!(
            result.is_err(),
            "T-083-08: unknown format 'sarif' must cause a parse error"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("sarif"),
            "T-083-08: error message must name 'sarif' as the invalid value, got: {err_msg}"
        );
    }

    // T-083-09: `--json` flag is still accepted (deprecated alias)
    // — see parse_check_with_json above, which is the renamed version of T-002-03.

    // T-083-10: `--format` is present on `install` subcommand too
    #[test]
    fn t083_10_format_on_install_subcommand() {
        let cli = Cli::parse_from([
            "dep-scan",
            "install",
            "express",
            "--registry",
            "npm",
            "--format",
            "osv",
        ]);
        match cli.command {
            Command::Install { format, .. } => {
                assert_eq!(
                    format,
                    OutputFormat::Osv,
                    "T-083-10: --format osv on install must equal Osv"
                );
            }
            _ => panic!("expected Install command"),
        }
    }

    // T-086-18: `--allow-unsigned` is accepted on `check` and defaults to false.
    #[test]
    fn t086_18_allow_unsigned_flag_on_check() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "--format", "osv"]);
        match &cli.command {
            Command::Check { allow_unsigned, .. } => {
                assert!(!allow_unsigned, "default must be false");
            }
            _ => panic!("expected Check command"),
        }
        let cli = Cli::parse_from([
            "dep-scan",
            "check",
            "lodash",
            "--format",
            "osv",
            "--allow-unsigned",
        ]);
        match &cli.command {
            Command::Check { allow_unsigned, .. } => {
                assert!(allow_unsigned, "--allow-unsigned must set the flag");
            }
            _ => panic!("expected Check command"),
        }
    }

    // T-086-18: `--allow-unsigned` is also accepted on `install`.
    #[test]
    fn t086_18_allow_unsigned_flag_on_install() {
        let cli = Cli::parse_from([
            "dep-scan",
            "install",
            "express",
            "--registry",
            "npm",
            "--allow-unsigned",
        ]);
        match &cli.command {
            Command::Install { allow_unsigned, .. } => {
                assert!(
                    allow_unsigned,
                    "--allow-unsigned must set the flag on install"
                );
            }
            _ => panic!("expected Install command"),
        }
    }

    // T-083-11: `--format` and `--json` are mutually exclusive
    #[test]
    fn t083_11_format_and_json_mutually_exclusive() {
        let result =
            Cli::try_parse_from(["dep-scan", "check", "lodash", "--format", "osv", "--json"]);
        assert!(
            result.is_err(),
            "T-083-11: --format and --json together must cause a parse error (conflict)"
        );
    }

    // T-089-01: `dep-scan signing export-pubkey` parses without arguments.
    #[test]
    fn t089_01_parse_signing_export_pubkey() {
        let cli = Cli::parse_from(["dep-scan", "signing", "export-pubkey"]);
        match cli.command {
            Command::Signing { action } => {
                assert_eq!(
                    action,
                    SigningAction::ExportPubkey,
                    "T-089-01: signing export-pubkey must parse to SigningAction::ExportPubkey"
                );
            }
            _ => panic!("T-089-01: expected Signing command"),
        }
    }

    // T-089-02: `dep-scan signing export-pubkey --help` exits 0 and mentions
    // signing.key_path and PEM/SPKI.
    #[test]
    fn t089_02_signing_export_pubkey_help_text() {
        let result = Cli::try_parse_from(["dep-scan", "signing", "export-pubkey", "--help"]);
        // clap returns an Err for --help (it exits), but we can check the
        // error message contains the expected strings.
        let err = result.expect_err("--help should cause a parse exit");
        let help_text = err.to_string();
        assert!(
            help_text.contains("signing.key_path"),
            "T-089-02: help text must mention 'signing.key_path', got:\n{help_text}"
        );
        assert!(
            help_text.to_lowercase().contains("pem") || help_text.to_lowercase().contains("spki"),
            "T-089-02: help text must mention PEM or SPKI format, got:\n{help_text}"
        );
    }
}

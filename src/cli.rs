use std::path::PathBuf;

use clap::{Parser, Subcommand};

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

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// Path to a lockfile to scan (package-lock.json, requirements.txt, Cargo.lock, go.sum)
        #[arg(long)]
        lockfile: Option<PathBuf>,

        /// Override lockfile format detection (npm, pypi, crates, go)
        #[arg(long)]
        lockfile_type: Option<String>,
    },

    /// Install packages (wrapping the underlying package manager)
    Install {
        /// Package name(s) to install
        #[arg(required = true)]
        packages: Vec<String>,
    },

    /// Manage dep-scan configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum ConfigAction {
    /// Show current configuration
    Show,
    /// Initialize a new configuration file
    Init,
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

    // T-002-03: CLI parses check with --json flag
    #[test]
    fn parse_check_with_json() {
        let cli = Cli::parse_from(["dep-scan", "check", "lodash", "--json"]);
        match cli.command {
            Command::Check { json, .. } => {
                assert!(json);
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
}

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::policy::mutable_ref::MutableRefSeverity;

/// Registry URL configuration for supported package managers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryConfig {
    /// npm registry URL
    #[serde(default = "default_npm_url")]
    pub npm_url: String,
    /// PyPI registry URL
    #[serde(default = "default_pypi_url")]
    pub pypi_url: String,
    /// crates.io registry URL
    #[serde(default = "default_crates_url")]
    pub crates_url: String,
    /// Go module proxy URL
    #[serde(default = "default_go_proxy_url")]
    pub go_proxy_url: String,
    /// Go checksum database URL
    #[serde(default = "default_go_sum_db_url")]
    pub go_sum_db_url: String,
}

fn default_npm_url() -> String {
    "https://registry.npmjs.org".to_string()
}

fn default_pypi_url() -> String {
    "https://pypi.org".to_string()
}

fn default_crates_url() -> String {
    "https://crates.io".to_string()
}

fn default_go_proxy_url() -> String {
    "https://proxy.golang.org".to_string()
}

fn default_go_sum_db_url() -> String {
    "https://sum.golang.org".to_string()
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            npm_url: default_npm_url(),
            pypi_url: default_pypi_url(),
            crates_url: default_crates_url(),
            go_proxy_url: default_go_proxy_url(),
            go_sum_db_url: default_go_sum_db_url(),
        }
    }
}

/// OSV.dev API configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsvConfig {
    /// Base URL for the OSV API.
    #[serde(default = "default_osv_url")]
    pub osv_url: String,
}

fn default_osv_url() -> String {
    "https://api.osv.dev".to_string()
}

impl Default for OsvConfig {
    fn default() -> Self {
        Self {
            osv_url: default_osv_url(),
        }
    }
}

/// Policy toggles for controlling which checks are enabled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyConfig {
    /// Check for typosquatting attacks
    #[serde(default = "default_true")]
    pub check_typosquatting: bool,
    /// Check for malicious install scripts
    #[serde(default = "default_true")]
    pub check_install_scripts: bool,
    /// Enforce minimum package age
    #[serde(default = "default_true")]
    pub check_min_age: bool,
    /// Check for suspicious maintainer changes
    #[serde(default = "default_true")]
    pub check_maintainer_changes: bool,
    /// Check for known vulnerabilities via OSV.dev
    #[serde(default = "default_true")]
    pub check_vulnerabilities: bool,
    /// Check for obfuscated code in install scripts
    #[serde(default = "default_true")]
    pub check_obfuscation: bool,
    /// Check npm packages for sigstore provenance attestations (task 032).
    ///
    /// When `true`, the policy queries the npm attestation endpoint and
    /// verifies any DSSE bundles found there.
    #[serde(default = "default_true")]
    pub check_npm_provenance: bool,
    /// When `true`, a missing npm provenance attestation escalates from
    /// `Warn` to `Block`. Invalid attestations always block regardless.
    #[serde(default = "default_false")]
    pub require_npm_provenance: bool,
    /// Check PyPI packages for PEP 740 sigstore provenance attestations (task 033).
    ///
    /// When `true`, the policy queries the PEP 691 Simple Index and verifies
    /// any PEP 740 attestation bundles found there.
    #[serde(default = "default_true")]
    pub check_pypi_provenance: bool,
    /// When `true`, a missing PyPI provenance attestation escalates from
    /// `Warn` to `Block`. Invalid attestations always block regardless.
    #[serde(default = "default_false")]
    pub require_pypi_provenance: bool,
    /// Check Go modules against the Go checksum database (sum.golang.org) signature
    /// verification policy (task 034).
    ///
    /// When `true`, the policy fetches the sumdb lookup response and verifies
    /// the Ed25519 tree-head signature against the pinned sum.golang.org public key.
    #[serde(default = "default_true")]
    pub check_go_sumdb: bool,
    /// When `true`, a module not found in the Go checksum database (404) escalates
    /// from `Warn` to `Block`. Invalid / malformed signatures always block regardless.
    #[serde(default = "default_false")]
    pub require_go_sumdb: bool,
    /// When `true`, a first observation of a package with zero or unknown download
    /// count produces a `Warn` verdict rather than a `Pass`.  This is an opt-in
    /// defense-in-depth signal against day-one malicious publishes.
    ///
    /// Default: `false` — preserves the pre-task trust-on-first-use (TOFU) behavior
    /// so existing users are not flooded with warnings on every new package scan.
    #[serde(default = "default_false")]
    pub maintainer_first_seen_warning: bool,

    /// Policy severity for git dependencies that point at a mutable ref
    /// (branch name, tag, short hash, or empty string).
    ///
    /// A full 40-hex (SHA-1) or 64-hex (SHA-256) commit hash is treated as
    /// immutable and always passes.  Everything else is mutable and triggers
    /// this policy.
    ///
    /// Accepted values: `"warn"` (default), `"block"`, `"off"`.
    /// Unknown values are rejected at config load time.
    #[serde(default)]
    pub mutable_git_ref: MutableRefSeverity,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            check_typosquatting: true,
            check_install_scripts: true,
            check_min_age: true,
            check_maintainer_changes: true,
            check_vulnerabilities: true,
            check_obfuscation: true,
            check_npm_provenance: true,
            require_npm_provenance: false,
            check_pypi_provenance: true,
            require_pypi_provenance: false,
            check_go_sumdb: true,
            require_go_sumdb: false,
            maintainer_first_seen_warning: false,
            mutable_git_ref: MutableRefSeverity::Warn,
        }
    }
}

/// Configuration for the popularity/download threshold policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PopularityConfig {
    /// Minimum number of downloads to pass without warning.
    #[serde(default = "default_min_downloads")]
    pub min_downloads: u64,
}

fn default_min_downloads() -> u64 {
    1000
}

impl Default for PopularityConfig {
    fn default() -> Self {
        Self {
            min_downloads: default_min_downloads(),
        }
    }
}

/// Configuration for the statement freshness signals embedded in signed interchange
/// output (task 088).
///
/// Each signed interchange payload includes:
/// - `osv_snapshot.queried_at`: the exact instant the OSV advisory data was fetched
///   (precise freshness signal for strict consumers).
/// - `valid_until`: `osv_queried_at + valid_until_hours` — a coarse backstop so a
///   consumer can quickly check staleness without verifying the signature.
///
/// The default 24 h window aligns with the standard CI daily-scan cadence. Air-gapped
/// environments that refresh on a longer cycle can raise it (e.g. 168 h = 1 week).
/// Zero is always rejected at load time — it would make every statement immediately
/// expired, which is never useful.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FreshnessConfig {
    /// How long a signed interchange statement is considered fresh.
    ///
    /// `valid_until` in the payload is set to `osv_queried_at + valid_until_hours`.
    /// Must be > 0. Default is 24 (matches the standard CI daily scan cadence).
    #[serde(default = "default_valid_until_hours")]
    pub valid_until_hours: u32,
}

fn default_valid_until_hours() -> u32 {
    24
}

impl Default for FreshnessConfig {
    fn default() -> Self {
        Self {
            valid_until_hours: default_valid_until_hours(),
        }
    }
}

/// Configuration for interchange-output signing identity (task 087).
///
/// dep-scan signs the machine-readable interchange formats (`--format
/// osv/cyclonedx/spdx/vex`) so a downstream consumer can verify the report's
/// origin (ADR 006 Q5). Two identities exist:
///
/// - **online keyless** (sigstore Fulcio + Rekor) — the default when network
///   is available;
/// - **offline operator key** — an operator-provisioned private Ed25519 key
///   loaded from [`SigningConfig::key_path`].
///
/// There is intentionally **no embedded-key default** (ADR 007): an empty
/// `key_path` means no offline signing key exists, and the offline path then
/// fails closed rather than emitting unsigned-but-signed-looking output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SigningConfig {
    /// Force offline signing mode, skipping the network keyless path entirely.
    ///
    /// Overridden by the `DEP_SCAN_OFFLINE` environment variable.
    #[serde(default = "default_false")]
    pub offline: bool,

    /// Path to an operator-provisioned private signing key (PEM-encoded PKCS#8
    /// Ed25519). Empty string means **no offline signing key is configured**.
    ///
    /// The reference is a path today; ADR 007 keeps it pluggable so a
    /// `pkcs11:` / `awskms:` backend can slot in later without a breaking
    /// config change.
    #[serde(default = "default_empty_string")]
    pub key_path: String,

    /// Fulcio base URL for the online keyless path (no hardcoded default — it
    /// is configurable for testing and future extensibility). Empty means the
    /// keyless path is not provisioned, so an online run falls back to the
    /// offline path (and thus fail-closed unless `key_path` is set).
    #[serde(default = "default_empty_string")]
    pub fulcio_url: String,

    /// Rekor base URL for the online keyless path. Empty = keyless not
    /// provisioned (see `fulcio_url`).
    #[serde(default = "default_empty_string")]
    pub rekor_url: String,

    /// OIDC identity token presented to Fulcio for keyless signing. Empty =
    /// keyless not provisioned. Provided by the operator's CI/workload identity
    /// out of band; dep-scan does not acquire it.
    #[serde(default = "default_empty_string")]
    pub oidc_token: String,
}

fn default_empty_string() -> String {
    String::new()
}

/// Configuration for the dependency confusion detection policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DependencyConfusionConfig {
    /// Package name prefixes that indicate internal/private packages.
    #[serde(default = "default_internal_prefixes")]
    pub internal_prefixes: Vec<String>,
}

fn default_internal_prefixes() -> Vec<String> {
    vec![
        "internal-".to_string(),
        "private-".to_string(),
        "corp-".to_string(),
    ]
}

impl Default for DependencyConfusionConfig {
    fn default() -> Self {
        Self {
            internal_prefixes: default_internal_prefixes(),
        }
    }
}

/// VCS host allow/deny policy configuration.
///
/// Controls which VCS hosts may be fetched when scanning git-sourced
/// dependencies (ADR 008).  Both lists default to empty, which permits any
/// host — an "open" posture that operators can restrict by setting
/// `allowed_hosts` and/or `denied_hosts` in `.dep-scan.toml`.
///
/// Rules (applied in priority order):
/// 1. If `denied_hosts` is non-empty and contains the host → **reject**.
/// 2. If `allowed_hosts` is non-empty and does **not** contain the host → **reject**.
/// 3. Otherwise → **permit**.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VcsConfig {
    /// Hosts that are explicitly allowed.  An empty list means any host is
    /// allowed (unless on the deny list).  Case-insensitive matching.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Hosts that are explicitly denied.  Takes precedence over
    /// `allowed_hosts`.  An empty list means no host is denied by default.
    /// Case-insensitive matching.
    #[serde(default)]
    pub denied_hosts: Vec<String>,
    /// Maximum wall-clock time, in seconds, a single VCS fetch may take before
    /// it is aborted with an error (task 096, REQ-096-07).  A fetch that exceeds
    /// this budget fails closed (the dep is treated as unfetchable, never
    /// `Pass`).  Default 30.
    #[serde(default = "default_vcs_fetch_timeout_secs")]
    pub fetch_timeout_secs: u64,
    /// Maximum size, in bytes, of a single blob materialised from a fetched
    /// tree (task 096, REQ-096-08).  Blobs larger than this are skipped with a
    /// diagnostic warning and never read into memory, preventing OOM on
    /// adversarially large fetched files.  Default 50 MiB.
    #[serde(default = "default_vcs_max_blob_bytes")]
    pub max_blob_bytes: u64,
}

fn default_vcs_fetch_timeout_secs() -> u64 {
    30
}

fn default_vcs_max_blob_bytes() -> u64 {
    50 * 1024 * 1024
}

impl Default for VcsConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            fetch_timeout_secs: default_vcs_fetch_timeout_secs(),
            max_blob_bytes: default_vcs_max_blob_bytes(),
        }
    }
}

/// Main configuration for dep-scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Minimum age in hours a package must have before it is allowed.
    #[serde(default = "default_min_package_age_hours")]
    pub min_package_age_hours: u64,

    /// Path to the cache database file. Defaults to `~/.dep-scan/cache.db`.
    #[serde(default)]
    pub cache_path: Option<String>,

    /// Registry URL configuration.
    #[serde(default)]
    pub registries: RegistryConfig,

    /// Policy toggles.
    #[serde(default)]
    pub policies: PolicyConfig,

    /// OSV.dev API configuration.
    #[serde(default)]
    pub osv: OsvConfig,

    /// Dependency confusion detection configuration.
    #[serde(default)]
    pub dependency_confusion: DependencyConfusionConfig,

    /// Popularity/download threshold configuration.
    #[serde(default)]
    pub popularity: PopularityConfig,

    /// Interchange-output signing identity configuration (task 087).
    #[serde(default)]
    pub signing: SigningConfig,

    /// Statement freshness configuration (task 088).
    ///
    /// Controls the `valid_until` field embedded in signed interchange payloads.
    #[serde(default)]
    pub freshness: FreshnessConfig,

    /// VCS host allow/deny policy configuration (task 095).
    ///
    /// Controls which VCS hosts may be fetched when scanning git-sourced
    /// dependencies.  Default is empty lists (any host permitted).
    #[serde(default)]
    pub vcs: VcsConfig,
}

fn default_min_package_age_hours() -> u64 {
    48
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_package_age_hours: default_min_package_age_hours(),
            cache_path: None,
            registries: RegistryConfig::default(),
            policies: PolicyConfig::default(),
            osv: OsvConfig::default(),
            dependency_confusion: DependencyConfusionConfig::default(),
            popularity: PopularityConfig::default(),
            signing: SigningConfig::default(),
            freshness: FreshnessConfig::default(),
            vcs: VcsConfig::default(),
        }
    }
}

impl Config {
    /// Parse a Config from a TOML string. Missing fields use defaults.
    pub fn from_toml_str(s: &str) -> Result<Config> {
        let config: Config =
            toml::from_str(s).context("Failed to parse configuration file as valid TOML")?;
        // REQ-088-03: valid_until_hours must be > 0; a zero window would make
        // every statement immediately expired, which is never useful.
        if config.freshness.valid_until_hours == 0 {
            anyhow::bail!(
                "freshness.valid_until_hours must be > 0 (got 0); \
                 set it to at least 1 in .dep-scan.toml"
            );
        }
        Ok(config)
    }

    /// Load configuration with the following precedence:
    /// 1. Explicit path (from `--config` CLI flag)
    /// 2. `.dep-scan.toml` in the current working directory
    /// 3. Built-in defaults
    ///
    /// After loading from file, environment variable overrides are applied.
    pub fn load(explicit_path: Option<&Path>) -> Result<Config> {
        let mut config = if let Some(path) = explicit_path {
            if path.exists() {
                let contents = std::fs::read_to_string(path)
                    .with_context(|| format!("Failed to read config file: {}", path.display()))?;
                Self::from_toml_str(&contents)
                    .with_context(|| format!("Invalid config file: {}", path.display()))?
            } else {
                // Explicit path that doesn't exist: fall back to defaults (no error)
                Config::default()
            }
        } else {
            // Try .dep-scan.toml in current directory
            let cwd_config = Path::new(".dep-scan.toml");
            if cwd_config.exists() {
                let contents =
                    std::fs::read_to_string(cwd_config).context("Failed to read .dep-scan.toml")?;
                Self::from_toml_str(&contents).context("Invalid .dep-scan.toml")?
            } else {
                Config::default()
            }
        };

        // Apply environment variable overrides
        config.apply_env_overrides();

        Ok(config)
    }

    /// Apply environment variable overrides on top of the loaded config.
    fn apply_env_overrides(&mut self) {
        if let Ok(val) = std::env::var("DEP_SCAN_MIN_AGE")
            && let Ok(hours) = val.parse::<u64>()
        {
            self.min_package_age_hours = hours;
        }
        if let Ok(val) = std::env::var("DEP_SCAN_NPM_URL") {
            self.registries.npm_url = val;
        }
        if let Ok(val) = std::env::var("DEP_SCAN_PYPI_URL") {
            self.registries.pypi_url = val;
        }
        if let Ok(val) = std::env::var("DEP_SCAN_CRATES_URL") {
            self.registries.crates_url = val;
        }
        if let Ok(val) = std::env::var("DEP_SCAN_GO_PROXY_URL") {
            self.registries.go_proxy_url = val;
        }
        if let Ok(val) = std::env::var("DEP_SCAN_GO_SUM_DB_URL") {
            self.registries.go_sum_db_url = val;
        }
        if let Ok(val) = std::env::var("DEP_SCAN_CACHE_PATH") {
            self.cache_path = Some(val);
        }
        if let Ok(val) = std::env::var("DEP_SCAN_OSV_URL") {
            self.osv.osv_url = val;
        }
        // DEP_SCAN_OFFLINE forces the offline signing path, overriding
        // `signing.offline` from the config file (task 087). Any value other
        // than "0", "false", or "" (case-insensitive) is treated as truthy so
        // `DEP_SCAN_OFFLINE=1` works as documented.
        if let Ok(val) = std::env::var("DEP_SCAN_OFFLINE") {
            let v = val.trim().to_ascii_lowercase();
            self.signing.offline = !matches!(v.as_str(), "" | "0" | "false");
        }
    }

    /// Resolve the effective cache path.
    ///
    /// Priority: `cache_path` from config/env, then `~/.dep-scan/cache.db`.
    pub fn resolve_cache_path(&self) -> std::path::PathBuf {
        if let Some(ref p) = self.cache_path {
            std::path::PathBuf::from(p)
        } else {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            std::path::PathBuf::from(home)
                .join(".dep-scan")
                .join("cache.db")
        }
    }

    /// Serialize the config to a TOML string.
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).context("Failed to serialize config to TOML")
    }

    /// Write the default config to a file at the given path.
    ///
    /// Produces a human-readable TOML file with explanatory comments for each
    /// section.  The `[freshness]` section and its `valid_until_hours` key are
    /// included with a comment describing the purpose (REQ-088-04).
    pub fn write_default(path: &Path) -> Result<()> {
        // Use a hand-crafted template so we can include section-level comments
        // that plain `toml::to_string_pretty` cannot produce.
        let dep_scan_version = env!("CARGO_PKG_VERSION");
        let content = format!(
            r#"# dep-scan configuration (generated by dep-scan {version})
# See https://github.com/tkdtaylor/dep-scan for documentation.

min_package_age_hours = 48

[registries]
npm_url = "https://registry.npmjs.org"
pypi_url = "https://pypi.org"
crates_url = "https://crates.io"
go_proxy_url = "https://proxy.golang.org"
go_sum_db_url = "https://sum.golang.org"

[osv]
osv_url = "https://api.osv.dev"

[freshness]
# How long a signed interchange statement is considered fresh.
# valid_until in the payload is set to osv_queried_at + valid_until_hours.
# 24h matches the standard CI daily scan cadence. Air-gapped environments
# that refresh less frequently can raise this (e.g. 168 for one week).
# Must be > 0.
valid_until_hours = 24

[policies]
check_typosquatting = true
check_install_scripts = true
check_min_age = true
check_maintainer_changes = true
check_vulnerabilities = true
check_obfuscation = true
check_npm_provenance = true
require_npm_provenance = false
check_pypi_provenance = true
require_pypi_provenance = false
check_go_sumdb = true
require_go_sumdb = false
maintainer_first_seen_warning = false
# Policy for git dependencies that point at a mutable ref (branch name, tag,
# short hash, or empty string). A full 40- or 64-hex commit SHA is treated as
# immutable and always passes. Accepted values: "warn" (default), "block", "off".
mutable_git_ref = "warn"

[popularity]
min_downloads = 1000

[dependency_confusion]
internal_prefixes = ["internal-", "private-", "corp-"]

[signing]
# offline = false
# key_path = ""
# fulcio_url = ""
# rekor_url = ""
# oidc_token = ""

[vcs]
# VCS host allow/deny policy for git-sourced dependencies (ADR 008).
# Empty lists (the default) permit fetching from any host.
# Set allowed_hosts to restrict fetching to specific hosts, e.g. an internal
# mirror. Set denied_hosts to block specific hosts; deny takes precedence.
# Case-insensitive matching. Example:
# allowed_hosts = ["git.corp.example.com"]
# denied_hosts = ["untrusted.example.com"]
# Maximum wall-clock seconds a single VCS fetch may take before it is aborted
# (fail-closed: an unfetchable dep is never treated as safe). Default 30.
fetch_timeout_secs = 30
# Maximum size in bytes of a single blob materialised from a fetched tree.
# Larger blobs are skipped with a warning and never read into memory, preventing
# OOM on adversarially large files. Default 52428800 (50 MiB).
max_blob_bytes = 52428800
"#,
            version = dep_scan_version
        );
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        Ok(())
    }
}

/// Process-global lock that serializes any test mutating `DEP_SCAN_*`
/// environment variables. Env vars are process-wide shared state, so tests in
/// *any* module that set/remove them (here in `config.rs`, and the
/// `resolve_signer` end-to-end test in `interchange_sign.rs`) must hold this
/// same lock to avoid cross-test interference. It is `pub(crate)` and
/// `#[cfg(test)]` so it is visible to sibling test modules but never compiled
/// into the production binary.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// RAII guard that removes an env var when dropped, even on panic.
    struct EnvGuard {
        key: &'static str,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(self.key);
            }
        }
    }

    // T-003-01: Default config has expected values
    #[test]
    fn default_config_has_expected_values() {
        let config = Config::default();
        assert_eq!(config.min_package_age_hours, 48);
        assert_eq!(config.registries.npm_url, "https://registry.npmjs.org");
        assert_eq!(config.registries.pypi_url, "https://pypi.org");
        assert!(config.policies.check_typosquatting);
        assert!(config.policies.check_install_scripts);
        assert!(config.policies.check_min_age);
        assert!(config.policies.check_maintainer_changes);
    }

    // T-003-02: Load config from TOML string with min_package_age_hours=24
    #[test]
    fn load_config_from_toml_string() {
        let toml_str = r#"
min_package_age_hours = 24
"#;
        let config = Config::from_toml_str(toml_str).unwrap();
        assert_eq!(config.min_package_age_hours, 24);
        // Other fields should be at defaults
        assert_eq!(config.registries.npm_url, "https://registry.npmjs.org");
        assert_eq!(config.registries.pypi_url, "https://pypi.org");
    }

    // T-003-03: Load config from file path (temp file)
    #[test]
    fn load_config_from_file_path() {
        let _lock = ENV_LOCK.lock().unwrap();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "min_package_age_hours = 72").unwrap();

        let config = Config::load(Some(file.path())).unwrap();
        assert_eq!(config.min_package_age_hours, 72);
    }

    // T-003-04: Missing config file falls back to defaults (no error)
    #[test]
    fn missing_config_file_falls_back_to_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();

        let path = Path::new("/tmp/nonexistent-dep-scan-config-abc123.toml");
        let config = Config::load(Some(path)).unwrap();
        assert_eq!(config.min_package_age_hours, 48);
        assert_eq!(config.registries.npm_url, "https://registry.npmjs.org");
    }

    // T-003-05: Invalid TOML produces clear error
    #[test]
    fn invalid_toml_produces_clear_error() {
        let bad_toml = "this is [[ not valid toml %%%";
        let result = Config::from_toml_str(bad_toml);
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("Failed to parse configuration file"),
            "Error message should mention parsing failure, got: {}",
            err_msg
        );
    }

    // T-003-06: Env var override DEP_SCAN_MIN_AGE=12 overrides file
    #[test]
    fn env_var_override_min_age() {
        let _lock = ENV_LOCK.lock().unwrap();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "min_package_age_hours = 99").unwrap();

        // EnvGuard ensures cleanup even on panic
        let _guard = EnvGuard::set("DEP_SCAN_MIN_AGE", "12");

        let config = Config::load(Some(file.path())).unwrap();
        assert_eq!(config.min_package_age_hours, 12);
    }

    // T-003-07: Registry URLs are configurable via TOML
    #[test]
    fn registry_urls_configurable_via_toml() {
        let toml_str = r#"
[registries]
npm_url = "https://custom-npm.example.com"
pypi_url = "https://custom-pypi.example.com"
"#;
        let config = Config::from_toml_str(toml_str).unwrap();
        assert_eq!(config.registries.npm_url, "https://custom-npm.example.com");
        assert_eq!(
            config.registries.pypi_url,
            "https://custom-pypi.example.com"
        );
    }

    // T-003-08: Partial config merges with defaults
    #[test]
    fn partial_config_merges_with_defaults() {
        let toml_str = r#"
min_package_age_hours = 100
"#;
        let config = Config::from_toml_str(toml_str).unwrap();
        assert_eq!(config.min_package_age_hours, 100);
        // Registry URLs should still be at defaults
        assert_eq!(config.registries.npm_url, "https://registry.npmjs.org");
        assert_eq!(config.registries.pypi_url, "https://pypi.org");
        // Policies should still be at defaults
        assert!(config.policies.check_typosquatting);
    }

    // T-011-09: OsvConfig has correct defaults
    #[test]
    fn osv_config_has_correct_defaults() {
        let config = Config::default();
        assert_eq!(config.osv.osv_url, "https://api.osv.dev");
        assert!(config.policies.check_vulnerabilities);
    }

    // T-011-10: DEP_SCAN_OSV_URL env var overrides osv_url
    #[test]
    fn env_var_override_osv_url() {
        let _lock = ENV_LOCK.lock().unwrap();

        let _guard = EnvGuard::set("DEP_SCAN_OSV_URL", "http://localhost:9999");

        let config = Config::load(None).unwrap();
        assert_eq!(config.osv.osv_url, "http://localhost:9999");
    }

    // T-017-04: Config defaults for new registry URLs
    #[test]
    fn default_config_has_crates_and_go_urls() {
        let config = Config::default();
        assert_eq!(config.registries.crates_url, "https://crates.io");
        assert_eq!(config.registries.go_proxy_url, "https://proxy.golang.org");
    }

    // T-017-05: Env var overrides for new URLs
    #[test]
    fn env_var_override_crates_url() {
        let _lock = ENV_LOCK.lock().unwrap();

        let _guard = EnvGuard::set("DEP_SCAN_CRATES_URL", "http://localhost:8080");

        let config = Config::load(None).unwrap();
        assert_eq!(config.registries.crates_url, "http://localhost:8080");
    }

    #[test]
    fn env_var_override_go_proxy_url() {
        let _lock = ENV_LOCK.lock().unwrap();

        let _guard = EnvGuard::set("DEP_SCAN_GO_PROXY_URL", "http://localhost:9090");

        let config = Config::load(None).unwrap();
        assert_eq!(config.registries.go_proxy_url, "http://localhost:9090");
    }

    // T-017-04 (continued): New URLs configurable via TOML
    #[test]
    fn crates_and_go_urls_configurable_via_toml() {
        let toml_str = r#"
[registries]
crates_url = "https://custom-crates.example.com"
go_proxy_url = "https://custom-go-proxy.example.com"
"#;
        let config = Config::from_toml_str(toml_str).unwrap();
        assert_eq!(
            config.registries.crates_url,
            "https://custom-crates.example.com"
        );
        assert_eq!(
            config.registries.go_proxy_url,
            "https://custom-go-proxy.example.com"
        );
    }

    // OsvConfig can be set via TOML
    #[test]
    fn osv_config_from_toml() {
        let toml_str = r#"
[osv]
osv_url = "https://custom-osv.example.com"
"#;
        let config = Config::from_toml_str(toml_str).unwrap();
        assert_eq!(config.osv.osv_url, "https://custom-osv.example.com");
    }

    // T-048-10: maintainer_first_seen_warning defaults to false
    #[test]
    fn t048_10_maintainer_first_seen_warning_defaults_to_false() {
        // T-048-10
        let config = Config::default();
        assert!(
            !config.policies.maintainer_first_seen_warning,
            "maintainer_first_seen_warning must default to false"
        );
    }

    // T-048-11: maintainer_first_seen_warning = true is accepted in TOML
    #[test]
    fn t048_11_maintainer_first_seen_warning_parsed_true() {
        // T-048-11
        let toml_str = "[policies]\nmaintainer_first_seen_warning = true\n";
        let config = Config::from_toml_str(toml_str).unwrap();
        assert!(
            config.policies.maintainer_first_seen_warning,
            "maintainer_first_seen_warning should be true when set in TOML"
        );
    }

    // T-087-14: [signing] section added to Config with correct defaults.
    #[test]
    fn t087_14_signing_defaults() {
        let config = Config::default();
        assert!(
            !config.signing.offline,
            "T-087-14: signing.offline must default to false"
        );
        assert_eq!(
            config.signing.key_path, "",
            "T-087-14: signing.key_path must default to empty (no embedded key)"
        );
    }

    // T-087-14 (cont.): partial config without a [signing] table falls back to
    // the signing defaults rather than failing to parse.
    #[test]
    fn t087_14_signing_absent_table_uses_defaults() {
        let config = Config::from_toml_str("min_package_age_hours = 24\n").unwrap();
        assert!(!config.signing.offline);
        assert_eq!(config.signing.key_path, "");
    }

    // T-087-13: signing.offline = true parses from TOML.
    #[test]
    fn t087_13_signing_offline_from_toml() {
        let toml_str = "[signing]\noffline = true\nkey_path = \"/tmp/k\"\n";
        let config = Config::from_toml_str(toml_str).unwrap();
        assert!(config.signing.offline, "T-087-13: offline = true parsed");
        assert_eq!(config.signing.key_path, "/tmp/k");
    }

    // T-087-13 (cont.): DEP_SCAN_OFFLINE env var overrides signing.offline from
    // the config file (env takes precedence per the config layering convention).
    #[test]
    fn t087_13_env_offline_overrides_config_false() {
        let _lock = ENV_LOCK.lock().unwrap();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[signing]\noffline = false").unwrap();

        let _guard = EnvGuard::set("DEP_SCAN_OFFLINE", "1");

        let config = Config::load(Some(file.path())).unwrap();
        assert!(
            config.signing.offline,
            "T-087-13: DEP_SCAN_OFFLINE=1 must override signing.offline = false"
        );
    }

    // T-087-13 (cont.): DEP_SCAN_OFFLINE=0 is falsy and does not force offline.
    #[test]
    fn t087_13_env_offline_zero_is_falsy() {
        let _lock = ENV_LOCK.lock().unwrap();

        let _guard = EnvGuard::set("DEP_SCAN_OFFLINE", "0");

        let config = Config::load(None).unwrap();
        assert!(
            !config.signing.offline,
            "T-087-13: DEP_SCAN_OFFLINE=0 is falsy and must not force offline"
        );
    }

    // T-088-17: Default Config has freshness.valid_until_hours == 24
    #[test]
    fn t088_17_default_freshness_valid_until_hours_is_24() {
        // T-088-17
        let config = Config::default();
        assert_eq!(
            config.freshness.valid_until_hours, 24,
            "T-088-17: default freshness.valid_until_hours must be 24"
        );
    }

    // T-088-11: valid_until_hours = 0 is rejected at parse time with an error
    // mentioning valid_until_hours > 0
    #[test]
    fn t088_11_valid_until_hours_zero_rejected() {
        // T-088-11
        let toml_str = "[freshness]\nvalid_until_hours = 0\n";
        let result = Config::from_toml_str(toml_str);
        assert!(
            result.is_err(),
            "T-088-11: valid_until_hours = 0 must return Err"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("valid_until_hours"),
            "T-088-11: error message must mention valid_until_hours, got: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("> 0") || msg.to_lowercase().contains("must be"),
            "T-088-11: error message must state the > 0 constraint, got: {msg}"
        );
    }

    // T-088-10: valid_until_hours = 168 (one week) is accepted
    #[test]
    fn t088_10_valid_until_hours_168_accepted() {
        // T-088-10
        let toml_str = "[freshness]\nvalid_until_hours = 168\n";
        let config =
            Config::from_toml_str(toml_str).expect("T-088-10: 168h must parse without error");
        assert_eq!(
            config.freshness.valid_until_hours, 168,
            "T-088-10: valid_until_hours = 168 must be stored verbatim"
        );
    }

    // T-088-18: write_default produces a [freshness] section with valid_until_hours = 24
    // and a descriptive comment
    #[test]
    fn t088_18_config_init_emits_freshness_section() {
        // T-088-18
        use tempfile::NamedTempFile;
        let f = NamedTempFile::new().expect("tempfile");
        Config::write_default(f.path()).expect("write_default");
        let content = std::fs::read_to_string(f.path()).expect("read config");
        assert!(
            content.contains("[freshness]"),
            "T-088-18: config init must include [freshness] section, got:\n{content}"
        );
        assert!(
            content.contains("valid_until_hours = 24"),
            "T-088-18: config init must include valid_until_hours = 24, got:\n{content}"
        );
        // Must include a descriptive comment
        let has_comment = content
            .lines()
            .any(|l| l.trim_start().starts_with('#') && l.contains("fresh"));
        assert!(
            has_comment,
            "T-088-18: [freshness] section must have a comment explaining the purpose, got:\n{content}"
        );
    }

    // T-048-12: MaintainerChangePolicy is constructed with the first_seen_warning value from config
    #[test]
    fn t048_12_maintainer_policy_wired_from_config() {
        // T-048-12
        use crate::policy::maintainer::MaintainerChangePolicy;
        // Simulate the construction that occurs in main.rs
        let config =
            Config::from_toml_str("[policies]\nmaintainer_first_seen_warning = true\n").unwrap();
        let policy = MaintainerChangePolicy {
            first_seen_warning: config.policies.maintainer_first_seen_warning,
        };
        assert!(
            policy.first_seen_warning,
            "Policy should carry the first_seen_warning flag from config"
        );
    }

    // T-094-17: mutable_git_ref defaults to Warn when no key is in the config
    #[test]
    fn t094_17_mutable_git_ref_defaults_to_warn() {
        // T-094-17
        use crate::policy::mutable_ref::MutableRefSeverity;
        let config = Config::default();
        assert_eq!(
            config.policies.mutable_git_ref,
            MutableRefSeverity::Warn,
            "T-094-17: default mutable_git_ref must be Warn"
        );

        // Also verify that a TOML without the key still defaults to Warn.
        let config2 = Config::from_toml_str("min_package_age_hours = 48\n").unwrap();
        assert_eq!(
            config2.policies.mutable_git_ref,
            MutableRefSeverity::Warn,
            "T-094-17: missing mutable_git_ref key must default to Warn"
        );
    }

    // T-094-19: Unknown mutable_git_ref value returns Err at config load
    #[test]
    fn t094_19_unknown_mutable_git_ref_returns_err() {
        // T-094-19
        let toml_str = "[policies]\nmutable_git_ref = \"explode\"\n";
        let result = Config::from_toml_str(toml_str);
        assert!(
            result.is_err(),
            "T-094-19: unknown mutable_git_ref value must return Err, got Ok"
        );
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("mutable_git_ref"),
            "T-094-19: error message must mention mutable_git_ref, got: {err_msg}"
        );
    }

    // T-095-01: Config::default() has vcs.allowed_hosts = [] and vcs.denied_hosts = []
    #[test]
    fn t095_01_default_vcs_lists_are_empty() {
        // T-095-01
        let config = Config::default();
        assert!(
            config.vcs.allowed_hosts.is_empty(),
            "T-095-01: default vcs.allowed_hosts must be empty"
        );
        assert!(
            config.vcs.denied_hosts.is_empty(),
            "T-095-01: default vcs.denied_hosts must be empty"
        );
    }

    // T-096-07/08: VcsConfig defaults for the fetch timeout and blob-size cap.
    #[test]
    fn t096_vcs_fetch_defaults() {
        let config = Config::default();
        assert_eq!(
            config.vcs.fetch_timeout_secs, 30,
            "REQ-096-07: default vcs.fetch_timeout_secs must be 30"
        );
        assert_eq!(
            config.vcs.max_blob_bytes,
            50 * 1024 * 1024,
            "REQ-096-08: default vcs.max_blob_bytes must be 50 MiB"
        );
    }

    // T-096-07/08: an absent [vcs] section still yields the fetch defaults, and
    // explicit values round-trip through TOML.
    #[test]
    fn t096_vcs_fetch_config_parsing() {
        let absent = Config::from_toml_str("min_package_age_hours = 1\n").unwrap();
        assert_eq!(absent.vcs.fetch_timeout_secs, 30);
        assert_eq!(absent.vcs.max_blob_bytes, 50 * 1024 * 1024);

        let explicit =
            Config::from_toml_str("[vcs]\nfetch_timeout_secs = 5\nmax_blob_bytes = 1024\n")
                .unwrap();
        assert_eq!(explicit.vcs.fetch_timeout_secs, 5);
        assert_eq!(explicit.vcs.max_blob_bytes, 1024);
    }

    // T-095-01 (cont.): Config::load with no [vcs] section uses defaults
    #[test]
    fn t095_01_absent_vcs_section_uses_defaults() {
        // T-095-01
        let config = Config::from_toml_str("min_package_age_hours = 48\n").unwrap();
        assert!(
            config.vcs.allowed_hosts.is_empty(),
            "T-095-01: absent [vcs] section must default to empty allowed_hosts"
        );
        assert!(
            config.vcs.denied_hosts.is_empty(),
            "T-095-01: absent [vcs] section must default to empty denied_hosts"
        );
    }

    // T-095-02: allowed_hosts accepts a list of hostname strings
    #[test]
    fn t095_02_allowed_hosts_parses() {
        // T-095-02
        let toml_str = r#"[vcs]
allowed_hosts = ["github.com", "gitlab.com"]
"#;
        let config = Config::from_toml_str(toml_str).unwrap();
        assert_eq!(
            config.vcs.allowed_hosts,
            vec!["github.com", "gitlab.com"],
            "T-095-02"
        );
    }

    // T-095-03: denied_hosts accepts a list of hostname strings
    #[test]
    fn t095_03_denied_hosts_parses() {
        // T-095-03
        let toml_str = r#"[vcs]
denied_hosts = ["evil.example.com"]
"#;
        let config = Config::from_toml_str(toml_str).unwrap();
        assert_eq!(
            config.vcs.denied_hosts,
            vec!["evil.example.com"],
            "T-095-03"
        );
    }

    // T-095-04: Both lists present simultaneously is valid
    #[test]
    fn t095_04_both_lists_present_valid() {
        // T-095-04
        let toml_str = r#"[vcs]
allowed_hosts = ["github.com"]
denied_hosts = ["evil.example.com"]
"#;
        let result = Config::from_toml_str(toml_str);
        assert!(
            result.is_ok(),
            "T-095-04: both lists must parse without error"
        );
        let config = result.unwrap();
        assert_eq!(config.vcs.allowed_hosts, vec!["github.com"]);
        assert_eq!(config.vcs.denied_hosts, vec!["evil.example.com"]);
    }

    // T-095-05: Non-string entry in host list returns error at config load
    #[test]
    fn t095_05_non_string_entry_returns_error() {
        // T-095-05
        let toml_str = "[vcs]\nallowed_hosts = [123]\n";
        let result = Config::from_toml_str(toml_str);
        assert!(
            result.is_err(),
            "T-095-05: integer in allowed_hosts must return Err, got Ok"
        );
    }

    // T-095-20: config init emits [vcs] section with commented examples
    #[test]
    fn t095_20_config_init_emits_vcs_section() {
        // T-095-20
        use tempfile::NamedTempFile;
        let f = NamedTempFile::new().expect("tempfile");
        Config::write_default(f.path()).expect("write_default");
        let content = std::fs::read_to_string(f.path()).expect("read config");

        assert!(
            content.contains("[vcs]"),
            "T-095-20: config init must include [vcs] section, got:\n{content}"
        );
        // allowed_hosts and denied_hosts must appear as commented-out examples.
        let has_allowed_comment = content
            .lines()
            .any(|l| l.trim_start().starts_with('#') && l.contains("allowed_hosts"));
        assert!(
            has_allowed_comment,
            "T-095-20: [vcs] section must include commented allowed_hosts example, got:\n{content}"
        );
        let has_denied_comment = content
            .lines()
            .any(|l| l.trim_start().starts_with('#') && l.contains("denied_hosts"));
        assert!(
            has_denied_comment,
            "T-095-20: [vcs] section must include commented denied_hosts example, got:\n{content}"
        );
        // Must include a comment explaining that empty lists allow any host.
        let has_explanation = content
            .lines()
            .any(|l| l.trim_start().starts_with('#') && l.contains("any host"));
        assert!(
            has_explanation,
            "T-095-20: [vcs] section must explain that empty lists allow any host, got:\n{content}"
        );
    }

    // T-094-20: config init emits [policies] mutable_git_ref with default and comment
    #[test]
    fn t094_20_config_init_emits_mutable_git_ref() {
        // T-094-20
        use tempfile::NamedTempFile;
        let f = NamedTempFile::new().expect("tempfile");
        Config::write_default(f.path()).expect("write_default");
        let content = std::fs::read_to_string(f.path()).expect("read config");

        assert!(
            content.contains("mutable_git_ref = \"warn\""),
            "T-094-20: config init must include mutable_git_ref = \"warn\", got:\n{content}"
        );
        // Must appear under [policies]
        let policies_pos = content
            .find("[policies]")
            .expect("T-094-20: [policies] section must exist");
        let mutable_ref_pos = content
            .find("mutable_git_ref")
            .expect("T-094-20: mutable_git_ref must appear");
        assert!(
            mutable_ref_pos > policies_pos,
            "T-094-20: mutable_git_ref must appear after [policies] header"
        );
        // Must include a descriptive comment
        let has_comment = content.lines().any(|l| {
            l.trim_start().starts_with('#')
                && (l.contains("mutable") || l.contains("git") || l.contains("branch"))
        });
        assert!(
            has_comment,
            "T-094-20: [policies] section must have a comment about mutable_git_ref, got:\n{content}"
        );
    }
}

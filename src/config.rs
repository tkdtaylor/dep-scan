use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Registry URL configuration for supported package managers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryConfig {
    /// npm registry URL
    #[serde(default = "default_npm_url")]
    pub npm_url: String,
    /// PyPI registry URL
    #[serde(default = "default_pypi_url")]
    pub pypi_url: String,
}

fn default_npm_url() -> String {
    "https://registry.npmjs.org".to_string()
}

fn default_pypi_url() -> String {
    "https://pypi.org".to_string()
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            npm_url: default_npm_url(),
            pypi_url: default_pypi_url(),
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
}

fn default_true() -> bool {
    true
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            check_typosquatting: true,
            check_install_scripts: true,
            check_min_age: true,
            check_maintainer_changes: true,
            check_vulnerabilities: true,
        }
    }
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
        }
    }
}

impl Config {
    /// Parse a Config from a TOML string. Missing fields use defaults.
    pub fn from_toml_str(s: &str) -> Result<Config> {
        let config: Config =
            toml::from_str(s).context("Failed to parse configuration file as valid TOML")?;
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
        if let Ok(val) = std::env::var("DEP_SCAN_CACHE_PATH") {
            self.cache_path = Some(val);
        }
        if let Ok(val) = std::env::var("DEP_SCAN_OSV_URL") {
            self.osv.osv_url = val;
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
    pub fn write_default(path: &Path) -> Result<()> {
        let config = Config::default();
        let content = config.to_toml_string()?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;

    /// Mutex to serialize tests that call Config::load (which reads env vars).
    /// This prevents env var mutations in one test from affecting another.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
}

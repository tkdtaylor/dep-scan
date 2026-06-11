use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::registry::RegistryType;

/// The source of a lockfile dependency — either a package registry or a VCS repository.
///
/// Introduced in task 090 (ADR 008 piece 1) to support git/VCS dependency detection.
/// Replaces the flat `registry: RegistryType` field on `LockfileDependency`.
#[derive(Debug, Clone, PartialEq)]
pub enum DependencySource {
    /// Dependency sourced from a package registry (npm, PyPI, crates.io, Go proxy).
    Registry { registry: RegistryType },
    /// Dependency sourced from a VCS (git) repository.
    /// Parsed by tasks 091/092; routed by task 093.
    #[allow(dead_code)]
    Git { url: String, ref_: String },
}

impl DependencySource {
    /// Return the `RegistryType` if this is a registry-sourced dependency, else `None`.
    pub fn registry_type(&self) -> Option<RegistryType> {
        match self {
            DependencySource::Registry { registry } => Some(*registry),
            DependencySource::Git { .. } => None,
        }
    }

    /// Return the git ref (branch/tag/commit) if this is a git-sourced dependency, else `None`.
    /// Used by task 093 (git-dep routing); suppressed until then.
    #[allow(dead_code)]
    pub fn git_ref(&self) -> Option<&str> {
        match self {
            DependencySource::Git { ref_, .. } => Some(ref_),
            DependencySource::Registry { .. } => None,
        }
    }

    /// Return the git URL if this is a git-sourced dependency, else `None`.
    /// Used by task 093 (git-dep routing); suppressed until then.
    #[allow(dead_code)]
    pub fn git_url(&self) -> Option<&str> {
        match self {
            DependencySource::Git { url, .. } => Some(url),
            DependencySource::Registry { .. } => None,
        }
    }
}

/// A dependency entry parsed from a lockfile.
///
/// T-090-08: The old `registry: RegistryType` flat field has been replaced by
/// `source: DependencySource`.  Any remaining `dep.registry` access will not
/// compile — verified by `cargo build` in the pre-commit gate.
#[derive(Debug, Clone, PartialEq)]
pub struct LockfileDependency {
    pub name: String,
    pub version: String,
    pub source: DependencySource,
}

/// Supported lockfile formats.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LockfileFormat {
    PackageLockJson,
    RequirementsTxt,
    CargoLock,
    GoSum,
}

/// Auto-detect lockfile format from filename.
pub fn detect_format(path: &Path) -> Result<LockfileFormat> {
    match path.file_name().and_then(|n| n.to_str()) {
        Some("package-lock.json") => Ok(LockfileFormat::PackageLockJson),
        Some("requirements.txt") | Some("requirements-dev.txt") => {
            Ok(LockfileFormat::RequirementsTxt)
        }
        Some("Cargo.lock") => Ok(LockfileFormat::CargoLock),
        Some("go.sum") => Ok(LockfileFormat::GoSum),
        Some(name) => bail!("Unknown lockfile format: {name}. Use --lockfile-type to specify."),
        None => bail!("Could not determine filename"),
    }
}

/// Parse a lockfile format string (from --lockfile-type) into a LockfileFormat.
pub fn parse_format_type(type_str: &str) -> Result<LockfileFormat> {
    match type_str.to_lowercase().as_str() {
        "npm" => Ok(LockfileFormat::PackageLockJson),
        "pypi" => Ok(LockfileFormat::RequirementsTxt),
        "crates" => Ok(LockfileFormat::CargoLock),
        "go" => Ok(LockfileFormat::GoSum),
        other => bail!("Unknown lockfile type: {other}. Valid types: npm, pypi, crates, go"),
    }
}

/// Parse a lockfile at the given path.
pub fn parse(path: &Path, format: Option<LockfileFormat>) -> Result<Vec<LockfileDependency>> {
    let format = match format {
        Some(f) => f,
        None => detect_format(path)?,
    };
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read lockfile: {}", path.display()))?;
    match format {
        LockfileFormat::PackageLockJson => parse_package_lock_json(&content),
        LockfileFormat::RequirementsTxt => parse_requirements_txt(&content),
        LockfileFormat::CargoLock => parse_cargo_lock(&content),
        LockfileFormat::GoSum => parse_go_sum(&content),
    }
}

/// Classify an npm `resolved` field value into a `DependencySource`.
///
/// Returns `Some(DependencySource::Git { .. })` when the resolved value indicates a git source:
/// - `git+https://`, `git+ssh://`, `git+http://` prefixes (stripped of `git+`, `#fragment` as ref)
/// - `github:user/repo#ref`, `gitlab:user/repo#ref`, `bitbucket:user/repo#ref` shorthands
///
/// Returns `None` when the resolved value is absent or not a JSON string (caller should skip entry).
/// Returns `Some(DependencySource::Registry { registry: Npm })` for non-git resolved URLs.
/// Degenerate git URLs (e.g. `git+https://`) are stored as-is rather than panicking.
fn classify_npm_resolved(resolved_value: Option<&Value>) -> Option<DependencySource> {
    let resolved_val = resolved_value?;
    // If the resolved field is not a string, return None (skip the entry)
    let resolved = resolved_val.as_str()?;

    // Check for git+ scheme prefixes
    for prefix in &["git+https://", "git+ssh://", "git+http://"] {
        if resolved.starts_with(prefix) {
            // Strip `git+` from the front (4 bytes)
            let without_git_plus = &resolved[4..];
            // Split on `#` to extract ref
            let (url, ref_) = match without_git_plus.find('#') {
                Some(idx) => (&without_git_plus[..idx], &without_git_plus[idx + 1..]),
                None => (without_git_plus, ""),
            };
            return Some(DependencySource::Git {
                url: url.to_string(),
                ref_: ref_.to_string(),
            });
        }
    }

    // Check for shorthand forms: github:, gitlab:, bitbucket:
    let shorthand_expansions: &[(&str, &str)] = &[
        ("github:", "https://github.com/"),
        ("gitlab:", "https://gitlab.com/"),
        ("bitbucket:", "https://bitbucket.org/"),
    ];
    for (shorthand_prefix, canonical_base) in shorthand_expansions {
        if let Some(path_and_ref) = resolved.strip_prefix(shorthand_prefix) {
            let (path, ref_) = match path_and_ref.find('#') {
                Some(idx) => (&path_and_ref[..idx], &path_and_ref[idx + 1..]),
                None => (path_and_ref, ""),
            };
            let url = format!("{}{}", canonical_base, path);
            return Some(DependencySource::Git {
                url,
                ref_: ref_.to_string(),
            });
        }
    }

    // Not a git URL — standard registry dep
    Some(DependencySource::Registry {
        registry: RegistryType::Npm,
    })
}

/// Parse an npm package-lock.json string (v2/v3 `packages` format, with v1 `dependencies` fallback).
pub fn parse_package_lock_json(content: &str) -> Result<Vec<LockfileDependency>> {
    let json: Value =
        serde_json::from_str(content).context("Failed to parse package-lock.json as JSON")?;

    // Try v2/v3 format: "packages" key
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        let mut deps = Vec::new();
        for (key, value) in packages {
            // Skip root entry (empty key)
            if key.is_empty() {
                continue;
            }
            // Extract package name by stripping node_modules/ prefix
            let name = key
                .rsplit("node_modules/")
                .next()
                .unwrap_or(key)
                .to_string();
            if name.is_empty() {
                continue;
            }

            let resolved_field = value.get("resolved");
            let source = match classify_npm_resolved(resolved_field) {
                Some(s) => s,
                // resolved is not a string type — skip this entry
                None if resolved_field.is_some() => continue,
                // No resolved field — fall through to version-based classification
                None => DependencySource::Registry {
                    registry: RegistryType::Npm,
                },
            };

            // For git deps: emit regardless of version field.
            // For registry deps: require a non-empty version.
            let version = value
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if matches!(source, DependencySource::Registry { .. }) && version.is_empty() {
                continue;
            }

            deps.push(LockfileDependency {
                name,
                version,
                source,
            });
        }
        return Ok(deps);
    }

    // Fallback to v1 format: "dependencies" key
    if let Some(dependencies) = json.get("dependencies").and_then(|d| d.as_object()) {
        let mut deps = Vec::new();
        for (name, value) in dependencies {
            let resolved_field = value.get("resolved");
            let source = match classify_npm_resolved(resolved_field) {
                Some(s) => s,
                // resolved is not a string type — skip this entry
                None if resolved_field.is_some() => continue,
                // No resolved field — fall through to version-based classification
                None => DependencySource::Registry {
                    registry: RegistryType::Npm,
                },
            };

            let version = value
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if matches!(source, DependencySource::Registry { .. }) && version.is_empty() {
                continue;
            }

            deps.push(LockfileDependency {
                name: name.clone(),
                version,
                source,
            });
        }
        return Ok(deps);
    }

    // No packages or dependencies key found -- return empty
    Ok(vec![])
}

/// Parse a Python requirements.txt string.
pub fn parse_requirements_txt(content: &str) -> Result<Vec<LockfileDependency>> {
    let mut deps = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip empty lines, comments, and flags (-r, -e, --index-url, etc.)
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }

        // Handle ==, >=, <=, ~=, != operators
        if let Some(idx) = trimmed.find("==") {
            let name = trimmed[..idx].trim().to_string();
            let version = trimmed[idx + 2..].trim().to_string();
            if !name.is_empty() && !version.is_empty() {
                deps.push(LockfileDependency {
                    name,
                    version,
                    source: DependencySource::Registry {
                        registry: RegistryType::PyPI,
                    },
                });
            }
        } else if let Some(idx) = find_version_operator(trimmed) {
            // For >=, <=, ~=, != -- extract name but no pinned version
            let name = trimmed[..idx].trim().to_string();
            if !name.is_empty() {
                deps.push(LockfileDependency {
                    name,
                    version: String::new(),
                    source: DependencySource::Registry {
                        registry: RegistryType::PyPI,
                    },
                });
            }
        } else {
            // Bare package name (no version specifier)
            let name = trimmed.to_string();
            if !name.is_empty() {
                deps.push(LockfileDependency {
                    name,
                    version: String::new(),
                    source: DependencySource::Registry {
                        registry: RegistryType::PyPI,
                    },
                });
            }
        }
    }
    Ok(deps)
}

/// Find the position of a version operator (>=, <=, ~=, !=) in a string.
/// Returns the byte offset of the start of the operator, or None.
fn find_version_operator(s: &str) -> Option<usize> {
    for (i, _) in s.char_indices() {
        if i + 2 <= s.len() {
            let op = &s[i..i + 2];
            if op == ">=" || op == "<=" || op == "~=" || op == "!=" {
                return Some(i);
            }
        }
    }
    None
}

/// Parse a Cargo.lock (TOML) string.
pub fn parse_cargo_lock(content: &str) -> Result<Vec<LockfileDependency>> {
    let parsed: toml::Value =
        toml::from_str(content).context("Failed to parse Cargo.lock as TOML")?;

    let mut deps = Vec::new();

    if let Some(packages) = parsed.get("package").and_then(|p| p.as_array()) {
        for pkg in packages {
            let source = pkg.get("source").and_then(|s| s.as_str());
            // Skip local/path dependencies (no source field)
            if source.is_none() {
                continue;
            }

            let name = pkg
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if !name.is_empty() && !version.is_empty() {
                deps.push(LockfileDependency {
                    name,
                    version,
                    source: DependencySource::Registry {
                        registry: RegistryType::Crates,
                    },
                });
            }
        }
    }

    Ok(deps)
}

/// Parse a Go go.sum string.
pub fn parse_go_sum(content: &str) -> Result<Vec<LockfileDependency>> {
    let mut seen = std::collections::HashSet::new();
    let mut deps = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Format: module version hash
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let module = parts[0].to_string();
        let mut version = parts[1].to_string();

        // Strip /go.mod suffix from version
        if version.ends_with("/go.mod") {
            version = version[..version.len() - 7].to_string();
        }

        let key = (module.clone(), version.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        deps.push(LockfileDependency {
            name: module,
            version,
            source: DependencySource::Registry {
                registry: RegistryType::Go,
            },
        });
    }

    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-023-01: Parse package-lock.json
    #[test]
    fn parse_package_lock_json_v2() {
        let content = r#"{
            "name": "my-project",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-project",
                    "version": "1.0.0"
                },
                "node_modules/express": {
                    "version": "4.18.2"
                },
                "node_modules/lodash": {
                    "version": "4.17.21"
                },
                "node_modules/debug": {
                    "version": "4.3.4"
                }
            }
        }"#;

        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 3);

        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"debug"));

        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert_eq!(express.version, "4.18.2");
        assert_eq!(
            express.source,
            DependencySource::Registry {
                registry: RegistryType::Npm
            }
        );

        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.21");
    }

    // T-023-01b: Parse package-lock.json v1 fallback (dependencies key)
    #[test]
    fn parse_package_lock_json_v1_fallback() {
        let content = r#"{
            "name": "my-project",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2"
                },
                "lodash": {
                    "version": "4.17.21"
                }
            }
        }"#;

        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 2);

        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert_eq!(express.version, "4.18.2");
        assert_eq!(
            express.source,
            DependencySource::Registry {
                registry: RegistryType::Npm
            }
        );
    }

    // T-023-01c: Scoped packages in package-lock.json
    #[test]
    fn parse_package_lock_json_scoped_packages() {
        let content = r#"{
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/@types/node": {
                    "version": "20.11.0"
                }
            }
        }"#;

        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "@types/node");
        assert_eq!(deps[0].version, "20.11.0");
    }

    // T-023-02: Parse requirements.txt
    #[test]
    fn parse_requirements_txt_basic() {
        let content = "requests==2.31.0\nflask==3.0.0\n# comment\n-r other.txt\n";
        let deps = parse_requirements_txt(content).unwrap();
        assert_eq!(deps.len(), 2);

        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, "2.31.0");
        assert_eq!(
            deps[0].source,
            DependencySource::Registry {
                registry: RegistryType::PyPI
            }
        );

        assert_eq!(deps[1].name, "flask");
        assert_eq!(deps[1].version, "3.0.0");
    }

    // T-023-02b: requirements.txt with non-pinned versions
    #[test]
    fn parse_requirements_txt_version_operators() {
        let content = "numpy>=1.24\nscipy<=2.0\nmatplotlib~=3.7\npandas!=1.5.0\nbare-pkg\n";
        let deps = parse_requirements_txt(content).unwrap();
        assert_eq!(deps.len(), 5);

        // Non-pinned versions have empty version string
        assert_eq!(deps[0].name, "numpy");
        assert_eq!(deps[0].version, "");

        assert_eq!(deps[1].name, "scipy");
        assert_eq!(deps[1].version, "");

        assert_eq!(deps[4].name, "bare-pkg");
        assert_eq!(deps[4].version, "");
    }

    // T-023-02c: requirements.txt skips all flag-like lines
    #[test]
    fn parse_requirements_txt_skips_flags() {
        let content = "-r base.txt\n-e .\n--index-url https://example.com\nrequests==2.31.0\n";
        let deps = parse_requirements_txt(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
    }

    // T-023-03: Parse Cargo.lock
    #[test]
    fn parse_cargo_lock_basic() {
        let content = r#"
[[package]]
name = "my-project"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde_json"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

        let deps = parse_cargo_lock(content).unwrap();
        // Should skip "my-project" (no source = local dependency)
        assert_eq!(deps.len(), 2);

        let serde = deps.iter().find(|d| d.name == "serde").unwrap();
        assert_eq!(serde.version, "1.0.228");
        assert_eq!(
            serde.source,
            DependencySource::Registry {
                registry: RegistryType::Crates
            }
        );

        let serde_json = deps.iter().find(|d| d.name == "serde_json").unwrap();
        assert_eq!(serde_json.version, "1.0.100");
    }

    // T-023-04: Parse go.sum
    #[test]
    fn parse_go_sum_basic() {
        let content = "github.com/gin-gonic/gin v1.9.1 h1:abc=\ngithub.com/gin-gonic/gin v1.9.1/go.mod h1:def=\n";
        let deps = parse_go_sum(content).unwrap();
        // Should deduplicate: same module+version appears twice
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[0].version, "v1.9.1");
        assert_eq!(
            deps[0].source,
            DependencySource::Registry {
                registry: RegistryType::Go
            }
        );
    }

    // T-023-04b: go.sum with multiple modules
    #[test]
    fn parse_go_sum_multiple_modules() {
        let content = "github.com/gin-gonic/gin v1.9.1 h1:abc=\ngithub.com/gin-gonic/gin v1.9.1/go.mod h1:def=\ngithub.com/stretchr/testify v1.8.4 h1:ghi=\n";
        let deps = parse_go_sum(content).unwrap();
        assert_eq!(deps.len(), 2);

        let gin = deps.iter().find(|d| d.name.contains("gin")).unwrap();
        assert_eq!(gin.version, "v1.9.1");

        let testify = deps.iter().find(|d| d.name.contains("testify")).unwrap();
        assert_eq!(testify.version, "v1.8.4");
    }

    // T-023-05: Auto-detect format from filename
    #[test]
    fn detect_format_from_filename() {
        assert_eq!(
            detect_format(Path::new("package-lock.json")).unwrap(),
            LockfileFormat::PackageLockJson
        );
        assert_eq!(
            detect_format(Path::new("requirements.txt")).unwrap(),
            LockfileFormat::RequirementsTxt
        );
        assert_eq!(
            detect_format(Path::new("requirements-dev.txt")).unwrap(),
            LockfileFormat::RequirementsTxt
        );
        assert_eq!(
            detect_format(Path::new("Cargo.lock")).unwrap(),
            LockfileFormat::CargoLock
        );
        assert_eq!(
            detect_format(Path::new("go.sum")).unwrap(),
            LockfileFormat::GoSum
        );
    }

    // T-023-05b: Unknown filename returns error
    #[test]
    fn detect_format_unknown_returns_error() {
        let result = detect_format(Path::new("unknown.lock"));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unknown lockfile format"));
        assert!(err_msg.contains("--lockfile-type"));
    }

    // T-023-05c: Path with directories still detects correctly
    #[test]
    fn detect_format_with_directory_path() {
        assert_eq!(
            detect_format(Path::new("/some/dir/package-lock.json")).unwrap(),
            LockfileFormat::PackageLockJson
        );
        assert_eq!(
            detect_format(Path::new("./project/Cargo.lock")).unwrap(),
            LockfileFormat::CargoLock
        );
    }

    // T-023-06: parse_format_type for --lockfile-type override
    #[test]
    fn parse_format_type_valid() {
        assert_eq!(
            parse_format_type("npm").unwrap(),
            LockfileFormat::PackageLockJson
        );
        assert_eq!(
            parse_format_type("pypi").unwrap(),
            LockfileFormat::RequirementsTxt
        );
        assert_eq!(
            parse_format_type("crates").unwrap(),
            LockfileFormat::CargoLock
        );
        assert_eq!(parse_format_type("go").unwrap(), LockfileFormat::GoSum);
    }

    // T-023-06b: parse_format_type with invalid type
    #[test]
    fn parse_format_type_invalid() {
        let result = parse_format_type("maven");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unknown lockfile type")
        );
    }

    // T-023-06c: parse_format_type is case-insensitive
    #[test]
    fn parse_format_type_case_insensitive() {
        assert_eq!(
            parse_format_type("NPM").unwrap(),
            LockfileFormat::PackageLockJson
        );
        assert_eq!(
            parse_format_type("PyPI").unwrap(),
            LockfileFormat::RequirementsTxt
        );
    }

    // T-023-07: Malformed input returns error
    #[test]
    fn malformed_package_lock_json_returns_error() {
        let content = "this is not json at all";
        let result = parse_package_lock_json(content);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse package-lock.json")
        );
    }

    // T-023-07b: Malformed Cargo.lock returns error
    #[test]
    fn malformed_cargo_lock_returns_error() {
        let content = "[[invalid toml";
        let result = parse_cargo_lock(content);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse Cargo.lock")
        );
    }

    // T-023-08: Empty lockfile returns empty Vec
    #[test]
    fn empty_package_lock_json_returns_empty() {
        let content = "{}";
        let deps = parse_package_lock_json(content).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn empty_requirements_txt_returns_empty() {
        let content = "";
        let deps = parse_requirements_txt(content).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn empty_cargo_lock_returns_empty() {
        // Minimal valid TOML with no packages
        let content = "version = 3\n";
        let deps = parse_cargo_lock(content).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn empty_go_sum_returns_empty() {
        let content = "";
        let deps = parse_go_sum(content).unwrap();
        assert!(deps.is_empty());
    }

    // T-023-06d: parse with format override via temp file
    #[test]
    fn parse_with_format_override() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("deps.txt");
        std::fs::write(&file_path, "requests==2.31.0\nflask==3.0.0\n").unwrap();

        let deps = parse(&file_path, Some(LockfileFormat::RequirementsTxt)).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "requests");
    }

    // Test that parse auto-detects from the filename
    #[test]
    fn parse_auto_detects_requirements_txt() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("requirements.txt");
        std::fs::write(&file_path, "requests==2.31.0\n").unwrap();

        let deps = parse(&file_path, None).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
    }

    // Test that parse returns error for missing file
    #[test]
    fn parse_missing_file_returns_error() {
        let result = parse(Path::new("/nonexistent/requirements.txt"), None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to read lockfile")
        );
    }

    // Test nested node_modules paths in package-lock.json
    #[test]
    fn parse_package_lock_nested_node_modules() {
        let content = r#"{
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/express": { "version": "4.18.2" },
                "node_modules/express/node_modules/debug": { "version": "2.6.9" }
            }
        }"#;

        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 2);
        // Nested dep should extract the last component after node_modules/
        let debug = deps.iter().find(|d| d.name == "debug").unwrap();
        assert_eq!(debug.version, "2.6.9");
    }

    // Test requirements.txt with whitespace and blank lines
    #[test]
    fn parse_requirements_txt_whitespace() {
        let content = "  requests==2.31.0  \n\n\n  flask==3.0.0  \n  \n";
        let deps = parse_requirements_txt(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[1].name, "flask");
    }

    // Test Cargo.lock with git source
    #[test]
    fn parse_cargo_lock_git_source() {
        let content = r#"
[[package]]
name = "my-project"
version = "0.1.0"

[[package]]
name = "some-crate"
version = "0.5.0"
source = "git+https://github.com/user/repo#abcdef"
"#;

        let deps = parse_cargo_lock(content).unwrap();
        // git source packages should still be included
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "some-crate");
    }

    // --- T-090 tests: DependencySource enum ---

    // T-090-01: DependencySource::Registry carries RegistryType
    #[test]
    fn t090_01_registry_source_carries_registry_type() {
        let source = DependencySource::Registry {
            registry: RegistryType::Npm,
        };
        assert_eq!(source.registry_type(), Some(RegistryType::Npm));
    }

    // T-090-02: DependencySource::Git carries url and ref_ strings
    #[test]
    fn t090_02_git_source_carries_url_and_ref() {
        let source = DependencySource::Git {
            url: "https://github.com/user/repo".into(),
            ref_: "abc123".into(),
        };
        assert_eq!(source.git_url(), Some("https://github.com/user/repo"));
        assert_eq!(source.git_ref(), Some("abc123"));
    }

    // T-090-03: DependencySource::Registry returns None for git_ref()
    #[test]
    fn t090_03_registry_source_git_ref_is_none() {
        let source = DependencySource::Registry {
            registry: RegistryType::Crates,
        };
        assert_eq!(source.git_ref(), None);
    }

    // T-090-04: DependencySource::Git returns None for registry_type()
    #[test]
    fn t090_04_git_source_registry_type_is_none() {
        let source = DependencySource::Git {
            url: "https://github.com/user/repo".into(),
            ref_: "main".into(),
        };
        assert_eq!(source.registry_type(), None);
    }

    // T-090-05: DependencySource implements Debug, Clone, PartialEq
    #[test]
    fn t090_05_dependency_source_derives() {
        // Two identical Git values compare equal
        let a = DependencySource::Git {
            url: "https://github.com/a/b".into(),
            ref_: "main".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);

        // Two identical Registry values compare equal
        let c = DependencySource::Registry {
            registry: RegistryType::Npm,
        };
        let d = c.clone();
        assert_eq!(c, d);

        // Registry(Npm) != Registry(PyPI)
        let e = DependencySource::Registry {
            registry: RegistryType::PyPI,
        };
        assert_ne!(c, e);

        // Git { url: "a", ref_: "b" } != Git { url: "a", ref_: "c" }
        let f = DependencySource::Git {
            url: "https://github.com/a/b".into(),
            ref_: "other".into(),
        };
        assert_ne!(a, f);

        // Debug is implemented (just check it doesn't panic)
        let _ = format!("{:?}", a);
    }

    // T-090-06: LockfileDependency has a source: DependencySource field
    #[test]
    fn t090_06_lockfile_dep_has_source_field() {
        let dep = LockfileDependency {
            name: "foo".into(),
            version: "1.0.0".into(),
            source: DependencySource::Registry {
                registry: RegistryType::Npm,
            },
        };
        assert_eq!(dep.name, "foo");
        assert_eq!(dep.version, "1.0.0");
        assert_eq!(
            dep.source,
            DependencySource::Registry {
                registry: RegistryType::Npm
            }
        );
    }

    // T-090-07: A git-sourced LockfileDependency can be constructed and round-trips through Clone
    #[test]
    fn t090_07_git_sourced_lockfile_dep_roundtrips() {
        let dep = LockfileDependency {
            name: "evil-pkg".into(),
            version: "".into(),
            source: DependencySource::Git {
                url: "https://github.com/evil/repo".into(),
                ref_: "main".into(),
            },
        };
        let cloned = dep.clone();
        assert_eq!(dep, cloned);
        assert_eq!(
            cloned.source.git_url(),
            Some("https://github.com/evil/repo")
        );
        assert_eq!(cloned.source.git_ref(), Some("main"));
    }

    // T-090-09: parse_package_lock_json produces DependencySource::Registry { registry: Npm }
    #[test]
    fn t090_09_npm_parser_produces_registry_source() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.21" }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Registry {
                registry: RegistryType::Npm
            }
        );
    }

    // T-090-10: parse_cargo_lock produces DependencySource::Registry { registry: Crates }
    #[test]
    fn t090_10_cargo_parser_produces_registry_source() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Registry {
                registry: RegistryType::Crates
            }
        );
    }

    // T-090-11: parse_requirements_txt produces DependencySource::Registry { registry: PyPI }
    #[test]
    fn t090_11_pypi_parser_produces_registry_source() {
        let content = "requests==2.31.0\n";
        let deps = parse_requirements_txt(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Registry {
                registry: RegistryType::PyPI
            }
        );
    }

    // T-090-12: parse_go_sum produces DependencySource::Registry { registry: Go }
    #[test]
    fn t090_12_go_parser_produces_registry_source() {
        let content =
            "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt38=\n";
        let deps = parse_go_sum(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Registry {
                registry: RegistryType::Go
            }
        );
    }

    // --- T-091 tests: npm lockfile git URL parser ---

    // T-091-01: git+https:// resolved URL is recognised
    #[test]
    fn t091_01_git_https_resolved_url_recognised() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/user/repo.git#abc1234"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "https://github.com/user/repo.git".to_string(),
                ref_: "abc1234".to_string(),
            }
        );
    }

    // T-091-02: git+ssh:// resolved URL is recognised
    #[test]
    fn t091_02_git_ssh_resolved_url_recognised() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "git+ssh://git@github.com/user/repo.git#abc1234"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "ssh://git@github.com/user/repo.git".to_string(),
                ref_: "abc1234".to_string(),
            }
        );
    }

    // T-091-03: git+http:// resolved URL is recognised
    #[test]
    fn t091_03_git_http_resolved_url_recognised() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "git+http://git.example.com/org/repo#deadbeef"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "http://git.example.com/org/repo".to_string(),
                ref_: "deadbeef".to_string(),
            }
        );
    }

    // T-091-04: github: shorthand is recognised and expanded
    #[test]
    fn t091_04_github_shorthand_recognised() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "github:user/repo#abc1234"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "https://github.com/user/repo".to_string(),
                ref_: "abc1234".to_string(),
            }
        );
    }

    // T-091-05: gitlab: shorthand is recognised and expanded
    #[test]
    fn t091_05_gitlab_shorthand_recognised() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "gitlab:user/repo#abc1234"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "https://gitlab.com/user/repo".to_string(),
                ref_: "abc1234".to_string(),
            }
        );
    }

    // T-091-06: bitbucket: shorthand is recognised and expanded
    #[test]
    fn t091_06_bitbucket_shorthand_recognised() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "bitbucket:user/repo#abc1234"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "https://bitbucket.org/user/repo".to_string(),
                ref_: "abc1234".to_string(),
            }
        );
    }

    // T-091-07: Package name is preserved from the lockfile key
    #[test]
    fn t091_07_package_name_preserved() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/evil-pkg": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/bad/evil#main"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "evil-pkg");
    }

    // T-091-08: Non-git resolved URL does not trigger git parsing
    #[test]
    fn t091_08_non_git_resolved_url_stays_registry() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/express": {
                    "version": "4.18.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Registry {
                registry: RegistryType::Npm
            }
        );
    }

    // T-091-09: Ref is extracted from the # fragment
    #[test]
    fn t091_09_ref_extracted_from_fragment() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/user/repo#abc1234def5678901234567890abcdef12345678"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source.git_ref(),
            Some("abc1234def5678901234567890abcdef12345678")
        );
    }

    // T-091-10: URL without # fragment gets empty ref
    #[test]
    fn t091_10_url_without_fragment_empty_ref() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/user/repo"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "https://github.com/user/repo".to_string(),
                ref_: "".to_string(),
            }
        );
    }

    // T-091-11: # in URL but no ref after it gets empty ref
    #[test]
    fn t091_11_hash_with_no_ref_gives_empty_ref() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/user/repo#"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].source.git_ref(), Some(""));
    }

    // T-091-12: Entry with empty version but git resolved is no longer dropped
    #[test]
    fn t091_12_empty_version_git_resolved_not_dropped() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "",
                    "resolved": "git+https://github.com/user/repo#abc"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert!(matches!(deps[0].source, DependencySource::Git { .. }));
    }

    // T-091-13: Entry with placeholder version and git resolved emits Git dep, not Registry dep
    #[test]
    fn t091_13_placeholder_version_git_resolved_emits_git() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/user/repo#abc"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert!(matches!(deps[0].source, DependencySource::Git { .. }));
    }

    // T-091-14: Lockfile with both registry and git deps produces both kinds
    #[test]
    fn t091_14_mixed_lockfile_produces_both_kinds() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/express": {
                    "version": "4.18.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
                },
                "node_modules/evil-pkg": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/bad/evil#main"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 2);

        let registry_deps: Vec<_> = deps
            .iter()
            .filter(|d| matches!(d.source, DependencySource::Registry { .. }))
            .collect();
        let git_deps: Vec<_> = deps
            .iter()
            .filter(|d| matches!(d.source, DependencySource::Git { .. }))
            .collect();
        assert_eq!(registry_deps.len(), 1);
        assert_eq!(git_deps.len(), 1);
    }

    // T-091-15: v1 dependencies format also parses git resolved URLs
    #[test]
    fn t091_15_v1_dependencies_format_parses_git_resolved() {
        let content = r#"{
            "name": "my-project",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "mypkg": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/user/repo#abc"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "https://github.com/user/repo".to_string(),
                ref_: "abc".to_string(),
            }
        );
    }

    // T-091-16: Scoped package with git resolved preserves scoped name
    #[test]
    fn t091_16_scoped_package_git_resolved_preserves_name() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/@myorg/mylib": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/myorg/mylib#abc"
                }
            }
        }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "@myorg/mylib");
    }

    // T-091-17: Truncated git URL (no host, no path) is stored as-is, not panicked
    #[test]
    fn t091_17_truncated_git_url_stored_as_is_no_panic() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": "git+https://"
                }
            }
        }"#;
        // Must not panic
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert!(matches!(deps[0].source, DependencySource::Git { .. }));
        // The url stored is whatever follows git+
        assert_eq!(deps[0].source.git_url(), Some("https://"));
    }

    // T-091-18: resolved value is not a string (JSON number) — entry is skipped, no panic
    #[test]
    fn t091_18_resolved_not_string_entry_skipped_no_panic() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/mypkg": {
                    "version": "1.0.0",
                    "resolved": 12345
                }
            }
        }"#;
        // Must not panic; entry with non-string resolved is skipped
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 0);
    }
}

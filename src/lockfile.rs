use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::registry::RegistryType;

/// A dependency entry parsed from a lockfile.
#[derive(Debug, Clone, PartialEq)]
pub struct LockfileDependency {
    pub name: String,
    pub version: String,
    pub registry: RegistryType,
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
            let version = value
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if version.is_empty() {
                continue;
            }
            deps.push(LockfileDependency {
                name,
                version,
                registry: RegistryType::Npm,
            });
        }
        return Ok(deps);
    }

    // Fallback to v1 format: "dependencies" key
    if let Some(dependencies) = json.get("dependencies").and_then(|d| d.as_object()) {
        let mut deps = Vec::new();
        for (name, value) in dependencies {
            let version = value
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if version.is_empty() {
                continue;
            }
            deps.push(LockfileDependency {
                name: name.clone(),
                version,
                registry: RegistryType::Npm,
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
                    registry: RegistryType::PyPI,
                });
            }
        } else if let Some(idx) = find_version_operator(trimmed) {
            // For >=, <=, ~=, != -- extract name but no pinned version
            let name = trimmed[..idx].trim().to_string();
            if !name.is_empty() {
                deps.push(LockfileDependency {
                    name,
                    version: String::new(),
                    registry: RegistryType::PyPI,
                });
            }
        } else {
            // Bare package name (no version specifier)
            let name = trimmed.to_string();
            if !name.is_empty() {
                deps.push(LockfileDependency {
                    name,
                    version: String::new(),
                    registry: RegistryType::PyPI,
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
                    registry: RegistryType::Crates,
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
            registry: RegistryType::Go,
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
        assert_eq!(express.registry, RegistryType::Npm);

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
        assert_eq!(express.registry, RegistryType::Npm);
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
        assert_eq!(deps[0].registry, RegistryType::PyPI);

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
        assert_eq!(serde.registry, RegistryType::Crates);

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
        assert_eq!(deps[0].registry, RegistryType::Go);
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
}

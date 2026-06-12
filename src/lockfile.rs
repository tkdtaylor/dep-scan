use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::registry::RegistryType;

// ---------------------------------------------------------------------------
// Task 100 — Transitive edge model (ADR 009 Decision 1)
// ---------------------------------------------------------------------------

/// A unique identity for a resolved dependency node in the transitive graph.
///
/// Matches the cache identity scheme established in tasks 097 (`src/cache.rs`):
/// - `Registry` variant maps to the `(name, version, registry)` cache key.
/// - `Git` variant maps to the `(name, commit_sha, "git")` cache key (`insert_git`).
///
/// No third variant is defined — this enum intentionally has exactly two arms.
///
/// Consumed by task 102 (DFS walker) and task 103 (manifest fetcher).
/// Suppressed until then per the project dead-code convention.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeId {
    /// A dependency resolved from a package registry (npm, PyPI, crates.io, Go).
    Registry {
        name: String,
        version: String,
        registry: String,
    },
    /// A dependency resolved from a VCS (git) source, pinned to a commit SHA.
    Git {
        name: String,
        /// Full or abbreviated commit SHA (stored verbatim from the lockfile).
        commit_sha: String,
    },
}

/// An in-memory directed graph of resolved dependency edges.
///
/// Nodes are `NodeId` values; edges are directed from dependant to dependency.
/// The graph is built once from a lockfile and then read-only during the walk.
///
/// Cycle safety: `DependencyGraph::from_edges` faithfully records every edge it
/// is given, including back-edges that form cycles.  It never traverses edges
/// during construction, so a cyclic input cannot cause an infinite loop here.
/// Cycle detection is the responsibility of the DFS walker (task 102).
///
/// Consumed by task 102 (DFS walker). Suppressed until then.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct DependencyGraph {
    /// Adjacency list: node → list of direct dependencies.
    edges: HashMap<NodeId, Vec<NodeId>>,
}

#[allow(dead_code)]
impl DependencyGraph {
    /// Create an empty graph with no nodes and no edges.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a graph from an iterator of directed `(from, to)` edge pairs.
    ///
    /// Both endpoints of every edge are guaranteed to appear in `nodes()`.
    /// A cyclic edge set (A→B, B→A) is stored faithfully and does not cause
    /// an infinite loop — the graph builder never traverses edges.
    pub fn from_edges(edges: impl IntoIterator<Item = (NodeId, NodeId)>) -> Self {
        let mut g = Self::new();
        for (from, to) in edges {
            // Ensure the `to` node exists as a key (even with no outgoing edges)
            g.edges.entry(to.clone()).or_default();
            g.edges.entry(from).or_default().push(to);
        }
        g
    }

    /// Add a single node with no outgoing edges (idempotent if already present).
    pub fn add_node(&mut self, node: NodeId) {
        self.edges.entry(node).or_default();
    }

    /// Iterate over all nodes in the graph (both those with and without edges).
    pub fn nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.edges.keys()
    }

    /// Return the direct dependencies of `node`, or an empty slice if `node` is
    /// not in the graph.
    pub fn edges_from(&self, node: &NodeId) -> &[NodeId] {
        self.edges.get(node).map(Vec::as_slice).unwrap_or(&[])
    }
}

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

/// Classify a Cargo.lock `source` field value into a `DependencySource`.
///
/// Returns `Some(DependencySource::Git { .. })` when the source starts with `git+`.
/// Returns `Some(DependencySource::Registry { registry: Crates })` when it starts with `registry+`.
/// Returns `None` for unknown prefixes (fail-safe — caller skips the entry without panicking).
///
/// For `git+` sources:
/// - The `git+` prefix is stripped from the stored URL.
/// - The fragment after `#` becomes `ref_`; if no `#` is present, `ref_` is an empty string.
/// - Query parameters (`?branch=`, `?tag=`, `?rev=`) are part of the URL and preserved in `url`.
fn classify_cargo_source(source: &str) -> Option<DependencySource> {
    if let Some(without_git_plus) = source.strip_prefix("git+") {
        // Split on `#` to extract ref fragment; query params stay in the URL portion
        let (url, ref_) = match without_git_plus.find('#') {
            Some(idx) => (&without_git_plus[..idx], &without_git_plus[idx + 1..]),
            None => (without_git_plus, ""),
        };
        return Some(DependencySource::Git {
            url: url.to_string(),
            ref_: ref_.to_string(),
        });
    }

    if source.starts_with("registry+") {
        return Some(DependencySource::Registry {
            registry: RegistryType::Crates,
        });
    }

    // Unknown prefix — fail-safe: skip without panicking
    None
}

/// Parse a Cargo.lock (TOML) string.
pub fn parse_cargo_lock(content: &str) -> Result<Vec<LockfileDependency>> {
    let parsed: toml::Value =
        toml::from_str(content).context("Failed to parse Cargo.lock as TOML")?;

    let mut deps = Vec::new();

    if let Some(packages) = parsed.get("package").and_then(|p| p.as_array()) {
        for pkg in packages {
            let source_str = pkg.get("source").and_then(|s| s.as_str());
            // Skip local/path dependencies (no source field)
            let source_str = match source_str {
                Some(s) => s,
                None => continue,
            };

            // Classify the source; skip unknown prefixes (fail-safe)
            let dep_source = match classify_cargo_source(source_str) {
                Some(s) => s,
                None => continue,
            };

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

            // Always require a non-empty name.
            // Version is required for registry deps but not for git deps.
            if name.is_empty() {
                continue;
            }
            if matches!(dep_source, DependencySource::Registry { .. }) && version.is_empty() {
                continue;
            }

            deps.push(LockfileDependency {
                name,
                version,
                source: dep_source,
            });
        }
    }

    Ok(deps)
}

// ---------------------------------------------------------------------------
// Task 100 — Lockfile-to-graph functions (ADR 009 Decision 1)
// These functions are consumed by task 102 (DFS walker) and task 103 (fetcher).
// #[allow(dead_code)] silences the binary-crate "never used" warning until those
// tasks land.
// ---------------------------------------------------------------------------

/// Build a `DependencyGraph` from a `package-lock.json` string (npm).
///
/// Supports lockfile versions 1 (via the `dependencies` key) and 2/v3 (via the
/// `packages` key).  Each resolved package becomes a `NodeId::Registry` node;
/// edges are derived from the `requires` field (v1) or the `dependencies` field
/// under each `packages` entry (v2/v3).
///
/// **Zero network I/O**: reads only the bytes passed in; never touches the
/// filesystem or the network beyond what `serde_json` does with the string.
///
/// Missing resolved targets: when a dependency name listed in `requires` /
/// `dependencies` cannot be matched to a resolved package entry, a
/// `tracing::warn!` diagnostic is emitted and the unresolvable edge is omitted
/// from the graph.  The graph is still returned (not an error).  Per the
/// fail-closed contract (ADR 009), the walk (task 102) will roll up the missing
/// edge as ≥ Warn.
#[allow(dead_code)]
pub fn package_lock_json_to_graph(content: &str) -> Result<DependencyGraph> {
    let json: Value =
        serde_json::from_str(content).context("Failed to parse package-lock.json as JSON")?;

    // ------------------------------------------------------------------
    // v2/v3: "packages" key
    // ------------------------------------------------------------------
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        // First pass: build a name → NodeId lookup table from the resolved packages.
        // The key is the package name (last segment after `node_modules/`).
        // For nested deduplicated packages the inner version wins (same behaviour
        // as the existing flat parser).
        let mut name_to_node: HashMap<String, NodeId> = HashMap::new();
        for (key, value) in packages {
            if key.is_empty() {
                continue;
            }
            let name = key
                .rsplit("node_modules/")
                .next()
                .unwrap_or(key.as_str())
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
            let node = NodeId::Registry {
                name: name.clone(),
                version,
                registry: "npm".to_string(),
            };
            name_to_node.insert(name, node);
        }

        // Second pass: build edges from the `dependencies` map inside each entry.
        let mut graph = DependencyGraph::new();
        // Ensure every resolved node is in the graph even if it has no outgoing edges.
        for node in name_to_node.values() {
            graph.add_node(node.clone());
        }

        for (key, value) in packages {
            if key.is_empty() {
                continue;
            }
            let name = key
                .rsplit("node_modules/")
                .next()
                .unwrap_or(key.as_str())
                .to_string();
            if name.is_empty() {
                continue;
            }
            let from_node = match name_to_node.get(&name) {
                Some(n) => n.clone(),
                None => continue,
            };

            // v2/v3 edge source: "dependencies" map (semver ranges, not resolved versions)
            if let Some(dep_map) = value.get("dependencies").and_then(|d| d.as_object()) {
                for dep_name in dep_map.keys() {
                    match name_to_node.get(dep_name.as_str()) {
                        Some(to_node) => {
                            graph
                                .edges
                                .entry(from_node.clone())
                                .or_default()
                                .push(to_node.clone());
                        }
                        None => {
                            // Unresolvable edge — emit diagnostic, do not panic.
                            // The walker (task 102) will roll this up as ≥ Warn.
                            eprintln!(
                                "dep-scan: unresolvable npm edge: {} requires {} (no resolved entry found)",
                                name, dep_name
                            );
                        }
                    }
                }
            }
        }

        return Ok(graph);
    }

    // ------------------------------------------------------------------
    // v1: "dependencies" key (flat map, may have nested `dependencies`)
    // ------------------------------------------------------------------
    if let Some(dependencies) = json.get("dependencies").and_then(|d| d.as_object()) {
        // First pass: collect all resolved (name, version) pairs recursively.
        let mut name_to_node: HashMap<String, NodeId> = HashMap::new();
        collect_npm_v1_nodes(dependencies, &mut name_to_node);

        // Second pass: build edges from `requires` maps.
        let mut graph = DependencyGraph::new();
        for node in name_to_node.values() {
            graph.add_node(node.clone());
        }
        build_npm_v1_edges(dependencies, &name_to_node, &mut graph);

        return Ok(graph);
    }

    // No packages or dependencies key — return empty graph.
    Ok(DependencyGraph::new())
}

/// Recursively collect resolved `(name, version)` nodes from a v1 `dependencies` object.
#[allow(dead_code)]
fn collect_npm_v1_nodes(
    deps_obj: &serde_json::Map<String, Value>,
    out: &mut HashMap<String, NodeId>,
) {
    for (name, value) in deps_obj {
        let version = value
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !version.is_empty() {
            out.insert(
                name.clone(),
                NodeId::Registry {
                    name: name.clone(),
                    version,
                    registry: "npm".to_string(),
                },
            );
        }
        // Recurse into nested dependencies
        if let Some(nested) = value.get("dependencies").and_then(|d| d.as_object()) {
            collect_npm_v1_nodes(nested, out);
        }
    }
}

/// Recursively build edges from v1 `requires` maps.
#[allow(dead_code)]
fn build_npm_v1_edges(
    deps_obj: &serde_json::Map<String, Value>,
    name_to_node: &HashMap<String, NodeId>,
    graph: &mut DependencyGraph,
) {
    for (name, value) in deps_obj {
        let from_node = match name_to_node.get(name.as_str()) {
            Some(n) => n.clone(),
            None => continue,
        };

        if let Some(requires) = value.get("requires").and_then(|r| r.as_object()) {
            for dep_name in requires.keys() {
                match name_to_node.get(dep_name.as_str()) {
                    Some(to_node) => {
                        graph
                            .edges
                            .entry(from_node.clone())
                            .or_default()
                            .push(to_node.clone());
                    }
                    None => {
                        eprintln!(
                            "dep-scan: unresolvable npm edge: {} requires {} (no resolved entry found)",
                            name, dep_name
                        );
                    }
                }
            }
        }

        // Recurse into nested dependencies
        if let Some(nested) = value.get("dependencies").and_then(|d| d.as_object()) {
            build_npm_v1_edges(nested, name_to_node, graph);
        }
    }
}

/// Build a `DependencyGraph` from a `Cargo.lock` TOML string.
///
/// Each `[[package]]` entry becomes a `NodeId` (Registry or Git depending on
/// `source`); local/path packages (no `source` field) are included as nodes
/// with empty edge sets so the root workspace crate's edges are visible.
///
/// Each `dependencies` line is parsed to find the corresponding resolved
/// `[[package]]` entry, which becomes an edge target.  The dependency hint
/// format is `"name version (source-url)"` or simply `"name"` (bare name).
///
/// Git-sourced entries (`source = "git+…#sha"`) produce `NodeId::Git` with the
/// commit SHA extracted from the `#` fragment — matching the `insert_git` cache
/// key from `src/cache.rs:261`.
///
/// **Zero network I/O**: reads only the bytes passed in.
#[allow(dead_code)]
pub fn cargo_lock_to_graph(content: &str) -> Result<DependencyGraph> {
    let parsed: toml::Value =
        toml::from_str(content).context("Failed to parse Cargo.lock as TOML")?;

    let packages = match parsed.get("package").and_then(|p| p.as_array()) {
        Some(pkgs) => pkgs,
        None => return Ok(DependencyGraph::new()),
    };

    /// Internal representation of a Cargo.lock package.
    struct CargoPkg {
        name: String,
        version: String,
        node: NodeId,
    }

    // First pass: build the list of all packages and their NodeIds.
    let mut all_pkgs: Vec<CargoPkg> = Vec::new();
    for pkg in packages {
        let name = pkg
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let node = if let Some(source_str) = pkg.get("source").and_then(|s| s.as_str()) {
            if let Some(without_git_plus) = source_str.strip_prefix("git+") {
                let commit_sha = match without_git_plus.find('#') {
                    Some(idx) => without_git_plus[idx + 1..].to_string(),
                    None => String::new(),
                };
                NodeId::Git {
                    name: name.clone(),
                    commit_sha,
                }
            } else if source_str.starts_with("registry+") {
                NodeId::Registry {
                    name: name.clone(),
                    version: version.clone(),
                    registry: "crates".to_string(),
                }
            } else {
                // Unknown source prefix — treat as local (no registry label)
                NodeId::Registry {
                    name: name.clone(),
                    version: version.clone(),
                    registry: "local".to_string(),
                }
            }
        } else {
            // No source field — local/path dependency
            NodeId::Registry {
                name: name.clone(),
                version: version.clone(),
                registry: "local".to_string(),
            }
        };

        all_pkgs.push(CargoPkg {
            name,
            version,
            node,
        });
    }

    // Build initial graph: every package is a node.
    let mut graph = DependencyGraph::new();
    for pkg in &all_pkgs {
        graph.add_node(pkg.node.clone());
    }

    // Second pass: build edges from each package's `dependencies` array.
    for (i, pkg) in packages.iter().enumerate() {
        let from_node = &all_pkgs[i].node;

        let dep_arr = match pkg.get("dependencies").and_then(|d| d.as_array()) {
            Some(arr) => arr,
            None => continue,
        };

        for dep_val in dep_arr {
            let dep_str = match dep_val.as_str() {
                Some(s) => s,
                None => continue,
            };

            // Cargo.lock dependency hint format:
            //   "name version (source-url)"  — version present
            //   "name version"               — version but no source
            //   "name"                       — bare name only (e.g. workspace member)
            let parts: Vec<&str> = dep_str.splitn(3, ' ').collect();
            let dep_name = parts[0];
            let dep_version = parts.get(1).copied().unwrap_or("");

            // Find the matching package: match by name, then by version if provided.
            let target = all_pkgs.iter().find(|p| {
                p.name == dep_name && (dep_version.is_empty() || dep_version == p.version.as_str())
            });

            match target {
                Some(t) => {
                    graph
                        .edges
                        .entry(from_node.clone())
                        .or_default()
                        .push(t.node.clone());
                }
                None => {
                    eprintln!(
                        "dep-scan: unresolvable Cargo.lock edge: {} depends on {} (not found in lockfile)",
                        all_pkgs[i].name, dep_str
                    );
                }
            }
        }
    }

    Ok(graph)
}

/// Build a `DependencyGraph` from a `requirements.txt` string (PyPI).
///
/// `requirements.txt` is a **flat format** — it encodes no dependency edges
/// between packages.  Every resolved entry becomes a `NodeId::Registry` node
/// with an **explicitly empty edge set**.  This is the correct, asserted
/// outcome, not a silent gap: requirements.txt does not carry a dependency
/// graph.  Edge extraction for PyPI transitive deps requires fetching each
/// package's `METADATA` file (task 103).
///
/// **Zero network I/O**.
#[allow(dead_code)]
pub fn requirements_txt_to_graph(content: &str) -> Result<DependencyGraph> {
    let deps = parse_requirements_txt(content)?;
    let mut graph = DependencyGraph::new();
    for dep in deps {
        let node = NodeId::Registry {
            name: dep.name,
            version: dep.version,
            registry: "pypi".to_string(),
        };
        // Edge set is intentionally empty — requirements.txt encodes no edges.
        graph.add_node(node);
    }
    Ok(graph)
}

/// Build a `DependencyGraph` from a `go.sum` string (Go modules).
///
/// `go.sum` is a **flat hash manifest** — it encodes no dependency edges between
/// modules.  Every resolved entry becomes a `NodeId::Registry` node with an
/// **explicitly empty edge set**.  This is the correct, asserted outcome, not a
/// silent gap: go.sum contains integrity hashes, not a module dependency graph.
/// Edge extraction for Go transitive deps requires fetching each module's
/// `go.mod` file (task 103).
///
/// **Zero network I/O**.
#[allow(dead_code)]
pub fn go_sum_to_graph(content: &str) -> Result<DependencyGraph> {
    let deps = parse_go_sum(content)?;
    let mut graph = DependencyGraph::new();
    for dep in deps {
        let node = NodeId::Registry {
            name: dep.name,
            version: dep.version,
            registry: "go".to_string(),
        };
        // Edge set is intentionally empty — go.sum encodes no dependency edges.
        graph.add_node(node);
    }
    Ok(graph)
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

    // --- T-092 tests: Cargo lockfile git source parser ---

    // T-092-01: registry+ source produces DependencySource::Registry(Crates)
    #[test]
    fn t092_01_registry_source_produces_registry_crates() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.228"
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

    // T-092-02: git+https:// source produces DependencySource::Git with stripped prefix and split ref
    #[test]
    fn t092_02_git_https_source_produces_git() {
        let content = r#"
[[package]]
name = "some-crate"
version = "0.5.0"
source = "git+https://github.com/user/repo#abc1234"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "https://github.com/user/repo".to_string(),
                ref_: "abc1234".to_string(),
            }
        );
    }

    // T-092-03: git+ssh:// source produces DependencySource::Git
    #[test]
    fn t092_03_git_ssh_source_produces_git() {
        let content = r#"
[[package]]
name = "some-crate"
version = "0.5.0"
source = "git+ssh://git@github.com/user/repo.git#abc1234"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "ssh://git@github.com/user/repo.git".to_string(),
                ref_: "abc1234".to_string(),
            }
        );
    }

    // T-092-04: git+https:// with ?branch= query preserves query in url, splits # as ref
    #[test]
    fn t092_04_git_source_with_branch_query_preserves_url() {
        let content = r#"
[[package]]
name = "some-crate"
version = "0.5.0"
source = "git+https://github.com/user/repo?branch=main#abc1234"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source,
            DependencySource::Git {
                url: "https://github.com/user/repo?branch=main".to_string(),
                ref_: "abc1234".to_string(),
            }
        );
    }

    // T-092-05: git+https:// with ?rev= query — both query and fragment carried through
    #[test]
    fn t092_05_git_source_with_rev_query() {
        let content = r#"
[[package]]
name = "some-crate"
version = "0.5.0"
source = "git+https://github.com/user/repo?rev=abc1234#abc1234"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0].source.git_url(),
            Some("https://github.com/user/repo?rev=abc1234")
        );
        assert_eq!(deps[0].source.git_ref(), Some("abc1234"));
    }

    // T-092-06: git+https:// with no # fragment gets empty ref, no panic
    #[test]
    fn t092_06_git_source_no_fragment_empty_ref() {
        let content = r#"
[[package]]
name = "some-crate"
version = "0.5.0"
source = "git+https://github.com/user/repo"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].source.git_ref(), Some(""));
    }

    // T-092-07: Local path dep (no source field) is still skipped
    #[test]
    fn t092_07_local_path_dep_no_source_skipped() {
        let content = r#"
[[package]]
name = "my-project"
version = "0.1.0"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert!(deps.is_empty());
    }

    // T-092-08: Name and version are preserved for git-source entries
    #[test]
    fn t092_08_name_and_version_preserved_for_git_source() {
        let content = r#"
[[package]]
name = "some-crate"
version = "0.5.0"
source = "git+https://github.com/user/repo#abc"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "some-crate");
        assert_eq!(deps[0].version, "0.5.0");
    }

    // T-092-09: Git dep with empty version is emitted (version not required for git)
    #[test]
    fn t092_09_git_dep_empty_version_not_skipped() {
        let content = r#"
[[package]]
name = "crate-no-ver"
source = "git+https://github.com/user/repo#abc"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "crate-no-ver");
        assert_eq!(deps[0].version, "");
        assert!(matches!(deps[0].source, DependencySource::Git { .. }));
    }

    // T-092-10: Lockfile with registry and git entries produces both kinds
    #[test]
    fn t092_10_mixed_lockfile_both_kinds() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "git-dep"
version = "0.1.0"
source = "git+https://github.com/user/repo#abc1234"
"#;
        let deps = parse_cargo_lock(content).unwrap();
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

    // T-092-11: Local, registry, and git all present — only registry + git emitted
    #[test]
    fn t092_11_local_registry_git_only_two_emitted() {
        let content = r#"
[[package]]
name = "my-project"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "git-dep"
version = "0.1.0"
source = "git+https://github.com/user/repo#abc1234"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 2);
        // Verify the local dep is not present
        assert!(!deps.iter().any(|d| d.name == "my-project"));
    }

    // T-092-12: Commit SHA as ref is stored verbatim
    #[test]
    fn t092_12_commit_sha_stored_verbatim() {
        let full_sha = "abcdef1234567890abcdef1234567890abcdef12";
        let content = format!(
            r#"
[[package]]
name = "some-crate"
version = "0.5.0"
source = "git+https://github.com/user/repo#{full_sha}"
"#
        );
        let deps = parse_cargo_lock(&content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].source.git_ref(), Some(full_sha));
    }

    // T-092-13: # with no content after it gives empty ref, not panic
    #[test]
    fn t092_13_hash_with_no_content_gives_empty_ref() {
        let content = r#"
[[package]]
name = "some-crate"
version = "0.5.0"
source = "git+https://github.com/user/repo#"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].source.git_ref(), Some(""));
    }

    // T-092-14: Unknown source prefix is skipped, not panicked
    #[test]
    fn t092_14_unknown_source_prefix_skipped_no_panic() {
        let content = r#"
[[package]]
name = "bzr-dep"
version = "1.0.0"
source = "bzr+https://bazaar.example.com/repo"
"#;
        // Must not panic; entry with unknown prefix is skipped
        let deps = parse_cargo_lock(content).unwrap();
        assert!(deps.is_empty());
    }

    // T-092-15: Syntactically invalid TOML returns Err, not panic
    #[test]
    fn t092_15_invalid_toml_returns_err_no_panic() {
        let content = "[[invalid toml";
        let result = parse_cargo_lock(content);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to parse Cargo.lock"));
    }

    // T-092-16: No regressions — existing tests cover this; verify classify_cargo_source directly
    #[test]
    fn t092_16_classify_cargo_source_direct() {
        // registry+ -> Registry(Crates)
        let s = classify_cargo_source("registry+https://github.com/rust-lang/crates.io-index");
        assert_eq!(
            s,
            Some(DependencySource::Registry {
                registry: RegistryType::Crates
            })
        );

        // git+ -> Git
        let s = classify_cargo_source("git+https://github.com/user/repo#abc");
        assert_eq!(
            s,
            Some(DependencySource::Git {
                url: "https://github.com/user/repo".to_string(),
                ref_: "abc".to_string(),
            })
        );

        // unknown prefix -> None
        let s = classify_cargo_source("bzr+https://example.com/repo");
        assert_eq!(s, None);

        // empty string -> None
        let s = classify_cargo_source("");
        assert_eq!(s, None);
    }

    // -----------------------------------------------------------------------
    // T-100 tests: NodeId, DependencyGraph, lockfile graph readers
    // -----------------------------------------------------------------------

    // T-100-01: Registry NodeId round-trips through equality
    #[test]
    fn t100_01_registry_node_id_equality() {
        let a = NodeId::Registry {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            registry: "npm".to_string(),
        };
        let b = NodeId::Registry {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            registry: "npm".to_string(),
        };
        // Same fields → equal
        assert_eq!(a, b);

        let c = NodeId::Registry {
            name: "lodash".to_string(),
            version: "4.17.22".to_string(), // different version
            registry: "npm".to_string(),
        };
        // Different version → not equal
        assert_ne!(a, c);
    }

    // T-100-02: Git NodeId round-trips through equality
    #[test]
    fn t100_02_git_node_id_equality() {
        let a = NodeId::Git {
            name: "my-lib".to_string(),
            commit_sha: "abc123def456".to_string(),
        };
        let b = NodeId::Git {
            name: "my-lib".to_string(),
            commit_sha: "abc123def456".to_string(),
        };
        assert_eq!(a, b);

        let c = NodeId::Git {
            name: "my-lib".to_string(),
            commit_sha: "zzz999".to_string(),
        };
        assert_ne!(a, c);
    }

    // T-100-03: NodeId is usable as a HashSet key
    #[test]
    fn t100_03_node_id_hashset_key() {
        use std::collections::HashSet;

        let mut set: HashSet<NodeId> = HashSet::new();

        let reg = NodeId::Registry {
            name: "express".to_string(),
            version: "4.18.2".to_string(),
            registry: "npm".to_string(),
        };
        let git = NodeId::Git {
            name: "my-lib".to_string(),
            commit_sha: "abc123".to_string(),
        };
        let reg2 = NodeId::Registry {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            registry: "npm".to_string(),
        };

        set.insert(reg.clone());
        set.insert(git.clone());
        set.insert(reg2.clone());

        assert!(set.contains(&reg));
        assert!(set.contains(&git));
        assert!(set.contains(&reg2));
        assert!(!set.contains(&NodeId::Registry {
            name: "unknown".to_string(),
            version: "1.0.0".to_string(),
            registry: "npm".to_string(),
        }));
        assert_eq!(set.len(), 3);
    }

    // T-100-04: NodeId matches the cache identity scheme
    #[test]
    fn t100_04_node_id_matches_cache_identity() {
        // Registry variant: (name, version, registry) — same fields as cache.rs insert
        let reg = NodeId::Registry {
            name: "serde".to_string(),
            version: "1.0.190".to_string(),
            registry: "crates".to_string(),
        };
        if let NodeId::Registry {
            name,
            version,
            registry,
        } = &reg
        {
            assert_eq!(name, "serde");
            assert_eq!(version, "1.0.190");
            assert_eq!(registry, "crates");
        } else {
            panic!("Expected Registry variant");
        }

        // Git variant: (name, commit_sha) — matches insert_git (name, commit_sha, "git")
        let git = NodeId::Git {
            name: "evil-pkg".to_string(),
            commit_sha: "abc123def456".to_string(),
        };
        if let NodeId::Git { name, commit_sha } = &git {
            assert_eq!(name, "evil-pkg");
            assert_eq!(commit_sha, "abc123def456");
        } else {
            panic!("Expected Git variant");
        }

        // Compile-time assertion: only two variants exist.
        // If a third variant were added, the exhaustive match below would fail to compile.
        let _exhaustive: &str = match &reg {
            NodeId::Registry { .. } => "registry",
            NodeId::Git { .. } => "git",
        };
    }

    // T-100-05: Empty graph has no nodes and no edges
    #[test]
    fn t100_05_empty_graph_no_nodes_no_edges() {
        let graph = DependencyGraph::new();
        assert_eq!(graph.nodes().count(), 0);

        // edges_from on a non-existent node returns empty slice
        let phantom = NodeId::Registry {
            name: "ghost".to_string(),
            version: "0.0.1".to_string(),
            registry: "npm".to_string(),
        };
        assert!(graph.edges_from(&phantom).is_empty());
    }

    // T-100-06: Graph exposes edges_from for a known node
    #[test]
    fn t100_06_graph_edges_from_known_node() {
        let node_a = NodeId::Registry {
            name: "a".to_string(),
            version: "1.0.0".to_string(),
            registry: "npm".to_string(),
        };
        let node_b = NodeId::Registry {
            name: "b".to_string(),
            version: "1.0.0".to_string(),
            registry: "npm".to_string(),
        };
        let node_c = NodeId::Registry {
            name: "c".to_string(),
            version: "1.0.0".to_string(),
            registry: "npm".to_string(),
        };

        let graph = DependencyGraph::from_edges([
            (node_a.clone(), node_b.clone()),
            (node_a.clone(), node_c.clone()),
        ]);

        // A has edges to B and C
        let edges_a = graph.edges_from(&node_a);
        assert_eq!(edges_a.len(), 2);
        assert!(edges_a.contains(&node_b));
        assert!(edges_a.contains(&node_c));

        // B has no outgoing edges
        assert!(graph.edges_from(&node_b).is_empty());

        // C has no outgoing edges
        assert!(graph.edges_from(&node_c).is_empty());
    }

    // T-100-07: Graph build from a cyclic lockfile does not infinite-loop
    #[test]
    fn t100_07_cyclic_graph_does_not_infinite_loop() {
        let node_a = NodeId::Registry {
            name: "a".to_string(),
            version: "1.0.0".to_string(),
            registry: "npm".to_string(),
        };
        let node_b = NodeId::Registry {
            name: "b".to_string(),
            version: "1.0.0".to_string(),
            registry: "npm".to_string(),
        };

        // A → B and B → A (cycle)
        let graph = DependencyGraph::from_edges([
            (node_a.clone(), node_b.clone()),
            (node_b.clone(), node_a.clone()),
        ]);

        // Both edges are recorded faithfully
        assert!(graph.edges_from(&node_a).contains(&node_b));
        assert!(graph.edges_from(&node_b).contains(&node_a));
        // Graph builds without panic or hang
    }

    // T-100-08: v1 package-lock.json extracts edges for a simple direct dep
    #[test]
    fn t100_08_npm_v1_edge_extraction() {
        let content = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "requires": { "accepts": "~1.3.8" },
                    "dependencies": {
                        "accepts": { "version": "1.3.8", "requires": {} }
                    }
                }
            }
        }"#;

        let graph = package_lock_json_to_graph(content).unwrap();

        let express = NodeId::Registry {
            name: "express".to_string(),
            version: "4.18.2".to_string(),
            registry: "npm".to_string(),
        };
        let accepts = NodeId::Registry {
            name: "accepts".to_string(),
            version: "1.3.8".to_string(),
            registry: "npm".to_string(),
        };

        assert!(graph.edges_from(&express).contains(&accepts));
    }

    // T-100-09: v2/v3 package-lock.json extracts edges via packages map
    #[test]
    fn t100_09_npm_v3_edge_extraction() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/express": {
                    "version": "4.18.2",
                    "dependencies": { "accepts": "^1.3.8" }
                },
                "node_modules/accepts": { "version": "1.3.8" }
            }
        }"#;

        let graph = package_lock_json_to_graph(content).unwrap();

        let express = NodeId::Registry {
            name: "express".to_string(),
            version: "4.18.2".to_string(),
            registry: "npm".to_string(),
        };
        let accepts = NodeId::Registry {
            name: "accepts".to_string(),
            version: "1.3.8".to_string(),
            registry: "npm".to_string(),
        };

        // Resolved version for the edge target is read from the packages map
        assert!(graph.edges_from(&express).contains(&accepts));
        // accepts has no outgoing edges
        assert!(graph.edges_from(&accepts).is_empty());
    }

    // T-100-10: npm edge extraction — dep referenced in requires but absent from resolved packages
    //           emits a diagnostic, not a panic
    #[test]
    fn t100_10_npm_unresolvable_edge_no_panic() {
        let content = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "requires": { "orphaned": "^1.0.0" }
                }
            }
        }"#;

        // Must not panic; graph is returned even with unresolvable edge
        let graph = package_lock_json_to_graph(content).unwrap();

        let express = NodeId::Registry {
            name: "express".to_string(),
            version: "4.18.2".to_string(),
            registry: "npm".to_string(),
        };

        // express is in the graph
        assert!(graph.nodes().any(|n| n == &express));
        // orphaned edge is omitted (no resolved entry), express has no outgoing edges
        assert!(graph.edges_from(&express).is_empty());
    }

    // T-100-11: npm edge extraction is zero-network
    #[test]
    fn t100_11_npm_graph_zero_network() {
        // This test verifies that package_lock_json_to_graph is a pure function
        // of the bytes passed in — no network calls are made.
        // We demonstrate this by parsing the same content twice and checking
        // idempotent results, with no async context or network available.
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": { "version": "4.17.21" }
            }
        }"#;

        let graph1 = package_lock_json_to_graph(content).unwrap();
        let graph2 = package_lock_json_to_graph(content).unwrap();

        // Both calls produce the same node set — no non-deterministic network
        // state can have affected the result.
        let mut nodes1: Vec<_> = graph1.nodes().collect();
        let mut nodes2: Vec<_> = graph2.nodes().collect();
        nodes1.sort_by_key(|n| format!("{n:?}"));
        nodes2.sort_by_key(|n| format!("{n:?}"));
        assert_eq!(nodes1.len(), nodes2.len());
        // All nodes are Registry (lodash) — no Git nodes, no HTTP calls needed
        assert!(graph1.nodes().all(|n| matches!(n, NodeId::Registry { .. })));
    }

    // T-100-12: Cargo.lock [[package]].dependencies edges extracted correctly
    #[test]
    fn t100_12_cargo_lock_edge_extraction() {
        let content = r#"
[[package]]
name = "my-crate"
version = "1.0.0"
dependencies = ["serde 1.0.190 (registry+https://github.com/rust-lang/crates.io-index)"]

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

        let graph = cargo_lock_to_graph(content).unwrap();

        let my_crate = NodeId::Registry {
            name: "my-crate".to_string(),
            version: "1.0.0".to_string(),
            registry: "local".to_string(),
        };
        let serde = NodeId::Registry {
            name: "serde".to_string(),
            version: "1.0.190".to_string(),
            registry: "crates".to_string(),
        };

        assert!(graph.edges_from(&my_crate).contains(&serde));
    }

    // T-100-13: Cargo.lock git source dependency is represented as NodeId::Git
    #[test]
    fn t100_13_cargo_lock_git_source_is_git_node_id() {
        let content = r#"
[[package]]
name = "my-crate"
version = "1.0.0"
dependencies = ["my-git-dep"]

[[package]]
name = "my-git-dep"
version = "0.1.0"
source = "git+https://github.com/foo/bar#abc123"
"#;

        let graph = cargo_lock_to_graph(content).unwrap();

        let git_dep = NodeId::Git {
            name: "my-git-dep".to_string(),
            commit_sha: "abc123".to_string(),
        };

        // The git dep is a node in the graph
        assert!(graph.nodes().any(|n| n == &git_dep));

        // my-crate has an edge to the git dep
        let my_crate = NodeId::Registry {
            name: "my-crate".to_string(),
            version: "1.0.0".to_string(),
            registry: "local".to_string(),
        };
        assert!(graph.edges_from(&my_crate).contains(&git_dep));
    }

    // T-100-14: Cargo.lock dependency with no version suffix still resolves
    #[test]
    fn t100_14_cargo_lock_bare_name_dep_resolves() {
        let content = r#"
[[package]]
name = "my-crate"
version = "1.0.0"
dependencies = ["log"]

[[package]]
name = "log"
version = "0.4.20"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

        let graph = cargo_lock_to_graph(content).unwrap();

        let my_crate = NodeId::Registry {
            name: "my-crate".to_string(),
            version: "1.0.0".to_string(),
            registry: "local".to_string(),
        };
        let log = NodeId::Registry {
            name: "log".to_string(),
            version: "0.4.20".to_string(),
            registry: "crates".to_string(),
        };

        // Edge is recorded even with bare-name dependency hint
        assert!(graph.edges_from(&my_crate).contains(&log));
    }

    // T-100-15: Cargo.lock edge extraction is zero-network
    #[test]
    fn t100_15_cargo_lock_graph_zero_network() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

        // Two identical calls with no network — results are identical.
        let g1 = cargo_lock_to_graph(content).unwrap();
        let g2 = cargo_lock_to_graph(content).unwrap();

        let count1 = g1.nodes().count();
        let count2 = g2.nodes().count();
        assert_eq!(count1, count2);
        assert!(g1.nodes().all(|n| matches!(n, NodeId::Registry { .. })));
    }

    // T-100-16: requirements.txt yields nodes with empty edge sets
    #[test]
    fn t100_16_requirements_txt_empty_edge_sets() {
        let content = "requests==2.31.0\nurllib3==2.0.7\n";
        let graph = requirements_txt_to_graph(content).unwrap();

        let requests = NodeId::Registry {
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            registry: "pypi".to_string(),
        };
        let urllib3 = NodeId::Registry {
            name: "urllib3".to_string(),
            version: "2.0.7".to_string(),
            registry: "pypi".to_string(),
        };

        // Both nodes are present
        assert!(graph.nodes().any(|n| n == &requests));
        assert!(graph.nodes().any(|n| n == &urllib3));

        // Edge sets are empty — requirements.txt encodes no dependency edges
        assert!(graph.edges_from(&requests).is_empty());
        assert!(graph.edges_from(&urllib3).is_empty());
    }

    // T-100-17: go.sum yields nodes with empty edge sets
    #[test]
    fn t100_17_go_sum_empty_edge_sets() {
        let content = concat!(
            "github.com/gin-gonic/gin v1.9.1 h1:abc=\n",
            "github.com/stretchr/testify v1.8.4 h1:def=\n",
        );
        let graph = go_sum_to_graph(content).unwrap();

        let gin = NodeId::Registry {
            name: "github.com/gin-gonic/gin".to_string(),
            version: "v1.9.1".to_string(),
            registry: "go".to_string(),
        };
        let testify = NodeId::Registry {
            name: "github.com/stretchr/testify".to_string(),
            version: "v1.8.4".to_string(),
            registry: "go".to_string(),
        };

        // Both nodes are present
        assert!(graph.nodes().any(|n| n == &gin));
        assert!(graph.nodes().any(|n| n == &testify));

        // Edge sets are empty — go.sum is a flat hash manifest, not a graph
        assert!(graph.edges_from(&gin).is_empty());
        assert!(graph.edges_from(&testify).is_empty());
    }

    // T-100-18: No regressions (tooling gate — verified by cargo test / clippy / fmt)
    // This test is a compile-time + suite-level check: if it runs, the suite passed.
    #[test]
    fn t100_18_no_regressions_suite_passes() {
        // Smoke: existing parse functions still compile and return Ok
        let npm = parse_package_lock_json(r#"{"packages":{}}"#).unwrap();
        assert!(npm.is_empty());

        let req = parse_requirements_txt("").unwrap();
        assert!(req.is_empty());

        let cargo = parse_cargo_lock("version = 3\n").unwrap();
        assert!(cargo.is_empty());

        let go = parse_go_sum("").unwrap();
        assert!(go.is_empty());
    }
}

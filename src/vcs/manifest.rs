//! Manifest edge reader for fetched git sub-trees — ADR 009 Decision 1, manifest-fallback.
//!
//! This module implements the "manifest-fallback" half of the lockfile-first strategy:
//! when a git-sourced dependency's transitive children are not covered by the consuming
//! project's lockfile, their direct edges are discovered by parsing the sub-tree's own
//! manifest from an already-materialised [`FetchedTree`].
//!
//! ## Design guarantees
//!
//! - **Zero network I/O (REQ-101-01):** All reads are from bytes already held in the
//!   `FetchedTree`.  No network call is possible — the function accepts only `&FetchedTree`,
//!   which is a fully-materialised in-memory type produced by task 096.
//! - **Absent/malformed manifest → `Err(ManifestError)` (REQ-101-04):** A missing or
//!   unparseable manifest is never silently reported as an empty edge set.  The caller
//!   (task 103) treats this as at least `Warn` per ADR 009's fail-closed contract.
//! - **Ecosystem hint selects exactly one manifest (REQ-101-06):** If both `package.json`
//!   and `Cargo.toml` are present in the tree, the `Ecosystem` argument selects exactly
//!   one; the other is ignored, preventing duplicate edges.

use std::path::Path;

use serde_json::Value;

use crate::lockfile::NodeId;

/// The package ecosystem to use when selecting a manifest from the fetched tree.
///
/// When both `package.json` and `Cargo.toml` are present in a tree, this hint
/// selects exactly one — preventing duplicate or conflicting edges (REQ-101-06).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    /// npm — reads `package.json` `dependencies` (excludes `devDependencies`).
    Npm,
    /// Cargo — reads `Cargo.toml` `[dependencies]`.
    Cargo,
}

/// A version range string or other unresolved dependency specifier read verbatim
/// from a manifest.
///
/// ADR 009 Decision 1: when a manifest lists a version range (e.g. `"^1.2.0"`)
/// rather than an exact pinned version, dep-scan records the range verbatim and
/// defers resolution.  The walker (task 103) rolls this up as at least `Warn`
/// (fail-closed, never `Pass`).  Semver resolution is explicitly out of scope
/// for this task (T-099-09).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedRange {
    /// Dependency name.
    pub name: String,
    /// The version specifier string exactly as written in the manifest (e.g.
    /// `"^1.2.0"`, `"1.0"`, `"https://github.com/..."`, `""`).
    pub range: String,
}

/// A single dependency edge discovered from a manifest.
///
/// - `Resolved` — the edge could be normalised to a cache `NodeId` (a registry
///   dep with an exact version, or a git dep with a pinned commit SHA).
/// - `Unresolved` — the edge carries a version range or an unpinned git dep;
///   the walker treats this as at least `Warn` (fail-closed).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestEdge {
    /// A dependency edge that resolves to a known cache identity.
    Resolved(NodeId),
    /// A dependency edge whose version cannot be resolved without a semver
    /// resolver or a registry query — stored verbatim.
    Unresolved(UnresolvedRange),
}

/// Error returned when a manifest cannot be found or parsed.
///
/// Per REQ-101-04: a missing or unparseable manifest always produces an
/// `Err(ManifestError)`, never a silent empty `Ok(vec![])`.  The caller (task
/// 103) maps this to at least `Warn` under the fail-closed contract.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// No manifest file matching the requested ecosystem was found in the tree.
    NotFound {
        /// The filename that was expected (e.g. `"package.json"`).
        expected: String,
    },
    /// A manifest file was found but could not be parsed.
    ParseError {
        /// The filename that failed to parse.
        file: String,
        /// A human-readable description of the parse failure.
        detail: String,
    },
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::NotFound { expected } => {
                write!(f, "manifest not found in fetched tree: expected {expected}")
            }
            ManifestError::ParseError { file, detail } => {
                write!(f, "failed to parse manifest {file}: {detail}")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// Read the direct dependency edges from a fetched git sub-tree's manifest.
///
/// Selects the appropriate manifest file based on `ecosystem`, parses it, and
/// returns the edges as `ManifestEdge` values.
///
/// # Errors
///
/// Returns `Err(ManifestError::NotFound)` if the expected manifest file is not
/// present in the tree.
///
/// Returns `Err(ManifestError::ParseError)` if the manifest file is present but
/// cannot be parsed.
///
/// A workspace root with no `[dependencies]` section (Cargo) is **not** an
/// error — it returns `Ok(vec![])`.
///
/// `devDependencies` in `package.json` are always excluded (REQ-101-05).
///
/// **Zero network I/O (REQ-101-01):** all reads are from bytes already in `tree`.
#[allow(dead_code)]
pub fn manifest_edges_from_tree(
    tree: &crate::vcs::fetch::FetchedTree,
    ecosystem: Ecosystem,
) -> Result<Vec<ManifestEdge>, ManifestError> {
    match ecosystem {
        Ecosystem::Npm => npm_edges(tree),
        Ecosystem::Cargo => cargo_edges(tree),
    }
}

/// Find a file in the tree by its basename (case-sensitive, root level only
/// first, then any depth).  Returns the content bytes on the first match.
fn find_manifest<'a>(tree: &'a crate::vcs::fetch::FetchedTree, filename: &str) -> Option<&'a [u8]> {
    // Prefer root-level manifest (no parent directory).
    for file in tree.files() {
        let p = file.path();
        if p.file_name().and_then(|n| n.to_str()) == Some(filename)
            && p.parent().map(|par| par == Path::new("")).unwrap_or(true)
        {
            return Some(file.content());
        }
    }
    // Fall back to any depth (e.g. if the manifest is in a subdirectory).
    for file in tree.files() {
        if file.path().file_name().and_then(|n| n.to_str()) == Some(filename) {
            return Some(file.content());
        }
    }
    None
}

/// Parse npm edges from `package.json`.
fn npm_edges(tree: &crate::vcs::fetch::FetchedTree) -> Result<Vec<ManifestEdge>, ManifestError> {
    let bytes = find_manifest(tree, "package.json").ok_or_else(|| ManifestError::NotFound {
        expected: "package.json".to_string(),
    })?;

    let content = std::str::from_utf8(bytes).map_err(|e| ManifestError::ParseError {
        file: "package.json".to_string(),
        detail: format!("not valid UTF-8: {e}"),
    })?;

    let json: Value = serde_json::from_str(content).map_err(|e| ManifestError::ParseError {
        file: "package.json".to_string(),
        detail: e.to_string(),
    })?;

    let mut edges = Vec::new();

    // Only read `dependencies` — devDependencies are excluded (REQ-101-05).
    if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        for (name, version_val) in deps {
            let range = version_val.as_str().unwrap_or("").to_string();
            // npm version ranges are always UnresolvedRange — we never have a
            // resolved version from a manifest (only from a lockfile).
            edges.push(ManifestEdge::Unresolved(UnresolvedRange {
                name: name.clone(),
                range,
            }));
        }
    }

    Ok(edges)
}

/// Parse Cargo edges from `Cargo.toml`.
fn cargo_edges(tree: &crate::vcs::fetch::FetchedTree) -> Result<Vec<ManifestEdge>, ManifestError> {
    let bytes = find_manifest(tree, "Cargo.toml").ok_or_else(|| ManifestError::NotFound {
        expected: "Cargo.toml".to_string(),
    })?;

    let content = std::str::from_utf8(bytes).map_err(|e| ManifestError::ParseError {
        file: "Cargo.toml".to_string(),
        detail: format!("not valid UTF-8: {e}"),
    })?;

    let parsed: toml::Value = toml::from_str(content).map_err(|e| ManifestError::ParseError {
        file: "Cargo.toml".to_string(),
        detail: e.to_string(),
    })?;

    let mut edges = Vec::new();

    // `[dependencies]` section — absent is valid (workspace root with no deps).
    let Some(deps_table) = parsed.get("dependencies").and_then(|d| d.as_table()) else {
        return Ok(edges);
    };

    for (dep_name, dep_val) in deps_table {
        let edge = classify_cargo_dep(dep_name, dep_val);
        edges.push(edge);
    }

    Ok(edges)
}

/// Classify a single Cargo dependency value into a `ManifestEdge`.
///
/// Per ADR 011: `Resolved` is emitted **only** when a concrete pinned identity
/// is available without semver parsing — that is exactly one case: a Cargo git
/// dependency with an explicit `rev = "<sha>"`, which yields `NodeId::Git`.
/// Every other manifest edge is `Unresolved(UnresolvedRange)`:
///
/// - Plain string `"1.0"` → `UnresolvedRange` (range, not a pin).
/// - Table with `git` + `rev` → `NodeId::Git` (pinned commit SHA).
/// - Table with `git` but no `rev` → `UnresolvedRange` (range = git URL).
/// - Table with `version` → `UnresolvedRange` (range = the version string).
/// - Table with `path` and no `version` → `UnresolvedRange` (local path dep).
fn classify_cargo_dep(name: &str, val: &toml::Value) -> ManifestEdge {
    match val {
        // Inline string: `dep = "1.0"` or `dep = "*"` — version range.
        toml::Value::String(version_str) => ManifestEdge::Unresolved(UnresolvedRange {
            name: name.to_string(),
            range: version_str.clone(),
        }),

        // Inline table: `dep = { version = "…", features = […] }` etc.
        toml::Value::Table(table) => {
            // Git dep with pinned rev → NodeId::Git (ADR 011: the ONLY Resolved case).
            if let Some(rev) = table.get("rev").and_then(|r| r.as_str())
                && !rev.is_empty()
            {
                return ManifestEdge::Resolved(NodeId::Git {
                    name: name.to_string(),
                    commit_sha: rev.to_string(),
                });
            }

            // Git dep without pinned rev → UnresolvedRange (range = git URL).
            if table.contains_key("git") {
                let git_url = table
                    .get("git")
                    .and_then(|g| g.as_str())
                    .unwrap_or("")
                    .to_string();
                return ManifestEdge::Unresolved(UnresolvedRange {
                    name: name.to_string(),
                    range: git_url,
                });
            }

            // Registry dep with explicit version → UnresolvedRange (ADR 011: a
            // version string like "1" is a range, not an exact pin; classifying
            // it as NodeId::Registry would produce an identity whose `version`
            // field holds a range string, not an exact artifact version).
            if let Some(version_str) = table.get("version").and_then(|v| v.as_str()) {
                return ManifestEdge::Unresolved(UnresolvedRange {
                    name: name.to_string(),
                    range: version_str.to_string(),
                });
            }

            // Path dep or workspace dep with no version → UnresolvedRange.
            let hint = table
                .get("path")
                .and_then(|p| p.as_str())
                .map(str::to_string)
                .unwrap_or_default();
            ManifestEdge::Unresolved(UnresolvedRange {
                name: name.to_string(),
                range: hint,
            })
        }

        // Any other TOML type (array, bool, int…) — treat as unresolved.
        _ => ManifestEdge::Unresolved(UnresolvedRange {
            name: name.to_string(),
            range: String::new(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests (TDD: T-101-01 through T-101-12)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::lockfile::NodeId;
    use crate::vcs::fetch::FetchedTree;

    fn tree_from(files: &[(&str, &[u8])]) -> FetchedTree {
        FetchedTree::from_files_for_test(
            files
                .iter()
                .map(|(p, c)| (PathBuf::from(p), c.to_vec()))
                .collect(),
        )
    }

    // T-101-01: package.json `dependencies` → UnresolvedRange edges
    #[test]
    fn t101_01_npm_dependencies_become_unresolved_range() {
        let json = br#"{"dependencies": {"express": "^4.18.0", "lodash": "1.2.3"}}"#;
        let tree = tree_from(&[("package.json", json)]);
        let edges = manifest_edges_from_tree(&tree, Ecosystem::Npm)
            .expect("T-101-01: must return Ok for valid package.json");

        // Order may vary — sort by name for determinism.
        let mut names_ranges: Vec<(String, String)> = edges
            .iter()
            .map(|e| match e {
                ManifestEdge::Unresolved(u) => (u.name.clone(), u.range.clone()),
                ManifestEdge::Resolved(_) => panic!("T-101-01: npm deps must be Unresolved"),
            })
            .collect();
        names_ranges.sort();

        assert_eq!(
            names_ranges,
            vec![
                ("express".to_string(), "^4.18.0".to_string()),
                ("lodash".to_string(), "1.2.3".to_string()),
            ],
            "T-101-01: both npm deps must appear as UnresolvedRange with verbatim ranges"
        );
    }

    // T-101-02: devDependencies excluded — only devDeps → empty Ok
    #[test]
    fn t101_02_npm_dev_dependencies_excluded_only_dev() {
        let json = br#"{"devDependencies": {"jest": "^29.0.0"}}"#;
        let tree = tree_from(&[("package.json", json)]);
        let edges =
            manifest_edges_from_tree(&tree, Ecosystem::Npm).expect("T-101-02: must return Ok");
        assert!(
            edges.is_empty(),
            "T-101-02: devDependencies must be excluded; expected empty, got {:?}",
            edges
        );
    }

    // T-101-03: both dependencies and devDependencies — only dependencies
    #[test]
    fn t101_03_npm_only_dependencies_not_dev() {
        let json = br#"{
            "dependencies": {"react": "^18.0.0"},
            "devDependencies": {"typescript": "^5.0.0"}
        }"#;
        let tree = tree_from(&[("package.json", json)]);
        let edges =
            manifest_edges_from_tree(&tree, Ecosystem::Npm).expect("T-101-03: must return Ok");

        assert_eq!(edges.len(), 1, "T-101-03: exactly one edge (react)");
        let ManifestEdge::Unresolved(u) = &edges[0] else {
            panic!("T-101-03: expected Unresolved");
        };
        assert_eq!(u.name, "react", "T-101-03: name must be react");
        assert_eq!(u.range, "^18.0.0", "T-101-03: range verbatim");

        let has_typescript = edges
            .iter()
            .any(|e| matches!(e, ManifestEdge::Unresolved(u) if u.name == "typescript"));
        assert!(
            !has_typescript,
            "T-101-03: typescript (devDep) must be absent"
        );
    }

    // T-101-04: Cargo.toml plain string + table version deps → both UnresolvedRange (ADR 011)
    #[test]
    fn t101_04_cargo_plain_version_becomes_unresolved() {
        let toml_src = b"[package]\nname = \"mylib\"\nversion = \"0.1.0\"\n\
            [dependencies]\nserde = \"1.0\"\ntokio = { version = \"1\", features = [\"full\"] }\n";
        let tree = tree_from(&[("Cargo.toml", toml_src)]);
        let edges = manifest_edges_from_tree(&tree, Ecosystem::Cargo)
            .expect("T-101-04: must return Ok for valid Cargo.toml");

        // Per ADR 011: both string-form ("1.0") and table-form ({ version = "1" }) are
        // version ranges — neither is a pinned exact identity. Both must be Unresolved.

        // serde = "1.0" → UnresolvedRange { range: "1.0" }
        let serde_edge = edges
            .iter()
            .find(|e| matches!(e, ManifestEdge::Unresolved(u) if u.name == "serde"));
        assert!(
            serde_edge.is_some(),
            "T-101-04: serde must be present as Unresolved"
        );
        if let Some(ManifestEdge::Unresolved(u)) = serde_edge {
            assert_eq!(
                u.range, "1.0",
                "T-101-04: serde range must be verbatim \"1.0\""
            );
        }

        // tokio = { version = "1", features = ["full"] } → UnresolvedRange { range: "1" }
        let tokio_edge = edges
            .iter()
            .find(|e| matches!(e, ManifestEdge::Unresolved(u) if u.name == "tokio"));
        assert!(
            tokio_edge.is_some(),
            "T-101-04: tokio must be present as Unresolved (not Resolved), got {:?}",
            edges
        );
        if let Some(ManifestEdge::Unresolved(u)) = tokio_edge {
            assert_eq!(u.range, "1", "T-101-04: tokio range must be verbatim \"1\"");
        }

        // Confirm no Resolved edges exist (ADR 011: only git+rev may be Resolved).
        let has_resolved = edges.iter().any(|e| matches!(e, ManifestEdge::Resolved(_)));
        assert!(
            !has_resolved,
            "T-101-04: no Resolved edges expected for registry deps (ADR 011), got {:?}",
            edges
        );
    }

    // T-101-05: Cargo.toml git dep with rev → NodeId::Git
    #[test]
    fn t101_05_cargo_git_dep_with_rev_becomes_git_node() {
        let toml_src = b"[package]\nname = \"x\"\nversion = \"0.1.0\"\n\
            [dependencies]\nmylib = { git = \"https://github.com/example/mylib\", rev = \"abc123def456\" }\n";
        let tree = tree_from(&[("Cargo.toml", toml_src)]);
        let edges =
            manifest_edges_from_tree(&tree, Ecosystem::Cargo).expect("T-101-05: must return Ok");

        assert_eq!(edges.len(), 1, "T-101-05: exactly one edge");
        match &edges[0] {
            ManifestEdge::Resolved(NodeId::Git { name, commit_sha }) => {
                assert_eq!(name, "mylib", "T-101-05: name");
                assert_eq!(commit_sha, "abc123def456", "T-101-05: commit_sha from rev");
            }
            other => panic!("T-101-05: expected Resolved(NodeId::Git), got {:?}", other),
        }
    }

    // T-101-06: Cargo.toml workspace root with no [dependencies] → empty Ok
    #[test]
    fn t101_06_cargo_workspace_no_deps_is_empty_ok() {
        let toml_src = b"[workspace]\nmembers = [\"crates/*\"]\n\
            [package]\nname = \"workspace-root\"\nversion = \"0.1.0\"\n";
        let tree = tree_from(&[("Cargo.toml", toml_src)]);
        let edges = manifest_edges_from_tree(&tree, Ecosystem::Cargo)
            .expect("T-101-06: workspace root with no [dependencies] must be Ok");
        assert!(
            edges.is_empty(),
            "T-101-06: expected empty edges for workspace root, got {:?}",
            edges
        );
    }

    // T-101-07: absent manifest → ManifestError::NotFound
    #[test]
    fn t101_07_absent_npm_manifest_is_err_not_found() {
        let tree = tree_from(&[("README.md", b"# Hello")]);
        let result = manifest_edges_from_tree(&tree, Ecosystem::Npm);
        match result {
            Err(ManifestError::NotFound { expected }) => {
                assert!(
                    expected.contains("package.json"),
                    "T-101-07: error must mention expected filename, got: {expected}"
                );
            }
            other => panic!("T-101-07: expected Err(NotFound), got {:?}", other),
        }
    }

    #[test]
    fn t101_07b_absent_cargo_manifest_is_err_not_found() {
        let tree = tree_from(&[("README.md", b"# Hello")]);
        let result = manifest_edges_from_tree(&tree, Ecosystem::Cargo);
        match result {
            Err(ManifestError::NotFound { expected }) => {
                assert!(
                    expected.contains("Cargo.toml"),
                    "T-101-07: Cargo error must mention Cargo.toml, got: {expected}"
                );
            }
            other => panic!(
                "T-101-07: expected Err(NotFound) for Cargo, got {:?}",
                other
            ),
        }
    }

    // T-101-08: malformed JSON → ManifestError::ParseError
    #[test]
    fn t101_08_malformed_json_is_err_parse_error() {
        let tree = tree_from(&[("package.json", b"{ broken json")]);
        let result = manifest_edges_from_tree(&tree, Ecosystem::Npm);
        match result {
            Err(ManifestError::ParseError { file, .. }) => {
                assert_eq!(
                    file, "package.json",
                    "T-101-08: ParseError must name package.json"
                );
            }
            Ok(_) => panic!("T-101-08: malformed JSON must not return Ok"),
            other => panic!("T-101-08: unexpected error variant: {:?}", other),
        }
    }

    // T-101-09: malformed TOML → ManifestError::ParseError
    #[test]
    fn t101_09_malformed_toml_is_err_parse_error() {
        let tree = tree_from(&[("Cargo.toml", b"[broken toml")]);
        let result = manifest_edges_from_tree(&tree, Ecosystem::Cargo);
        match result {
            Err(ManifestError::ParseError { file, .. }) => {
                assert_eq!(
                    file, "Cargo.toml",
                    "T-101-09: ParseError must name Cargo.toml"
                );
            }
            Ok(_) => panic!("T-101-09: malformed TOML must not return Ok"),
            other => panic!("T-101-09: unexpected error variant: {:?}", other),
        }
    }

    // T-101-10: ecosystem hint selects exactly one manifest
    #[test]
    fn t101_10_ecosystem_hint_selects_one_manifest() {
        let npm_json = br#"{"dependencies": {"express": "^4.18.0"}}"#;
        let cargo_toml = b"[package]\nname=\"x\"\nversion=\"0.1.0\"\n\
            [dependencies]\nserde = { version = \"1.0\" }\n";
        let tree = tree_from(&[("package.json", npm_json), ("Cargo.toml", cargo_toml)]);

        // Npm hint → only npm edges
        let npm_edges = manifest_edges_from_tree(&tree, Ecosystem::Npm)
            .expect("T-101-10: Npm hint must succeed");
        assert_eq!(
            npm_edges.len(),
            1,
            "T-101-10: Npm hint must return exactly one edge"
        );
        assert!(
            matches!(&npm_edges[0], ManifestEdge::Unresolved(u) if u.name == "express"),
            "T-101-10: Npm edge must be express"
        );

        // Cargo hint → only cargo edges
        let cargo_edges = manifest_edges_from_tree(&tree, Ecosystem::Cargo)
            .expect("T-101-10: Cargo hint must succeed");
        assert_eq!(
            cargo_edges.len(),
            1,
            "T-101-10: Cargo hint must return exactly one edge"
        );
        // Per ADR 011: table-with-version is Unresolved (range = the version string).
        assert!(
            matches!(&cargo_edges[0], ManifestEdge::Unresolved(u) if u.name == "serde"),
            "T-101-10: Cargo edge must be serde as Unresolved (ADR 011), got {:?}",
            cargo_edges
        );
    }

    // T-101-11: zero network I/O structural guarantee (no-network type)
    #[test]
    fn t101_11_zero_network_io_structural() {
        // FetchedTree::from_files_for_test is a purely in-memory constructor.
        // manifest_edges_from_tree accepts only &FetchedTree; it has no path
        // to make a network call. This test confirms the function works with a
        // test-only tree and returns Ok without panicking.
        let json = br#"{"dependencies": {"axios": "1.0.0"}}"#;
        let tree = tree_from(&[("package.json", json)]);
        let result = manifest_edges_from_tree(&tree, Ecosystem::Npm);
        assert!(
            result.is_ok(),
            "T-101-11: must succeed with in-memory test tree (zero network)"
        );
    }

    // T-101-12: Cargo git dep without rev → UnresolvedRange with git URL as range
    #[test]
    fn t101_12_cargo_git_dep_without_rev_is_unresolved() {
        let toml_src = b"[package]\nname = \"x\"\nversion = \"0.1.0\"\n\
            [dependencies]\nmylib = { git = \"https://github.com/example/mylib\" }\n";
        let tree = tree_from(&[("Cargo.toml", toml_src)]);
        let edges =
            manifest_edges_from_tree(&tree, Ecosystem::Cargo).expect("T-101-12: must return Ok");

        assert_eq!(edges.len(), 1, "T-101-12: exactly one edge");
        match &edges[0] {
            ManifestEdge::Unresolved(u) => {
                assert_eq!(u.name, "mylib", "T-101-12: name");
                // The git URL must be stored verbatim as the range (ADR 011).
                assert_eq!(
                    u.range, "https://github.com/example/mylib",
                    "T-101-12: range must be the exact git URL verbatim"
                );
            }
            ManifestEdge::Resolved(_) => {
                panic!("T-101-12: git dep without rev must be Unresolved, not Resolved")
            }
        }
    }
}

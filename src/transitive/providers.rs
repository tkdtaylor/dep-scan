//! Concrete [`EdgeProvider`] implementations — ADR 009 piece 3b (task 103).
//!
//! Task 102 defines the abstract [`EdgeProvider`] trait the pure DFS engine
//! walks; this module wires the two *real* edge sources behind it:
//!
//! - [`LockfileEdgeProvider`] — registry edges read from a task-100
//!   [`DependencyGraph`] (the lockfile we already parsed). Lockfile-first
//!   (ADR 009 Decision 1): the edges are read straight from a graph in hand,
//!   with **zero network I/O**.
//! - [`ManifestEdgeProvider`] — git sub-tree edges read from a task-096
//!   [`FetchedTree`]'s own manifest via task-101 `manifest_edges_from_tree`.
//!   The tree was already fetched on the scan path; edge discovery here reads
//!   bytes already in hand (REQ-103-04) — it never triggers a new fetch.
//!
//! ## Fail-closed reconciliation (ADR 009 Decision 1 / REQ-103-02)
//!
//! Both providers normalise every edge to a cache [`NodeId`] before returning
//! it, so the engine's visited set collapses a node reached via the lockfile and
//! the same node reached via a manifest into one entry. Where a provider cannot
//! produce a concrete edge set — an absent/unparseable manifest, or a manifest
//! edge carrying an unresolved version range — it returns [`EdgeError`] rather
//! than a silent empty `Ok(vec![])`. The engine turns that error into a
//! diagnostic and floors the parent's verdict at ≥ `Warn` (never `Pass`).

use crate::lockfile::{DependencyGraph, NodeId};
use crate::transitive::engine::{EdgeError, EdgeProvider};
use crate::vcs::fetch::FetchedTree;
use crate::vcs::manifest::{Ecosystem, ManifestEdge, manifest_edges_from_tree};

// ---------------------------------------------------------------------------
// LockfileEdgeProvider (REQ-103-01)
// ---------------------------------------------------------------------------

/// An [`EdgeProvider`] backed by a task-100 [`DependencyGraph`] built from a
/// lockfile.
///
/// Registry edges are *already resolved and pinned* in the lockfile, so this
/// provider is a pure in-memory adjacency lookup — **no network, no fetch**
/// (ADR 009 Decision 1, lockfile-first).
///
/// A node that is **not** in the graph returns an **empty** edge set
/// (`Ok(vec![])`), not an error: a node may legitimately be absent from the
/// lockfile and instead appear via a manifest edge deeper in the walk (e.g. a
/// git sub-tree's child). Returning empty here lets the DFS engine reach that
/// node through the other source without flooring it spuriously (REQ-103-01).
#[allow(dead_code)] // entry-point wiring lands in task 108
pub struct LockfileEdgeProvider {
    graph: DependencyGraph,
}

#[allow(dead_code)] // entry-point wiring lands in task 108
impl LockfileEdgeProvider {
    /// Wrap an already-built [`DependencyGraph`].
    pub fn new(graph: DependencyGraph) -> Self {
        Self { graph }
    }

    /// Build a provider from raw `package-lock.json` bytes (npm).
    ///
    /// Convenience constructor for the npm path — parses the lockfile into a
    /// graph via task 100, then wraps it. **Zero network I/O**: only the bytes
    /// passed in are read.
    pub fn from_npm_lockfile_bytes(bytes: &str) -> anyhow::Result<Self> {
        let graph = crate::lockfile::package_lock_json_to_graph(bytes)?;
        Ok(Self::new(graph))
    }
}

impl EdgeProvider for LockfileEdgeProvider {
    fn edges_for(&self, node: &NodeId) -> Result<Vec<NodeId>, EdgeError> {
        // Pre-parsed adjacency lookup. A node not present in the lockfile graph
        // has an empty edge set here (it may still be reached via a manifest
        // edge deeper in the walk) — REQ-103-01.
        Ok(self.graph.edges_from(node).to_vec())
    }
}

// ---------------------------------------------------------------------------
// ManifestEdgeProvider (REQ-103-02)
// ---------------------------------------------------------------------------

/// An [`EdgeProvider`] backed by a single fetched git sub-tree's own manifest.
///
/// ADR 009 Decision 1 manifest-fallback: a git-sourced dependency's transitive
/// children are not in the consuming project's lockfile, so their direct edges
/// are read from the sub-tree's `package.json` / `Cargo.toml` inside the
/// already-materialised [`FetchedTree`] (task 096). The tree was fetched on the
/// scan path; **this provider performs no fetch** — it reads bytes already in
/// hand (REQ-103-04).
///
/// Fail-closed (REQ-103-02): an absent or unparseable manifest returns
/// [`EdgeError`], never a silent empty set. A manifest edge that carries an
/// unresolved version range (the common npm / Cargo case per ADR 011) also
/// returns [`EdgeError::UnresolvedRange`], so the parent is floored at ≥ `Warn`.
#[allow(dead_code)] // entry-point wiring lands in task 108
pub struct ManifestEdgeProvider {
    /// Edges pre-extracted from the tree at construction time, or the error to
    /// surface for every `edges_for` call (absent / unparseable manifest, or the
    /// first unresolved range encountered).
    result: Result<Vec<NodeId>, EdgeError>,
}

#[allow(dead_code)] // entry-point wiring lands in task 108
impl ManifestEdgeProvider {
    /// Read the direct edges of a fetched git sub-tree from its manifest.
    ///
    /// Calls task-101 `manifest_edges_from_tree`, then normalises each
    /// [`ManifestEdge`] to a cache [`NodeId`]:
    ///
    /// - `ManifestEdge::Resolved(node)` → the `NodeId` directly.
    /// - `ManifestEdge::Unresolved(range)` → fail-closed: surfaced as
    ///   [`EdgeError::UnresolvedRange`] so the engine floors the parent at
    ///   ≥ `Warn` (it cannot scan a version it has not resolved — ADR 011 / 009).
    ///
    /// An absent or unparseable manifest (a [`crate::vcs::manifest::ManifestError`])
    /// is also surfaced as [`EdgeError::UnresolvedRange`] — the only fail-closed
    /// edge-error channel the task-102 engine exposes — carrying the manifest
    /// filename and the parse/absence detail, so an unscannable sub-tree is
    /// floored at ≥ `Warn`, never silently `Ok(vec![])` (REQ-103-02 / T-103-05).
    pub fn from_fetched_tree(tree: &FetchedTree, ecosystem: Ecosystem) -> Self {
        let result = match manifest_edges_from_tree(tree, ecosystem) {
            Ok(edges) => Self::normalise(edges),
            Err(manifest_err) => Err(EdgeError::UnresolvedRange {
                // Fail-closed: an absent/unparseable manifest is unscannable
                // input. We reuse the single fail-closed edge-error channel the
                // engine understands; the message names the manifest so the
                // diagnostic is actionable.
                name: manifest_filename(ecosystem).to_string(),
                range: manifest_err.to_string(),
            }),
        };
        Self { result }
    }

    /// Normalise a manifest's edge list to concrete `NodeId`s, failing closed on
    /// the first unresolved range (the engine surfaces a single `EdgeError` per
    /// node, so the first unresolved edge floors the parent at ≥ `Warn`).
    fn normalise(edges: Vec<ManifestEdge>) -> Result<Vec<NodeId>, EdgeError> {
        let mut nodes = Vec::with_capacity(edges.len());
        for edge in edges {
            match edge {
                ManifestEdge::Resolved(node) => nodes.push(node),
                ManifestEdge::Unresolved(range) => {
                    return Err(EdgeError::UnresolvedRange {
                        name: range.name,
                        range: range.range,
                    });
                }
            }
        }
        Ok(nodes)
    }
}

impl EdgeProvider for ManifestEdgeProvider {
    fn edges_for(&self, _node: &NodeId) -> Result<Vec<NodeId>, EdgeError> {
        // The tree was read once at construction; every call returns the same
        // pre-extracted edge set (or the same fail-closed error). No fetch and
        // no re-parse happens here (REQ-103-04).
        self.result.clone()
    }
}

/// The manifest filename associated with an ecosystem, for diagnostics.
fn manifest_filename(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "package.json",
        Ecosystem::Cargo => "Cargo.toml",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::lockfile::NodeId;
    use crate::vcs::fetch::FetchedTree;

    fn reg(name: &str, version: &str, registry: &str) -> NodeId {
        NodeId::Registry {
            name: name.to_string(),
            version: version.to_string(),
            registry: registry.to_string(),
        }
    }

    fn tree_from(files: &[(&str, &[u8])]) -> FetchedTree {
        FetchedTree::from_files_for_test(
            files
                .iter()
                .map(|(p, c)| (PathBuf::from(p), c.to_vec()))
                .collect(),
        )
    }

    // --- T-103-02: lockfile provider returns correct edges (two-level tree) ---

    /// A package-lock.json (v2/v3 `packages`) with A → B → C.
    fn abc_npm_lockfile() -> &'static str {
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/a": { "version": "1.0.0", "dependencies": { "b": "1.0.0" } },
                "node_modules/b": { "version": "1.0.0", "dependencies": { "c": "1.0.0" } },
                "node_modules/c": { "version": "1.0.0" }
            }
        }"#
    }

    #[test]
    fn t103_02_lockfile_provider_returns_correct_edges() {
        let provider = LockfileEdgeProvider::from_npm_lockfile_bytes(abc_npm_lockfile())
            .expect("T-103-02: lockfile must parse");

        let a = reg("a", "1.0.0", "npm");
        let b = reg("b", "1.0.0", "npm");
        let c = reg("c", "1.0.0", "npm");

        let a_edges = provider.edges_for(&a).expect("T-103-02: edges_for(a)");
        assert_eq!(a_edges, vec![b.clone()], "T-103-02: A's only edge is B");

        let b_edges = provider.edges_for(&b).expect("T-103-02: edges_for(b)");
        assert_eq!(b_edges, vec![c.clone()], "T-103-02: B's only edge is C");

        let c_edges = provider.edges_for(&c).expect("T-103-02: edges_for(c)");
        assert!(c_edges.is_empty(), "T-103-02: C is a leaf");
    }

    // --- T-103-02b: node absent from the lockfile → empty edge set, not error ---

    #[test]
    fn t103_02b_absent_node_is_empty_not_error() {
        let provider = LockfileEdgeProvider::from_npm_lockfile_bytes(abc_npm_lockfile()).unwrap();
        // A git node that the lockfile never mentions: must be Ok(empty), so the
        // walk can still reach it via a manifest edge deeper down (REQ-103-01).
        let git_node = NodeId::Git {
            name: "deep".to_string(),
            commit_sha: "f".repeat(40),
        };
        let edges = provider.edges_for(&git_node);
        assert_eq!(
            edges,
            Ok(vec![]),
            "T-103-02b: a node not in the lockfile must yield an empty edge set, not an error"
        );
    }

    // --- T-103-04: manifest provider returns correct edges from a FetchedTree ---
    //
    // npm manifest edges are always UnresolvedRange (task 101 / ADR 011), so the
    // *resolved-edge* path is exercised with a Cargo git+rev manifest, the one
    // ManifestEdge::Resolved case. The npm fail-closed path is T-103-05b.

    #[test]
    fn t103_04_manifest_provider_returns_resolved_git_edge() {
        let cargo = b"[package]\nname = \"x\"\nversion = \"0.1.0\"\n\
            [dependencies]\nb = { git = \"https://github.com/example/b\", rev = \"abc123def456\" }\n";
        let tree = tree_from(&[("Cargo.toml", cargo as &[u8])]);
        let provider = ManifestEdgeProvider::from_fetched_tree(&tree, Ecosystem::Cargo);

        let parent = reg("a", "1.0.0", "git");
        let edges = provider
            .edges_for(&parent)
            .expect("T-103-04: resolved git+rev edge must be Ok");
        assert_eq!(
            edges,
            vec![NodeId::Git {
                name: "b".to_string(),
                commit_sha: "abc123def456".to_string(),
            }],
            "T-103-04: the pinned git dep must resolve to a NodeId::Git edge"
        );
    }

    // --- T-103-05: manifest provider fail-closed on missing manifest ---

    #[test]
    fn t103_05_manifest_provider_fail_closed_on_missing_manifest() {
        // A tree with no manifest file at all.
        let tree = tree_from(&[("README.md", b"# no manifest here" as &[u8])]);
        let provider = ManifestEdgeProvider::from_fetched_tree(&tree, Ecosystem::Npm);

        let parent = reg("a", "1.0.0", "git");
        let result = provider.edges_for(&parent);
        match result {
            Err(EdgeError::UnresolvedRange { name, range }) => {
                assert_eq!(
                    name, "package.json",
                    "T-103-05: missing-manifest error must name the manifest"
                );
                assert!(
                    range.contains("not found") || range.contains("package.json"),
                    "T-103-05: error detail must explain the absence, got: {range}"
                );
            }
            Ok(edges) => panic!(
                "T-103-05: absent manifest must NOT be a silent empty set, got Ok({edges:?})"
            ),
        }
    }

    // --- T-103-05b: npm UnresolvedRange edge also fails closed ---

    #[test]
    fn t103_05b_npm_unresolved_range_fails_closed() {
        // npm dependency ranges are always Unresolved (task 101) → fail closed.
        let json = br#"{"dependencies": {"express": "^4.18.0"}}"#;
        let tree = tree_from(&[("package.json", json as &[u8])]);
        let provider = ManifestEdgeProvider::from_fetched_tree(&tree, Ecosystem::Npm);

        let parent = reg("a", "1.0.0", "git");
        let result = provider.edges_for(&parent);
        assert!(
            matches!(
                result,
                Err(EdgeError::UnresolvedRange { ref name, ref range })
                    if name == "express" && range == "^4.18.0"
            ),
            "T-103-05b: an unresolved npm range must fail closed, got {result:?}"
        );
    }

    // --- T-103-05c: unparseable manifest fails closed (not silent empty) ---

    #[test]
    fn t103_05c_unparseable_manifest_fails_closed() {
        let tree = tree_from(&[("package.json", b"{ broken json" as &[u8])]);
        let provider = ManifestEdgeProvider::from_fetched_tree(&tree, Ecosystem::Npm);
        let parent = reg("a", "1.0.0", "git");
        assert!(
            matches!(
                provider.edges_for(&parent),
                Err(EdgeError::UnresolvedRange { .. })
            ),
            "T-103-05c: an unparseable manifest must fail closed, not Ok(empty)"
        );
    }
}

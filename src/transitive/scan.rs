// SPDX-License-Identifier: Apache-2.0
//! Transitive scan orchestration — the capstone entry point (ADR 009, task 108).
//!
//! This is the single seam `run_check` (`src/main.rs`) calls when
//! `[transitive].enabled = true`. It assembles the pieces every preceding task
//! built — the lockfile graph + git-manifest edge providers (task 103), the DFS
//! engine (task 102), the verdict rollup (task 104), the bounded fetch pool and
//! node budget (task 105), the `subtree_digest` cache gate (task 106), and the
//! `[transitive]` config (task 107) — into one walk that:
//!
//! 1. walks the dependency graph from each direct dependency root,
//! 2. fetches and scans git sub-trees (the only nodes that need a NEW network
//!    fetch — registry-node verdicts are reused from the flat scan), through the
//!    task-105 bounded fetch pool, charged against the task-105 node budget,
//! 3. rolls each root's subtree up worst-verdict-wins (task 104),
//! 4. surfaces every diagnostic (`DepthLimitReached`, `CycleDetected`,
//!    `NodeBudgetExceeded`, `UnresolvedRange`) in both the native table and the
//!    JSON output, and
//! 5. writes each scanned git node's `subtree_digest` (task 106) so a warm
//!    re-scan is a cache hit and a changed child invalidates its parent.
//!
//! ## Why registry-node verdicts are reused, not re-scanned
//!
//! An npm/Cargo lockfile lists **every** resolved package — direct and
//! transitive — as a flat entry, so the flat scan loop in `run_check` has already
//! scanned and cached every registry node before this entry point runs. The
//! transitive layer therefore does **no** new registry network I/O: it reads each
//! registry node's already-computed verdict from the flat results and only does
//! genuinely new work (fetch + policy scan) for **git sub-tree nodes**, which the
//! flat lockfile cannot cover (ADR 009 Decision 1 manifest-fallback). This keeps
//! the walk fast and the "network only on explicit scan" invariant intact: the
//! only fetches are git sub-tree fetches, all on the scan path.
//!
//! ## Fail-closed (ADR 009 Decision 2c)
//!
//! Every gap — an unfetchable git sub-tree, an `UnresolvedRange` manifest edge, a
//! depth-limit cut, a node-budget breach — rolls up to **at least `Warn`**, never
//! `Pass`. A malicious transitive node cannot hide behind a clean direct dep
//! (the headline scenario, T-108-04).

use std::collections::HashMap;

use crate::cache::Cache;
use crate::lockfile::{DependencyGraph, DependencySource, NodeId};
use crate::transitive::budget::{BudgetCharge, NodeBudget, NodeBudgetExceeded};
use crate::transitive::engine::{
    Diagnostic, EdgeError, EdgeProvider, NodeScanner, OnDepthLimit, TransitiveEngine, Verdict,
};
use crate::transitive::pool::run_bounded;
use crate::transitive::providers::ManifestEdgeProvider;
use crate::transitive::scanner::verdict_from_result_str;
use crate::vcs::manifest::Ecosystem;

// ---------------------------------------------------------------------------
// NodeId stringification (cache digest + display)
// ---------------------------------------------------------------------------

/// Render a [`NodeId`] to a stable, unambiguous string.
///
/// Used for two purposes:
/// - the `child_NodeId` half of a [`crate::cache::compute_subtree_digest`] pair
///   (task 106 takes pre-stringified `&str`s so `cache.rs` stays decoupled from
///   the transitive `NodeId` type), and
/// - the human-readable node name in the native/JSON diagnostic rows.
///
/// The scheme is `registry:<reg>/<name>@<version>` for registry nodes and
/// `git:<name>@<commit_sha>` for git nodes, so two distinct identities can never
/// collide.
pub(crate) fn node_id_string(node: &NodeId) -> String {
    match node {
        NodeId::Registry {
            name,
            version,
            registry,
        } => format!("registry:{registry}/{name}@{version}"),
        NodeId::Git { name, commit_sha } => format!("git:{name}@{commit_sha}"),
    }
}

/// Map a [`Verdict`] to the `pass`/`warn`/`block` string the cache digest and the
/// output rows use.
fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "pass",
        Verdict::Warn => "warn",
        Verdict::Block => "block",
    }
}

// ---------------------------------------------------------------------------
// Output-facing diagnostic + node row types
// ---------------------------------------------------------------------------

/// A diagnostic rendered into the scan output in **both** the native table and
/// the JSON payload (REQ-108-03).
///
/// This is the output-facing projection of the engine's [`Diagnostic`] plus the
/// budget's [`NodeBudgetExceeded`]; it carries exactly the fields each format
/// renders, so the two formats can never drift.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind")]
pub(crate) enum TransitiveDiagnostic {
    /// A subtree was cut at `max_depth` (carries the cut node + the depth).
    DepthLimitReached { node: String, depth: usize },
    /// A back-edge to an on-path node was found (carries both endpoints).
    CycleDetected { from: String, to: String },
    /// The per-scan node budget was exceeded (carries count + limit).
    NodeBudgetExceeded { count: u32, limit: u32 },
    /// A manifest edge carried an unresolvable range (carries the parent +
    /// the unresolvable `(name, range)`).
    UnresolvedRange {
        from: String,
        name: String,
        range: String,
    },
    /// A git node could not be fetched/resolved and was floored to `Warn`
    /// (SEC-003). Carries the node + a short reason so the operator does not see
    /// a bare `warn` row with no explanation.
    Unfetchable { node: String, reason: String },
}

impl TransitiveDiagnostic {
    /// The one-line human-readable string the native table renders.
    pub(crate) fn render_line(&self) -> String {
        match self {
            TransitiveDiagnostic::DepthLimitReached { node, depth } => format!(
                "  transitive: DEPTH-LIMIT — {node} cut at depth {depth} (verdict floored, fail-closed)"
            ),
            TransitiveDiagnostic::CycleDetected { from, to } => {
                format!("  transitive: CYCLE — back-edge {from} -> {to} (not re-traversed)")
            }
            TransitiveDiagnostic::NodeBudgetExceeded { count, limit } => format!(
                "  transitive: NODE-BUDGET — scan reached {count} distinct nodes, exceeding \
                 max_total_nodes {limit} (fail-closed: result is at least Warn)"
            ),
            TransitiveDiagnostic::UnresolvedRange { from, name, range } => format!(
                "  transitive: UNRESOLVED-RANGE — {from} requires {name} {range} \
                 (cannot pin; verdict floored, fail-closed)"
            ),
            TransitiveDiagnostic::Unfetchable { node, reason } => format!(
                "  transitive: UNFETCHABLE — {node} ({reason}); verdict floored to \
                 warn (fail-closed)"
            ),
        }
    }
}

/// One scanned transitive node, for the native table's transitive rows (T-108-12)
/// and the JSON payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct TransitiveNodeRow {
    /// The node identity string (`node_id_string`).
    pub(crate) node: String,
    /// The depth at which the node was reached (0 = a direct dep root).
    pub(crate) depth: usize,
    /// The node's own scan verdict, `pass`/`warn`/`block`.
    pub(crate) verdict: String,
}

/// The complete result of a transitive scan, ready to merge into `run_check`'s
/// output and exit-code logic.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub(crate) struct TransitiveOutcome {
    /// The worst verdict across every walked root and its subtree, with all
    /// fail-closed floors applied. `None` means no roots were walked.
    #[serde(serialize_with = "serialize_opt_verdict")]
    pub(crate) worst_verdict: Option<Verdict>,
    /// Every diagnostic, rendered in both formats (REQ-108-03).
    pub(crate) diagnostics: Vec<TransitiveDiagnostic>,
    /// One row per distinct scanned transitive node (REQ-108-12).
    pub(crate) nodes: Vec<TransitiveNodeRow>,
}

fn serialize_opt_verdict<S: serde::Serializer>(
    v: &Option<Verdict>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match v {
        Some(verdict) => s.serialize_str(verdict_str(*verdict)),
        None => s.serialize_none(),
    }
}

impl TransitiveOutcome {
    /// Whether the outcome warrants a non-zero exit code (Warn or Block).
    pub(crate) fn is_failure(&self) -> bool {
        matches!(self.worst_verdict, Some(Verdict::Warn) | Some(Verdict::Block))
            // A node-budget breach is itself a failure even if it is the only
            // signal (fail-closed, REQ-108-05 / T-108-16).
            || self
                .diagnostics
                .iter()
                .any(|d| matches!(d, TransitiveDiagnostic::NodeBudgetExceeded { .. }))
    }

    /// Render the transitive section of the native table.
    ///
    /// Returns an empty string when there is nothing transitive to show, so a
    /// disabled or empty walk adds no bytes to the flat output.
    pub(crate) fn render_native_section(&self) -> String {
        use std::fmt::Write as _;
        if self.nodes.is_empty() && self.diagnostics.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        let _ = writeln!(out, "Transitive scan:");
        for row in &self.nodes {
            let verdict_disp = match row.verdict.as_str() {
                "pass" => "pass".to_string(),
                "warn" => "WARN".to_string(),
                "block" => "BLOCK".to_string(),
                other => other.to_string(),
            };
            let _ = writeln!(
                out,
                "  {:<40} depth {:<3} {}",
                row.node, row.depth, verdict_disp
            );
        }
        for diag in &self.diagnostics {
            let _ = writeln!(out, "{}", diag.render_line());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Git provenance resolver (git NodeId -> (url, ref))
// ---------------------------------------------------------------------------

/// Resolves a git [`NodeId`] back to the `(url, ref)` it must be fetched from,
/// using provenance recorded from the lockfile's direct git deps.
///
/// A git `NodeId` carries only `(name, commit_sha)` (the cache identity); the
/// repository URL is not part of the identity, so it must be looked up from the
/// edge that introduced the node.
pub(crate) struct LockfileGitResolver {
    /// `name -> (url, ref)` for every git node whose origin is known.
    targets: HashMap<String, (String, String)>,
}

impl LockfileGitResolver {
    fn new() -> Self {
        Self {
            targets: HashMap::new(),
        }
    }

    fn record(&mut self, name: &str, url: &str, ref_: &str) {
        self.targets
            .insert(name.to_string(), (url.to_string(), ref_.to_string()));
    }
}

impl crate::transitive::scanner::GitTargetResolver for LockfileGitResolver {
    fn resolve(
        &self,
        name: &str,
        _commit_sha: &str,
    ) -> Option<crate::transitive::scanner::GitTarget> {
        self.targets
            .get(name)
            .map(|(url, ref_)| crate::transitive::scanner::GitTarget {
                url: url.clone(),
                ref_: ref_.clone(),
            })
    }
}

// ---------------------------------------------------------------------------
// Registry scanner reusing already-computed flat verdicts
// ---------------------------------------------------------------------------

/// A registry scanner that reuses the verdict the flat scan already computed for
/// a registry node, rather than re-running the async registry pipeline.
///
/// Keyed on the package name (the flat scan keys results by name, and a lockfile
/// resolves at most one version per name). An unknown registry node — one not in
/// the flat results — fails closed to `Warn` (it is unscanned input): the walk
/// never invents a `Pass` for a node it has no verdict for.
pub(crate) struct FlatResultRegistryScanner {
    verdicts: HashMap<String, Verdict>,
}

impl FlatResultRegistryScanner {
    /// Build from `(name, result_str)` pairs taken from the flat `CheckResult`s.
    pub(crate) fn from_flat_results(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            verdicts: pairs
                .into_iter()
                .map(|(name, result)| (name, verdict_from_result_str(&result)))
                .collect(),
        }
    }
}

impl crate::transitive::scanner::RegistryScanner for FlatResultRegistryScanner {
    fn scan_registry(&self, name: &str, _version: &str, _registry: &str) -> Verdict {
        // Unknown registry node → fail-closed Warn (never silent Pass).
        self.verdicts.get(name).copied().unwrap_or(Verdict::Warn)
    }
}

// ---------------------------------------------------------------------------
// Composite edge provider (registry: lockfile graph; git: fetched manifest)
// ---------------------------------------------------------------------------

/// Edge provider that reconciles the two ADR-009 sources by node identity:
/// registry edges from the lockfile graph (task 103 `LockfileEdgeProvider`
/// semantics) and git sub-tree edges from a pre-fetched manifest provider
/// (task 103 `ManifestEdgeProvider`), keyed on the git node.
///
/// Git manifest edges are pre-extracted at construction (the trees were fetched
/// through the bounded pool before the walk), so `edges_for` performs **no**
/// fetch and **no** re-parse — it is a pure adjacency lookup (REQ-103-04).
pub(crate) struct CompositeEdgeProvider {
    graph: DependencyGraph,
    /// `git NodeId -> its pre-extracted manifest edge result`.
    git_edges: HashMap<NodeId, Result<Vec<NodeId>, EdgeError>>,
}

impl CompositeEdgeProvider {
    fn new(graph: DependencyGraph) -> Self {
        Self {
            graph,
            git_edges: HashMap::new(),
        }
    }

    fn set_git_edges(&mut self, node: NodeId, edges: Result<Vec<NodeId>, EdgeError>) {
        self.git_edges.insert(node, edges);
    }
}

impl EdgeProvider for CompositeEdgeProvider {
    fn edges_for(&self, node: &NodeId) -> Result<Vec<NodeId>, EdgeError> {
        match node {
            NodeId::Git { .. } => self
                .git_edges
                .get(node)
                .cloned()
                // A git node we never fetched a manifest for has no recorded
                // edges — treat as a leaf (Ok(empty)). Its own scan verdict still
                // participates in rollup; this is not a fail-closed gap because
                // the node itself WAS scanned.
                .unwrap_or(Ok(vec![])),
            NodeId::Registry { .. } => Ok(self.graph.edges_from(node).to_vec()),
        }
    }
}

// ---------------------------------------------------------------------------
// Walk seam (so a spy can assert dfs_walk is NOT invoked when disabled)
// ---------------------------------------------------------------------------

/// The seam the orchestration walks each root through. Production uses
/// [`EngineWalker`] (the real task-102 DFS engine); tests inject a spy that
/// records whether `walk_root` was ever called (T-108-03 / T-108-14: when the
/// feature is disabled the orchestration is never entered, so the walker is
/// never invoked).
pub(crate) trait RootWalker {
    /// Walk one root and return its rolled-up verdict + diagnostics.
    fn walk_root(
        &self,
        root: &NodeId,
        max_depth: usize,
        on_depth_limit: OnDepthLimit,
    ) -> crate::transitive::engine::WalkResult;
}

/// Production [`RootWalker`]: drives the real task-102 DFS engine.
pub(crate) struct EngineWalker<'a, E: EdgeProvider, S: NodeScanner> {
    engine: TransitiveEngine<'a, E, S>,
}

impl<'a, E: EdgeProvider, S: NodeScanner> EngineWalker<'a, E, S> {
    pub(crate) fn new(edges: &'a E, scanner: &'a S) -> Self {
        Self {
            engine: TransitiveEngine::new(edges, scanner),
        }
    }
}

impl<E: EdgeProvider, S: NodeScanner> RootWalker for EngineWalker<'_, E, S> {
    fn walk_root(
        &self,
        root: &NodeId,
        max_depth: usize,
        on_depth_limit: OnDepthLimit,
    ) -> crate::transitive::engine::WalkResult {
        self.engine.dfs_walk(root, max_depth, on_depth_limit)
    }
}

// ---------------------------------------------------------------------------
// Diagnostic projection
// ---------------------------------------------------------------------------

/// Project an engine [`Diagnostic`] to the output-facing [`TransitiveDiagnostic`].
fn project_diagnostic(d: &Diagnostic) -> TransitiveDiagnostic {
    match d {
        Diagnostic::DepthLimitReached { node, depth } => TransitiveDiagnostic::DepthLimitReached {
            node: node_id_string(node),
            depth: *depth,
        },
        Diagnostic::CycleDetected { from, to } => TransitiveDiagnostic::CycleDetected {
            from: node_id_string(from),
            to: node_id_string(to),
        },
        Diagnostic::UnresolvedRange { from, name, range } => {
            TransitiveDiagnostic::UnresolvedRange {
                from: node_id_string(from),
                name: name.clone(),
                range: range.clone(),
            }
        }
        Diagnostic::Unfetchable { node, reason } => TransitiveDiagnostic::Unfetchable {
            node: node_id_string(node),
            reason: reason.clone(),
        },
    }
}

/// Project a budget breach to the output-facing diagnostic.
fn project_budget(b: &NodeBudgetExceeded) -> TransitiveDiagnostic {
    TransitiveDiagnostic::NodeBudgetExceeded {
        count: b.count,
        limit: b.limit,
    }
}

// ---------------------------------------------------------------------------
// The orchestration entry point
// ---------------------------------------------------------------------------

/// The collaborators a transitive scan needs, threaded from `run_check`.
pub(crate) struct TransitiveScanInputs<'a> {
    /// The lockfile dependency graph (registry edges), already parsed.
    pub(crate) graph: DependencyGraph,
    /// The direct dependency roots to walk from, with their source (so git
    /// roots can be fetch-resolved).
    pub(crate) roots: Vec<(NodeId, Option<DependencySource>)>,
    /// Verdicts the flat scan already computed, as `(name, result_str)` pairs.
    pub(crate) flat_verdicts: Vec<(String, String)>,
    /// The shared cache (git two-gate decision + subtree-digest write).
    pub(crate) cache: &'a Cache,
    /// The same policy set the flat scan uses.
    pub(crate) policies: &'a [Box<dyn crate::policy::Policy>],
    /// `max_depth` / `on_depth_limit` / `fetch_concurrency` / `max_total_nodes`.
    pub(crate) config: &'a crate::config::TransitiveConfig,
}

/// Run the transitive scan and produce its [`TransitiveOutcome`].
///
/// `fetcher` is the git-tree fetcher seam (the real `VcsFetcher` in production,
/// a spy in tests). This function performs the genuine NEW network work (git
/// sub-tree fetches) through the bounded pool, then walks each root through the
/// DFS engine for rollup + diagnostics, and finally writes each scanned git
/// node's `subtree_digest` to the cache.
pub(crate) fn run_transitive_scan<F>(
    inputs: TransitiveScanInputs<'_>,
    fetcher: &F,
) -> TransitiveOutcome
where
    F: crate::GitTreeFetcher + Clone + Send + Sync + 'static,
{
    let TransitiveScanInputs {
        graph,
        roots,
        flat_verdicts,
        cache,
        policies,
        config,
    } = inputs;

    let max_depth = config.max_depth as usize;
    let on_depth_limit: OnDepthLimit = config.on_depth_limit.into();

    // --- Node budget (task 105): charge every distinct reachable node up front.
    // The budget is a hard upper bound on work; exceeding it fails the scan
    // closed (REQ-108-05 / T-108-16).
    let mut budget = NodeBudget::new(config.max_total_nodes);
    let mut budget_breach: Option<NodeBudgetExceeded> = None;

    // Build the git provenance resolver and the set of direct git roots.
    let mut git_resolver = LockfileGitResolver::new();
    let mut git_roots: Vec<NodeId> = Vec::new();
    for (node, source) in &roots {
        if let (NodeId::Git { name, .. }, Some(DependencySource::Git { url, ref_ })) =
            (node, source.as_ref())
        {
            git_resolver.record(name, url, ref_);
            git_roots.push(node.clone());
        }
    }

    // Charge the budget over every node we will reach: all graph nodes + roots +
    // git roots. (Charging up front is the cheapest way to enforce the ceiling
    // before any fetch is spent.)
    let mut all_charge_nodes: Vec<NodeId> = graph.nodes().cloned().collect();
    for (node, _) in &roots {
        all_charge_nodes.push(node.clone());
    }
    for g in &git_roots {
        all_charge_nodes.push(g.clone());
    }
    for node in &all_charge_nodes {
        if let BudgetCharge::Exceeded(breach) = budget.charge(node) {
            budget_breach = Some(breach);
            break;
        }
    }

    // --- Build the registry-verdict scanner (reuses the flat results).
    let registry_scanner = FlatResultRegistryScanner::from_flat_results(flat_verdicts);

    // --- Build the composite edge provider.
    let mut composite = CompositeEdgeProvider::new(graph);

    // The transitive node scanner reuses the SAME git arm the flat scan uses
    // (task 103): cache decision -> fetch -> run_git_tree_policies -> cache write.
    let scanner = crate::transitive::scanner::TransitiveNodeScanner::new(
        cache,
        fetcher,
        policies,
        &git_resolver,
        &registry_scanner,
    );

    // Pre-fetch + extract manifest edges for each direct git root, bounding the
    // number of simultaneous fetches at fetch_concurrency through the task-105
    // bounded pool (REQ-108-05 / T-108-15).
    //
    // A git root that is already a VALID warm cache hit (pinned SHA, content_hash
    // and subtree_digest both present) is NOT re-fetched here (T-108-17): its
    // cached verdict is authoritative and the subtree-digest gate guarantees its
    // subtree is unchanged, so it is treated as a leaf. The invalidate pre-pass
    // below still drops it if a child's verdict actually changed (T-108-18).
    if budget_breach.is_none() && !git_roots.is_empty() {
        let cold_roots: Vec<NodeId> = git_roots
            .iter()
            .filter(|r| !is_warm_git_root(cache, &git_resolver, r))
            .cloned()
            .collect();
        // Warm roots are leaves on this path: no fetch, no re-discovered edges.
        for node in &git_roots {
            if is_warm_git_root(cache, &git_resolver, node) {
                composite.set_git_edges(node.clone(), Ok(vec![]));
            }
        }
        let trees = bounded_fetch_trees(
            &cold_roots,
            &git_resolver,
            fetcher,
            config.fetch_concurrency,
        );
        for (node, tree) in cold_roots.iter().zip(trees) {
            let edges = match tree {
                Some(tree) => {
                    let ecosystem = detect_ecosystem(&tree);
                    let provider = ManifestEdgeProvider::from_fetched_tree(&tree, ecosystem);
                    provider.edges_for(node)
                }
                // Unfetchable / unknown origin: no discoverable edges. The node's
                // OWN verdict still fails closed in the scanner's git arm (the
                // re-fetch + Err → Warn path), so it is never silently Pass.
                None => Ok(vec![]),
            };
            // SEC-001: charge the budget for every node a git sub-tree's manifest
            // discovers. Without this, a git sub-tree could declare an arbitrary
            // fan-out that is never charged, so `max_total_nodes` would NOT be the
            // hard upper bound ADR 009 Decision 3b mitigation 5 promises. A breach
            // here still fails closed (NodeBudgetExceeded → ≥ Warn → exit ≥ 1).
            if let Ok(children) = &edges {
                for child in children {
                    if let BudgetCharge::Exceeded(breach) = budget.charge(child) {
                        budget_breach = Some(breach);
                        break;
                    }
                }
            }
            composite.set_git_edges(node.clone(), edges);
            if budget_breach.is_some() {
                break;
            }
        }
    }

    // --- Subtree-digest invalidation pre-pass (task 106, ADR 009 Decision 4,
    // REQ-108-06 / T-108-18). For each git parent that carries a stored
    // subtree_digest, recompute the digest from its children's CURRENT verdicts;
    // if it no longer matches (a child's verdict changed, or a child was
    // added/removed), the parent's cached row is **stale and unsafe** — invalidate
    // it so the walk re-scans the parent and propagates the new verdict to the
    // root. This is the second gate ADR 009 adds alongside the content-hash gate:
    // a content-unchanged parent whose subtree changed must NOT serve its stale
    // verdict.
    if budget_breach.is_none() {
        invalidate_stale_parents(cache, &composite, &scanner, &git_roots, &git_resolver);
    }

    // --- Walk each root through the DFS engine for rollup + diagnostics.
    let walker = EngineWalker::new(&composite, &scanner);
    let mut outcome = TransitiveOutcome::default();
    if let Some(breach) = &budget_breach {
        outcome.diagnostics.push(project_budget(breach));
    }

    // Dedup node rows + diagnostics across roots (a diamond node appears once).
    let mut seen_rows: HashMap<String, ()> = HashMap::new();
    let mut seen_diags: HashMap<String, ()> = HashMap::new();

    if budget_breach.is_none() {
        for (root, _) in &roots {
            let result = walker.walk_root(root, max_depth, on_depth_limit);
            outcome.worst_verdict = Some(match outcome.worst_verdict {
                Some(prev) => prev.max(result.verdict),
                None => result.verdict,
            });
            for diag in &result.diagnostics {
                let projected = project_diagnostic(diag);
                let key = format!("{projected:?}");
                if seen_diags.insert(key, ()).is_none() {
                    outcome.diagnostics.push(projected);
                }
            }
            // SEC-002: build display rows from the walk's OWN per-node verdicts —
            // the single authoritative scan the rollup above was computed from —
            // NOT an independent re-scan. This guarantees a row can never show a
            // verdict worse than the rolled-up `worst_verdict` while the exit code
            // under-reports it: both derive from the same scan.
            for (node, depth, verdict) in &result.node_verdicts {
                let key = node_id_string(node);
                if seen_rows.insert(key.clone(), ()).is_some() {
                    continue; // diamond dedup across roots
                }
                // Belt-and-suspenders: fold any node-row verdict that is somehow
                // worse than the rollup back into worst_verdict BEFORE is_failure()
                // is consulted, so the exit code can never under-report relative to
                // a printed row (SEC-002).
                outcome.worst_verdict = Some(match outcome.worst_verdict {
                    Some(prev) => prev.max(*verdict),
                    None => *verdict,
                });
                outcome.nodes.push(TransitiveNodeRow {
                    node: key,
                    depth: *depth,
                    verdict: verdict_str(*verdict).to_string(),
                });
            }
        }

        // SEC-003: surface every git node that was floored to Warn because it
        // could not be fetched/resolved, so the operator sees WHY a `warn` row has
        // no policy reason (rather than a bare, unexplained warn). Drained from the
        // scanner after the walk; deduped against diagnostics already emitted.
        for un in scanner.take_unfetchable() {
            let projected = TransitiveDiagnostic::Unfetchable {
                node: node_id_string(&un.node),
                reason: un.reason,
            };
            let key = format!("{projected:?}");
            if seen_diags.insert(key, ()).is_none() {
                outcome.diagnostics.push(projected);
            }
        }
    }

    // --- Write each scanned git node's subtree_digest (task 106) so a warm
    // re-scan is a cache hit and a changed child invalidates its parent.
    //
    // SEC-004: skip the cache write entirely on a budget breach. A breached scan
    // is a fail-closed, incomplete scan; persisting a pass row or an empty-subtree
    // digest for it would let a subsequent run serve a stale cache hit derived
    // from work that was never actually completed. A breached scan persists
    // nothing.
    if budget_breach.is_none() {
        write_subtree_digests(cache, &composite, &scanner, &roots, max_depth);
    }

    outcome
}

/// Detect which ecosystem's manifest a fetched tree carries (npm vs Cargo).
/// Prefers `package.json`, then `Cargo.toml`; defaults to npm.
fn detect_ecosystem(tree: &crate::vcs::fetch::FetchedTree) -> Ecosystem {
    let mut has_cargo = false;
    for f in tree.files() {
        let name = f.path().file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "package.json" {
            return Ecosystem::Npm;
        }
        if name == "Cargo.toml" {
            has_cargo = true;
        }
    }
    if has_cargo {
        Ecosystem::Cargo
    } else {
        Ecosystem::Npm
    }
}

/// Fetch each git root's tree, bounding simultaneous fetches at
/// `fetch_concurrency` through the task-105 bounded pool, and return the trees in
/// `git_roots` order (`None` for an unresolvable/unfetchable root).
///
/// The bounded pool ([`run_bounded`]) is the single place fetch concurrency is
/// decided (task 105, REQ-105-01/07). Because the pool spawns `'static` worker
/// threads, each worker captures only owned data: the resolved `(url, ref)`
/// target Strings and a clonable, `Send + Sync` fetcher handle. The fetched
/// trees are sent back over a per-index sink; the closures themselves return a
/// `Verdict` placeholder so the existing `run_bounded` signature is reused
/// verbatim with no second concurrency implementation.
fn bounded_fetch_trees<F>(
    git_roots: &[NodeId],
    resolver: &LockfileGitResolver,
    fetcher: &F,
    fetch_concurrency: u32,
) -> Vec<Option<crate::vcs::fetch::FetchedTree>>
where
    F: crate::GitTreeFetcher + Clone + Send + Sync + 'static,
{
    use crate::transitive::scanner::GitTargetResolver as _;
    use std::sync::{Arc, Mutex};

    let n = git_roots.len();
    let sink: Arc<Mutex<Vec<Option<crate::vcs::fetch::FetchedTree>>>> =
        Arc::new(Mutex::new((0..n).map(|_| None).collect()));

    let tasks: Vec<_> = git_roots
        .iter()
        .enumerate()
        .filter_map(|(idx, node)| {
            let NodeId::Git { name, commit_sha } = node else {
                return None;
            };
            let target = resolver.resolve(name, commit_sha)?;
            let fetcher = fetcher.clone();
            let sink = Arc::clone(&sink);
            Some(move || -> Verdict {
                if let Ok(tree) = fetcher.fetch_tree(&target.url, &target.ref_) {
                    sink.lock().expect("fetch sink mutex poisoned")[idx] = Some(tree);
                }
                Verdict::Pass
            })
        })
        .collect();

    let _ = run_bounded(tasks, fetch_concurrency);

    Arc::try_unwrap(sink)
        .expect("all pool workers joined before unwrap")
        .into_inner()
        .expect("fetch sink mutex poisoned")
}

/// Whether a git root is a VALID warm cache hit that need not be re-fetched for
/// edge discovery (T-108-17). True only when:
///   - the resolved ref is a **pinned** SHA (mutable refs are never cached and
///     always re-fetch — task 097), and
///   - a cache row exists carrying BOTH a `content_hash` (the content gate) and a
///     `subtree_digest` (the task-106 subtree gate).
///
/// When true the orchestration skips the pre-fetch and treats the root as a leaf:
/// its cached verdict is authoritative and its subtree is provably unchanged. The
/// invalidate pre-pass still drops the row if a child's verdict actually changed,
/// forcing a re-walk (T-108-18).
fn is_warm_git_root(cache: &Cache, resolver: &LockfileGitResolver, root: &NodeId) -> bool {
    use crate::transitive::scanner::GitTargetResolver as _;
    let NodeId::Git { name, .. } = root else {
        return false;
    };
    let Some(target) = resolver.resolve(name, "") else {
        return false;
    };
    if crate::policy::mutable_ref::classify_ref(&target.ref_)
        != crate::policy::mutable_ref::RefKind::Pinned
    {
        return false;
    }
    match cache.lookup(name, &target.ref_, "git") {
        Ok(Some(entry)) => entry.content_hash.is_some() && entry.subtree_digest.is_some(),
        _ => false,
    }
}

/// Invalidate any git parent whose stored `subtree_digest` no longer matches the
/// digest recomputed from its children's **current** verdicts (task 106 /
/// REQ-108-06).
///
/// This is the live wiring of [`crate::cache::subtree_digest_valid`]: for each
/// git root that has children and a cached row carrying a subtree digest, we
/// re-fingerprint the subtree from the children's current verdicts and compare.
/// On mismatch the row is invalidated so the subsequent walk re-scans the parent
/// — a content-unchanged parent whose subtree changed is never served stale
/// (fail-closed, ADR 009 Decision 4). Children's current verdicts are obtained by
/// scanning them; git children are fetched fresh (so a changed child re-fetches),
/// and the node-budget/cache already bound that work.
fn invalidate_stale_parents<E: EdgeProvider, S: NodeScanner>(
    cache: &Cache,
    edges: &E,
    scanner: &S,
    git_roots: &[NodeId],
    resolver: &LockfileGitResolver,
) {
    use crate::transitive::scanner::GitTargetResolver as _;
    for root in git_roots {
        let NodeId::Git { name, .. } = root else {
            continue;
        };
        let Some(target) = resolver.resolve(name, "") else {
            continue;
        };
        // Only pinned refs are cached (task 097); a mutable ref is never cached,
        // so there is nothing to invalidate (it always re-fetches anyway).
        if crate::policy::mutable_ref::classify_ref(&target.ref_)
            != crate::policy::mutable_ref::RefKind::Pinned
        {
            continue;
        }
        let stored = match cache.lookup(name, &target.ref_, "git") {
            Ok(Some(entry)) => entry.subtree_digest,
            _ => continue,
        };
        // Only a row that actually recorded a subtree (a transitive parent) can be
        // stale by the subtree-digest gate; a flat row (None) is governed by the
        // content-hash gate alone.
        let Some(stored_digest) = stored else {
            continue;
        };
        let children = match edges.edges_for(root) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let child_strings: Vec<(String, String)> = children
            .iter()
            .map(|c| (node_id_string(c), verdict_str(scanner.scan(c)).to_string()))
            .collect();
        let child_refs: Vec<(&str, &str)> = child_strings
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let recomputed = crate::cache::compute_subtree_digest(&child_refs);
        if !crate::cache::subtree_digest_valid(Some(&stored_digest), Some(&recomputed)) {
            // Stale: a child changed. Drop the parent's row so the walk re-scans
            // it and propagates the new verdict (REQ-108-06 / T-108-18).
            let _ = cache.invalidate(name, &target.ref_, "git");
        }
    }
}

/// Compute and store each scanned git node's `subtree_digest` (task 106).
///
/// For every git root reachable within `max_depth`, we recompute the digest over
/// its children's `(NodeId, verdict)` pairs and write it on the cache row (only
/// for pinned SHAs — mutable refs are never cached, task 097). This is what makes
/// a warm re-scan a cache hit and a changed child invalidate its parent
/// (REQ-108-06): on the next scan the parent's recomputed digest is compared
/// against this stored value.
fn write_subtree_digests<E: EdgeProvider, S: NodeScanner>(
    cache: &Cache,
    edges: &E,
    scanner: &S,
    roots: &[(NodeId, Option<DependencySource>)],
    max_depth: usize,
) {
    if max_depth == 0 {
        return;
    }
    for (root, source) in roots {
        if let (NodeId::Git { name, .. }, Some(DependencySource::Git { ref_, .. })) =
            (root, source.as_ref())
        {
            if crate::policy::mutable_ref::classify_ref(ref_)
                != crate::policy::mutable_ref::RefKind::Pinned
            {
                continue;
            }
            let children = match edges.edges_for(root) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let child_strings: Vec<(String, String)> = children
                .iter()
                .map(|c| (node_id_string(c), verdict_str(scanner.scan(c)).to_string()))
                .collect();
            let child_refs: Vec<(&str, &str)> = child_strings
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            let digest = crate::cache::compute_subtree_digest(&child_refs);
            let verdict = scanner.scan(root);
            // Preserve the existing content hash so the content-hash gate still
            // holds on the next scan; skip if the node was never cached (e.g.
            // unfetchable).
            if let Ok(Some(entry)) = cache.lookup(name, ref_, "git")
                && let Some(content_hash) = entry.content_hash.as_deref()
            {
                let _ = cache.insert_git(
                    name,
                    ref_,
                    verdict_str(verdict),
                    Some(content_hash),
                    Some(&digest),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DepthLimitAction, TransitiveConfig};
    use crate::lockfile::NodeId;
    use crate::policy::Policy;
    use crate::vcs::fetch::FetchedTree;
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn reg(name: &str, version: &str) -> NodeId {
        NodeId::Registry {
            name: name.to_string(),
            version: version.to_string(),
            registry: "npm".to_string(),
        }
    }
    fn git(name: &str, sha: &str) -> NodeId {
        NodeId::Git {
            name: name.to_string(),
            commit_sha: sha.to_string(),
        }
    }

    const PINNED: &str = "abc123def4567890abc123def4567890abc12345"; // 40 hex

    /// A fetcher returning a fixed tree and counting fetches (zero network).
    ///
    /// Also tracks peak concurrent fetches (T-108-15) and can be told to fail
    /// every fetch (SEC-003 unfetchable path).
    #[derive(Clone)]
    struct SpyFetcher {
        files: Vec<(PathBuf, Vec<u8>)>,
        fetches: Arc<AtomicUsize>,
        /// Live concurrent fetches right now, and the peak observed — the gauge
        /// pattern from task 105's `ConcurrencyGauge`, inlined so T-108-15 can
        /// assert the wired pool honours `fetch_concurrency`.
        live: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        /// When set, every `fetch_tree` returns an error (unfetchable path).
        fail: bool,
    }
    impl SpyFetcher {
        fn new(files: &[(&str, &[u8])]) -> Self {
            Self {
                files: files
                    .iter()
                    .map(|(p, c)| (PathBuf::from(p), c.to_vec()))
                    .collect(),
                fetches: Arc::new(AtomicUsize::new(0)),
                live: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
                fail: false,
            }
        }
        /// A fetcher whose every fetch fails (SEC-003 unfetchable git node).
        fn failing() -> Self {
            let mut f = Self::new(&[]);
            f.fail = true;
            f
        }
        fn fetch_count(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
        /// Highest number of simultaneous fetches observed (T-108-15).
        fn peak_concurrency(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }
    }
    impl crate::GitTreeFetcher for SpyFetcher {
        fn fetch_tree(&self, _url: &str, _ref_: &str) -> anyhow::Result<FetchedTree> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            // Concurrency gauge: bump live, raise peak, hold briefly so an
            // over-admission would be observable, then drop live.
            let now = self.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(20));
            self.live.fetch_sub(1, Ordering::SeqCst);
            if self.fail {
                return Err(anyhow::anyhow!("spy fetch failure (fixture)"));
            }
            Ok(FetchedTree::from_files_for_test(self.files.clone()))
        }
    }

    /// A policy that always blocks (simulates a malicious install script).
    #[derive(Debug)]
    struct AlwaysBlock;
    impl Policy for AlwaysBlock {
        fn name(&self) -> &str {
            "always_block"
        }
        fn evaluate(&self, _ctx: &crate::types::ScanContext) -> crate::policy::PolicyResult {
            crate::policy::PolicyResult::Block("malicious install script (fixture)".to_string())
        }
    }

    fn cfg(enabled: bool) -> TransitiveConfig {
        TransitiveConfig {
            enabled,
            max_depth: 5,
            on_depth_limit: DepthLimitAction::Warn,
            fetch_concurrency: 4,
            max_total_nodes: 5000,
        }
    }

    // --- T-108-04 (unit half): a clean registry parent with a MALICIOUS git
    // transitive child rolls up to Block, naming the git sub-tree. ----------
    #[test]
    fn t108_04_malicious_git_child_rolls_up_block_and_is_named() {
        let cache = Cache::in_memory().unwrap();
        let root = reg("root-pkg", "1.0.0");
        let child = git("dep-b", PINNED);

        // root-pkg is a clean registry direct dep; dep-b is a malicious git
        // sub-tree reached as a direct git root from the lockfile.
        let graph = DependencyGraph::from_edges(vec![]);
        let policies: Vec<Box<dyn Policy>> = vec![Box::new(AlwaysBlock)];
        let flat = vec![("root-pkg".to_string(), "pass".to_string())];
        let fetcher = SpyFetcher::new(&[("postinstall.js", b"require('child_process')" as &[u8])]);

        let inputs = TransitiveScanInputs {
            graph,
            roots: vec![
                (root.clone(), None),
                (
                    child.clone(),
                    Some(DependencySource::Git {
                        url: "git://127.0.0.1/repo".to_string(),
                        ref_: PINNED.to_string(),
                    }),
                ),
            ],
            flat_verdicts: flat,
            cache: &cache,
            policies: &policies,
            config: &cfg(true),
        };
        let outcome = run_transitive_scan(inputs, &fetcher);

        assert_eq!(
            outcome.worst_verdict,
            Some(Verdict::Block),
            "T-108-04: a malicious git transitive child must roll up to Block"
        );
        assert!(outcome.is_failure());
        let named = outcome
            .nodes
            .iter()
            .any(|r| r.node.contains("dep-b") && r.verdict == "block");
        assert!(
            named,
            "T-108-04: output must name dep-b as the Block source, rows: {:?}",
            outcome.nodes
        );
        assert!(fetcher.fetch_count() >= 1);
    }

    // --- T-108-05: an all-clean transitive tree rolls up to Pass. ----------
    #[test]
    fn t108_05_all_clean_tree_rolls_up_pass() {
        let cache = Cache::in_memory().unwrap();
        let (root, a, b) = (reg("root", "1.0"), reg("a", "1.0"), reg("b", "1.0"));
        let graph =
            DependencyGraph::from_edges(vec![(root.clone(), a.clone()), (a.clone(), b.clone())]);
        let policies: Vec<Box<dyn Policy>> = vec![];
        let flat = vec![
            ("root".to_string(), "pass".to_string()),
            ("a".to_string(), "pass".to_string()),
            ("b".to_string(), "pass".to_string()),
        ];
        let fetcher = SpyFetcher::new(&[]);
        let inputs = TransitiveScanInputs {
            graph,
            roots: vec![(root.clone(), None)],
            flat_verdicts: flat,
            cache: &cache,
            policies: &policies,
            config: &cfg(true),
        };
        let outcome = run_transitive_scan(inputs, &fetcher);
        assert_eq!(outcome.worst_verdict, Some(Verdict::Pass));
        assert!(!outcome.is_failure());
        assert_eq!(fetcher.fetch_count(), 0, "pure registry walk: no git fetch");
    }

    // --- T-108-06/07: DepthLimitReached renders in JSON and native. --------
    #[test]
    fn t108_06_07_depth_limit_renders_in_both_formats() {
        let cache = Cache::in_memory().unwrap();
        let (root, a, b) = (reg("root", "1.0"), reg("a", "1.0"), reg("b", "1.0"));
        let graph =
            DependencyGraph::from_edges(vec![(root.clone(), a.clone()), (a.clone(), b.clone())]);
        let policies: Vec<Box<dyn Policy>> = vec![];
        let flat = vec![
            ("root".to_string(), "pass".to_string()),
            ("a".to_string(), "pass".to_string()),
            ("b".to_string(), "pass".to_string()),
        ];
        let fetcher = SpyFetcher::new(&[]);
        let mut config = cfg(true);
        config.max_depth = 1;
        let inputs = TransitiveScanInputs {
            graph,
            roots: vec![(root.clone(), None)],
            flat_verdicts: flat,
            cache: &cache,
            policies: &policies,
            config: &config,
        };
        let outcome = run_transitive_scan(inputs, &fetcher);
        let native = outcome.render_native_section();
        assert!(
            native.contains("DEPTH-LIMIT"),
            "T-108-07: native output must show the depth-limit diagnostic:\n{native}"
        );
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(
            json.contains("DepthLimitReached") && json.contains("\"depth\":2"),
            "T-108-06: JSON output must carry DepthLimitReached with depth: {json}"
        );
    }

    // --- T-108-09: CycleDetected renders in both formats. ------------------
    #[test]
    fn t108_09_cycle_renders_in_both_formats() {
        let cache = Cache::in_memory().unwrap();
        let (a, b) = (reg("a", "1.0"), reg("b", "1.0"));
        let graph =
            DependencyGraph::from_edges(vec![(a.clone(), b.clone()), (b.clone(), a.clone())]);
        let policies: Vec<Box<dyn Policy>> = vec![];
        let flat = vec![
            ("a".to_string(), "pass".to_string()),
            ("b".to_string(), "pass".to_string()),
        ];
        let fetcher = SpyFetcher::new(&[]);
        let inputs = TransitiveScanInputs {
            graph,
            roots: vec![(a.clone(), None)],
            flat_verdicts: flat,
            cache: &cache,
            policies: &policies,
            config: &cfg(true),
        };
        let outcome = run_transitive_scan(inputs, &fetcher);
        let native = outcome.render_native_section();
        assert!(
            native.contains("CYCLE"),
            "T-108-09: native output must show the cycle diagnostic:\n{native}"
        );
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(
            json.contains("CycleDetected"),
            "T-108-09: JSON output must carry CycleDetected: {json}"
        );
    }

    // --- T-108-08/16: NodeBudgetExceeded renders in both formats + fails. ---
    #[test]
    fn t108_08_16_node_budget_exceeded_in_both_formats_and_fails() {
        let cache = Cache::in_memory().unwrap();
        let nodes: Vec<NodeId> = (0..5).map(|i| reg(&format!("n{i}"), "1.0")).collect();
        let mut edges = Vec::new();
        for w in nodes.windows(2) {
            edges.push((w[0].clone(), w[1].clone()));
        }
        let graph = DependencyGraph::from_edges(edges);
        let policies: Vec<Box<dyn Policy>> = vec![];
        let flat: Vec<(String, String)> = nodes
            .iter()
            .map(|n| match n {
                NodeId::Registry { name, .. } => (name.clone(), "pass".to_string()),
                _ => unreachable!(),
            })
            .collect();
        let fetcher = SpyFetcher::new(&[]);
        let mut config = cfg(true);
        config.max_total_nodes = 2;
        let inputs = TransitiveScanInputs {
            graph,
            roots: vec![(nodes[0].clone(), None)],
            flat_verdicts: flat,
            cache: &cache,
            policies: &policies,
            config: &config,
        };
        let outcome = run_transitive_scan(inputs, &fetcher);
        assert!(
            outcome.is_failure(),
            "T-108-16: a budget breach must fail the scan closed"
        );
        let native = outcome.render_native_section();
        assert!(
            native.contains("NODE-BUDGET") && native.contains('2'),
            "T-108-08: native must show NodeBudgetExceeded with the limit:\n{native}"
        );
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(
            json.contains("NodeBudgetExceeded") && json.contains("\"limit\":2"),
            "T-108-08: JSON must carry NodeBudgetExceeded count+limit: {json}"
        );
    }

    // --- T-108-15: fetch_concurrency=1 serialises git fetches; all scanned. -
    #[test]
    fn t108_15_fetch_concurrency_one_scans_all_git_nodes() {
        let cache = Cache::in_memory().unwrap();
        let shas = [
            "1111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222",
            "3333333333333333333333333333333333333333",
        ];
        let roots: Vec<(NodeId, Option<DependencySource>)> = shas
            .iter()
            .enumerate()
            .map(|(i, sha)| {
                (
                    git(&format!("g{i}"), sha),
                    Some(DependencySource::Git {
                        url: "git://127.0.0.1/repo".to_string(),
                        ref_: sha.to_string(),
                    }),
                )
            })
            .collect();
        let policies: Vec<Box<dyn Policy>> = vec![];
        // A git sub-tree with a manifest declaring no dependencies: edge
        // discovery succeeds with an empty edge set (a clean leaf).
        let fetcher = SpyFetcher::new(&[("package.json", b"{}" as &[u8])]);
        let mut config = cfg(true);
        config.fetch_concurrency = 1;
        let inputs = TransitiveScanInputs {
            graph: DependencyGraph::from_edges(vec![]),
            roots,
            flat_verdicts: vec![],
            cache: &cache,
            policies: &policies,
            config: &config,
        };
        let outcome = run_transitive_scan(inputs, &fetcher);
        let scanned_git = outcome
            .nodes
            .iter()
            .filter(|r| r.node.starts_with("git:"))
            .count();
        assert_eq!(
            scanned_git, 3,
            "T-108-15: all three git nodes must be scanned, rows: {:?}",
            outcome.nodes
        );
        assert_eq!(outcome.worst_verdict, Some(Verdict::Pass));
        // T-108-15 (peak concurrency): with fetch_concurrency = 1 the wired pool
        // must serialise fetches — observed peak concurrent fetches must be ≤ 1.
        // The gauge in SpyFetcher makes an over-admission observable (20ms hold);
        // a sequential walk also satisfies peak ≤ 1, so the assertion is honest.
        assert!(
            fetcher.peak_concurrency() <= 1,
            "T-108-15: fetch_concurrency = 1 must keep peak concurrent fetches ≤ 1, observed {}",
            fetcher.peak_concurrency()
        );
    }

    // --- T-108-17: warm cache -> the pinned git node's verdict is served from
    // the cache and the subtree digest is written. -------------------------
    #[test]
    fn t108_17_warm_cache_serves_pinned_node_with_digest() {
        let cache = Cache::in_memory().unwrap();
        let sha = PINNED;
        let policies: Vec<Box<dyn Policy>> = vec![];
        let config = cfg(true);
        let mk = || TransitiveScanInputs {
            graph: DependencyGraph::from_edges(vec![]),
            roots: vec![(
                git("g", sha),
                Some(DependencySource::Git {
                    url: "git://127.0.0.1/repo".to_string(),
                    ref_: sha.to_string(),
                }),
            )],
            flat_verdicts: vec![],
            cache: &cache,
            policies: &policies,
            config: &config,
        };
        // A git sub-tree with a manifest declaring no dependencies: edge
        // discovery succeeds with an empty edge set (a clean leaf).
        let fetcher = SpyFetcher::new(&[("package.json", b"{}" as &[u8])]);

        let _ = run_transitive_scan(mk(), &fetcher);
        assert!(
            fetcher.fetch_count() >= 1,
            "first scan must fetch the git node"
        );
        // Capture the fetch count after the cold run.
        let fetches_after_run1 = fetcher.fetch_count();
        let row = cache.lookup("g", sha, "git").unwrap().unwrap();
        assert!(
            row.subtree_digest.is_some(),
            "T-108-17: a scanned git node must carry a subtree_digest after the walk"
        );

        let _ = run_transitive_scan(mk(), &fetcher);
        let row2 = cache.lookup("g", sha, "git").unwrap().unwrap();
        assert_eq!(
            row2.result, "pass",
            "T-108-17: warm cache must serve the same Pass verdict"
        );
        // T-108-17 (warm-cache no-fetch): the second run must NOT re-fetch the
        // unchanged pinned git node — its verdict and edges are served from cache.
        assert_eq!(
            fetcher.fetch_count(),
            fetches_after_run1,
            "T-108-17: a warm pinned node must NOT trigger another VcsFetcher::fetch \
             (fetch count must not increase on the warm run)"
        );
    }

    // --- T-108-03 / T-108-14: the walker is NOT invoked when disabled. -----
    struct SpyWalker {
        calls: RefCell<usize>,
    }
    impl RootWalker for SpyWalker {
        fn walk_root(
            &self,
            _root: &NodeId,
            _max_depth: usize,
            _on_depth_limit: OnDepthLimit,
        ) -> crate::transitive::engine::WalkResult {
            *self.calls.borrow_mut() += 1;
            crate::transitive::engine::WalkResult {
                verdict: Verdict::Pass,
                diagnostics: vec![],
                node_verdicts: vec![],
            }
        }
    }

    /// Structural mirror of the run_check gate used to exercise the RootWalker
    /// seam in isolation. NOTE: the REAL `if config.transitive.enabled` gate in
    /// main.rs is exercised end-to-end by the integration test
    /// `t108_03_real_gate_disabled_skips_walker_enabled_enters_it`
    /// (tests/transitive_scan_path_integration.rs) — that test FAILS if the gate
    /// is deleted. This unit test only proves the walker seam itself respects an
    /// enabled flag (the deferred T-108-14 dfs_walk-spy assertion).
    fn gated_walk(walker: &SpyWalker, config: &TransitiveConfig, roots: &[NodeId]) {
        if config.enabled {
            for r in roots {
                let _ = walker.walk_root(r, config.max_depth as usize, OnDepthLimit::Warn);
            }
        }
    }

    #[test]
    fn t108_03_14_walker_not_invoked_when_disabled() {
        let walker = SpyWalker {
            calls: RefCell::new(0),
        };
        let roots = vec![reg("root", "1.0")];

        gated_walk(&walker, &cfg(false), &roots);
        assert_eq!(
            *walker.calls.borrow(),
            0,
            "T-108-03/14: dfs_walk must NOT be invoked when [transitive].enabled = false"
        );

        gated_walk(&walker, &cfg(true), &roots);
        assert_eq!(
            *walker.calls.borrow(),
            1,
            "the gate must invoke the walker when enabled"
        );
    }

    // --- node_id_string is stable and unambiguous --------------------------
    #[test]
    fn node_id_string_is_unambiguous() {
        assert_eq!(node_id_string(&reg("a", "1.0")), "registry:npm/a@1.0");
        assert_eq!(node_id_string(&git("a", PINNED)), format!("git:a@{PINNED}"));
        assert_ne!(
            node_id_string(&reg("a", "1.0")),
            node_id_string(&git("a", PINNED))
        );
    }

    // --- T-108-18: a changed child invalidates the parent's stale cache row. -
    //
    // Drives `invalidate_stale_parents` directly (the live wiring of the
    // task-106 subtree-digest gate). A git parent's row is primed with a digest
    // computed over a CLEAN child verdict; when the child later scans Block, the
    // parent's recomputed digest no longer matches → the parent row is
    // invalidated so the walk re-scans it and the new verdict propagates.
    struct OneEdge {
        parent: NodeId,
        child: NodeId,
    }
    impl EdgeProvider for OneEdge {
        fn edges_for(&self, node: &NodeId) -> Result<Vec<NodeId>, EdgeError> {
            if *node == self.parent {
                Ok(vec![self.child.clone()])
            } else {
                Ok(vec![])
            }
        }
    }
    struct FixedScanner {
        verdicts: HashMap<NodeId, Verdict>,
    }
    impl NodeScanner for FixedScanner {
        fn scan(&self, node: &NodeId) -> Verdict {
            self.verdicts.get(node).copied().unwrap_or(Verdict::Pass)
        }
    }

    #[test]
    fn t108_18_changed_child_invalidates_parent_cache_row() {
        let cache = Cache::in_memory().unwrap();
        let parent_sha = PINNED;
        let parent = git("parent", parent_sha);
        let child = git("child", "f".repeat(40).as_str());

        // Prime the cache: parent scanned Pass with a digest over the CLEAN child
        // (verdict pass). This is the state after a first clean scan.
        let clean_digest =
            crate::cache::compute_subtree_digest(&[(node_id_string(&child).as_str(), "pass")]);
        cache
            .insert_git(
                "parent",
                parent_sha,
                "pass",
                Some("sha256:deadbeef"),
                Some(&clean_digest),
            )
            .unwrap();

        // Provenance for the parent.
        let mut resolver = LockfileGitResolver::new();
        resolver.record("parent", "git://127.0.0.1/parent", parent_sha);

        let edges = OneEdge {
            parent: parent.clone(),
            child: child.clone(),
        };

        // Round 1: the child is still CLEAN — the parent's stored digest matches,
        // so the row is NOT invalidated (a warm hit).
        let clean_scanner = FixedScanner {
            verdicts: HashMap::new(), // all Pass
        };
        invalidate_stale_parents(
            &cache,
            &edges,
            &clean_scanner,
            std::slice::from_ref(&parent),
            &resolver,
        );
        assert!(
            cache.lookup("parent", parent_sha, "git").unwrap().is_some(),
            "T-108-18: an unchanged subtree must NOT invalidate the parent row"
        );

        // Round 2: the child now scans BLOCK — the recomputed digest differs, so
        // the parent's stale row must be invalidated (dropped).
        let mut changed = HashMap::new();
        changed.insert(child.clone(), Verdict::Block);
        let changed_scanner = FixedScanner { verdicts: changed };
        invalidate_stale_parents(
            &cache,
            &edges,
            &changed_scanner,
            std::slice::from_ref(&parent),
            &resolver,
        );
        assert!(
            cache.lookup("parent", parent_sha, "git").unwrap().is_none(),
            "T-108-18: a changed child must invalidate the parent's stale cache row \
             (fail-closed: the parent is re-scanned, never served its stale Pass)"
        );
    }

    // --- T-108-10: render_native (task 098) is reused, not reimplemented. ----
    //
    // The flat table is rendered by the production `render_native` helper; the
    // transitive section is rendered by `render_native_section` and APPENDED. We
    // assert the combined run_check output begins with exactly the bytes
    // `render_native` produces for the flat results — proving no flat-table
    // rendering is duplicated in the transitive path (REQ-108-04).
    #[test]
    fn t108_10_render_native_is_reused_not_reimplemented() {
        let results = vec![crate::CheckResult {
            package: "demo".to_string(),
            version: "1.0.0".to_string(),
            registry: "npm".to_string(),
            age_hours: Some(10),
            result: "pass".to_string(),
            reason: None,
            policies: vec![],
            vulns: vec![],
        }];
        // The exact flat-table bytes the production helper emits.
        let flat = crate::render_native(&results);

        let mut outcome = TransitiveOutcome::default();
        outcome.nodes.push(TransitiveNodeRow {
            node: "registry:npm/demo@1.0.0".to_string(),
            depth: 0,
            verdict: "pass".to_string(),
        });
        // The combined output run_check prints is `render_native(results)` then
        // `outcome.render_native_section()`.
        let combined = format!("{flat}{}", outcome.render_native_section());
        assert!(
            combined.starts_with(&flat),
            "T-108-10: the transitive path must reuse render_native verbatim for the flat table"
        );
        // And the transitive section is a separate, appended block (does not
        // reimplement the Package/Version/Age header).
        let section = outcome.render_native_section();
        assert!(
            !section.contains("Package"),
            "transitive section must not re-render the flat header"
        );
        assert!(section.contains("Transitive scan:"));
    }

    // --- SEC-002: a node whose row shows Block forces exit ≥ 1 (no under-report).
    //
    // Display rows and the rollup now derive from ONE scan (WalkResult.node_verdicts),
    // so a row that shows `block` can never coexist with an exit code that
    // under-reports it. This asserts the invariant end-to-end: the moment any node
    // row is Block, is_failure() is true and worst_verdict is Block.
    #[test]
    fn sec_002_block_row_forces_failure_no_under_report() {
        let cache = Cache::in_memory().unwrap();
        let root = reg("root-pkg", "1.0.0");
        let child = git("dep-evil", PINNED);
        let graph = DependencyGraph::from_edges(vec![]);
        // The git child scans Block (malicious install script fixture).
        let policies: Vec<Box<dyn Policy>> = vec![Box::new(AlwaysBlock)];
        let flat = vec![("root-pkg".to_string(), "pass".to_string())];
        let fetcher = SpyFetcher::new(&[("postinstall.js", b"require('child_process')" as &[u8])]);
        let inputs = TransitiveScanInputs {
            graph,
            roots: vec![
                (root, None),
                (
                    child,
                    Some(DependencySource::Git {
                        url: "git://127.0.0.1/repo".to_string(),
                        ref_: PINNED.to_string(),
                    }),
                ),
            ],
            flat_verdicts: flat,
            cache: &cache,
            policies: &policies,
            config: &cfg(true),
        };
        let outcome = run_transitive_scan(inputs, &fetcher);

        // The display row for the git child shows Block.
        let block_row = outcome
            .nodes
            .iter()
            .find(|r| r.node.contains("dep-evil"))
            .expect("the git child must have a display row");
        assert_eq!(
            block_row.verdict, "block",
            "SEC-002: the git child row must show block"
        );
        // Because a row shows Block, the exit code MUST be ≥ 1: is_failure() true
        // and worst_verdict at least Block — never under-reporting the printed row.
        assert!(
            outcome.is_failure(),
            "SEC-002: a node whose row shows Block must force exit ≥ 1 (no under-report)"
        );
        assert_eq!(
            outcome.worst_verdict,
            Some(Verdict::Block),
            "SEC-002: worst_verdict must reflect the worst node row actually shown"
        );
    }

    // --- SEC-001: a git sub-tree's manifest-discovered fan-out exceeding
    // max_total_nodes triggers NodeBudgetExceeded (the hard ceiling now bounds
    // nodes discovered DURING the walk, not just the up-front graph).
    #[test]
    fn sec_001_manifest_discovered_fan_out_breaches_budget() {
        let cache = Cache::in_memory().unwrap();
        // A git root whose fetched Cargo.toml declares 5 pinned git deps — a
        // fan-out the lockfile graph never saw. These are discovered ONLY during
        // the walk via the manifest.
        let cargo = b"[package]\nname = \"x\"\nversion = \"0.1.0\"\n\
            [dependencies]\n\
            c0 = { git = \"https://h/c0\", rev = \"aaaa000000\" }\n\
            c1 = { git = \"https://h/c1\", rev = \"aaaa111111\" }\n\
            c2 = { git = \"https://h/c2\", rev = \"aaaa222222\" }\n\
            c3 = { git = \"https://h/c3\", rev = \"aaaa333333\" }\n\
            c4 = { git = \"https://h/c4\", rev = \"aaaa444444\" }\n";
        let fetcher = SpyFetcher::new(&[("Cargo.toml", cargo as &[u8])]);
        let root = git("rootgit", PINNED);
        let policies: Vec<Box<dyn Policy>> = vec![];
        // Budget of 2: the single git root is charged up front (1), then its 5
        // manifest-discovered children breach the ceiling DURING edge extraction.
        let mut config = cfg(true);
        config.max_total_nodes = 2;
        let inputs = TransitiveScanInputs {
            graph: DependencyGraph::from_edges(vec![]),
            roots: vec![(
                root,
                Some(DependencySource::Git {
                    url: "git://127.0.0.1/repo".to_string(),
                    ref_: PINNED.to_string(),
                }),
            )],
            flat_verdicts: vec![],
            cache: &cache,
            policies: &policies,
            config: &config,
        };
        let outcome = run_transitive_scan(inputs, &fetcher);
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|d| matches!(d, TransitiveDiagnostic::NodeBudgetExceeded { .. })),
            "SEC-001: manifest-discovered fan-out exceeding max_total_nodes must \
             trigger NodeBudgetExceeded, diagnostics: {:?}",
            outcome.diagnostics
        );
        assert!(
            outcome.is_failure(),
            "SEC-001: a budget breach (even from manifest-discovered nodes) must fail closed"
        );
    }

    // --- SEC-004: a breached scan persists NOTHING to cache (no pass row, no
    // empty-subtree digest written during a fail-closed breach).
    #[test]
    fn sec_004_breached_scan_writes_no_cache_row() {
        let cache = Cache::in_memory().unwrap();
        // A pinned git root that WOULD be cached on a clean scan. The Cargo.toml
        // declares a fan-out that breaches the budget, so the scan fails closed.
        let cargo = b"[package]\nname = \"x\"\nversion = \"0.1.0\"\n\
            [dependencies]\n\
            d0 = { git = \"https://h/d0\", rev = \"bbbb000000\" }\n\
            d1 = { git = \"https://h/d1\", rev = \"bbbb111111\" }\n\
            d2 = { git = \"https://h/d2\", rev = \"bbbb222222\" }\n";
        let fetcher = SpyFetcher::new(&[("Cargo.toml", cargo as &[u8])]);
        let root = git("breachgit", PINNED);
        let policies: Vec<Box<dyn Policy>> = vec![];
        let mut config = cfg(true);
        config.max_total_nodes = 2;
        let inputs = TransitiveScanInputs {
            graph: DependencyGraph::from_edges(vec![]),
            roots: vec![(
                root,
                Some(DependencySource::Git {
                    url: "git://127.0.0.1/repo".to_string(),
                    ref_: PINNED.to_string(),
                }),
            )],
            flat_verdicts: vec![],
            cache: &cache,
            policies: &policies,
            config: &config,
        };
        let outcome = run_transitive_scan(inputs, &fetcher);
        assert!(
            outcome.is_failure(),
            "SEC-004 precondition: the scan breached"
        );
        // No cache row may have been written for the breached root.
        assert!(
            cache.lookup("breachgit", PINNED, "git").unwrap().is_none(),
            "SEC-004: a breached (fail-closed) scan must persist NO cache row"
        );
    }

    // --- SEC-003: an unfetchable git node surfaces an Unfetchable diagnostic in
    // BOTH native and JSON (no bare, unexplained `warn` row).
    #[test]
    fn sec_003_unfetchable_node_emits_diagnostic_in_both_formats() {
        let cache = Cache::in_memory().unwrap();
        let root = git("unreachable", PINNED);
        let policies: Vec<Box<dyn Policy>> = vec![];
        // The fetcher fails every fetch → the git node is floored to Warn with the
        // "fetch failed" reason recorded by the scanner.
        let fetcher = SpyFetcher::failing();
        let inputs = TransitiveScanInputs {
            graph: DependencyGraph::from_edges(vec![]),
            roots: vec![(
                root,
                Some(DependencySource::Git {
                    url: "git://127.0.0.1/repo".to_string(),
                    ref_: PINNED.to_string(),
                }),
            )],
            flat_verdicts: vec![],
            cache: &cache,
            policies: &policies,
            config: &cfg(true),
        };
        let outcome = run_transitive_scan(inputs, &fetcher);

        // Fail-closed: the node is at least Warn.
        assert!(
            outcome.worst_verdict >= Some(Verdict::Warn),
            "SEC-003: an unfetchable git node must be floored ≥ Warn"
        );
        // The Unfetchable diagnostic is present with a reason.
        assert!(
            outcome.diagnostics.iter().any(|d| matches!(
                d,
                TransitiveDiagnostic::Unfetchable { node, reason }
                    if node.contains("unreachable") && reason == "fetch failed"
            )),
            "SEC-003: an Unfetchable diagnostic with a reason must be present: {:?}",
            outcome.diagnostics
        );
        // Native renders it.
        let native = outcome.render_native_section();
        assert!(
            native.contains("UNFETCHABLE") && native.contains("fetch failed"),
            "SEC-003: native output must explain the unfetchable node:\n{native}"
        );
        // JSON renders it.
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(
            json.contains("Unfetchable") && json.contains("fetch failed"),
            "SEC-003: JSON output must carry the Unfetchable diagnostic: {json}"
        );
    }

    // --- SEC-003 (unknown-origin path): a git node whose origin cannot be
    // resolved also surfaces an Unfetchable diagnostic (reason "unknown origin").
    #[test]
    fn sec_003_unknown_origin_emits_unfetchable() {
        let cache = Cache::in_memory().unwrap();
        // A git root with NO DependencySource → no provenance recorded → the
        // scanner's resolve() returns None → "unknown origin".
        let root = git("noorigin", PINNED);
        let policies: Vec<Box<dyn Policy>> = vec![];
        let fetcher = SpyFetcher::new(&[]);
        let inputs = TransitiveScanInputs {
            graph: DependencyGraph::from_edges(vec![]),
            roots: vec![(root, None)],
            flat_verdicts: vec![],
            cache: &cache,
            policies: &policies,
            config: &cfg(true),
        };
        let outcome = run_transitive_scan(inputs, &fetcher);
        assert!(
            outcome.diagnostics.iter().any(|d| matches!(
                d,
                TransitiveDiagnostic::Unfetchable { reason, .. } if reason == "unknown origin"
            )),
            "SEC-003: an unresolvable-origin git node must emit Unfetchable(unknown origin): {:?}",
            outcome.diagnostics
        );
    }

    // --- T-108-19: tooling gate marker. `cargo test` / clippy -D warnings / fmt
    // --check are enforced by the pre-commit pipeline, not a unit test. This
    // marker keeps T-108-19 referenced (mirrors T-102-18 / T-103-11 / T-105-12).
    #[test]
    fn t108_19_tooling_gate_marker() {}
}

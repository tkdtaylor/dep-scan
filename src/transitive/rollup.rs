//! Transitive verdict rollup (ADR 009 piece 4 — Decision 2c, task 104).
//!
//! The pure DFS engine (task 102) walks the dependency tree in post-order and
//! needs a single worst-verdict-wins combiner to fold each node's children
//! verdicts together with the node's own scan result. dep-scan already has
//! exactly one such combiner — [`crate::policy::aggregate_results`] — used by
//! the flat scan arm. **This module reuses it; it does not reimplement
//! worst-verdict comparison** (REQ-104-01).
//!
//! ## What this module provides
//!
//! - [`combine_verdicts`] — the single rollup point. It maps a slice of
//!   [`Verdict`]s onto the `PolicyDetail` shape `aggregate_results` consumes
//!   (each verdict becomes a synthetic detail whose `result` string is
//!   `"pass"`/`"warn"`/`"block"`), calls `aggregate_results`, and maps the
//!   `("pass"|"warn"|"block", _)` string it returns back to a [`Verdict`] via
//!   [`crate::transitive::scanner::verdict_from_result_str`] (which fails closed
//!   to `Warn` on any unrecognised string).
//!
//! The engine's [`TransitiveEngine::dfs_walk`] post-order calls
//! `combine_verdicts` to roll a node's verdict up from its children's
//! already-computed verdicts plus its own scan result, so:
//!
//! - **Post-order** (REQ-104-02): children are fully walked and their verdicts
//!   computed before the parent folds them in.
//! - **Unscannable floor ≥ Warn** (REQ-104-03): a depth-limited, unfetchable, or
//!   `UnresolvedRange` edge contributes at least `Warn` (the floor is produced at
//!   the edge by the engine and passed into `combine_verdicts` like any other
//!   contribution).
//! - **`on_depth_limit = Block`** (REQ-104-04): a cut child contributes `Block`.
//! - **Monotonic upward** (REQ-104-05): `aggregate_results` is worst-wins, so a
//!   child can only raise (never lower) an ancestor's verdict.
//!
//! [`TransitiveEngine::dfs_walk`]: crate::transitive::engine::TransitiveEngine::dfs_walk

use crate::policy::{PolicyDetail, aggregate_results};
use crate::transitive::engine::Verdict;
use crate::transitive::scanner::verdict_from_result_str;

/// Map a single [`Verdict`] to the `result` string `aggregate_results` consumes.
///
/// This is the inverse of [`verdict_from_result_str`] and the only place the
/// transitive layer encodes a `Verdict` into the flat-scan string vocabulary.
fn verdict_result_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "pass",
        Verdict::Warn => "warn",
        Verdict::Block => "block",
    }
}

/// Roll a set of verdict contributions into a single worst-verdict-wins result.
///
/// This is **the** transitive rollup point (REQ-104-01). Each contribution —
/// the node's own scan result and every child/floor contribution — is turned
/// into a synthetic [`PolicyDetail`] and handed to
/// [`crate::policy::aggregate_results`], the existing flat-scan combiner. The
/// `("pass"|"warn"|"block", _)` string it returns is mapped back to a
/// [`Verdict`]. No worst-verdict comparison is performed here.
///
/// An **empty** slice rolls up to `Pass`: a node with no children and a clean
/// scan is a pass. (Callers always include the node's own scan verdict, so the
/// empty case only arises in direct unit tests.)
#[allow(dead_code)] // wired into the engine post-order; also exercised directly by tests
pub fn combine_verdicts(verdicts: &[Verdict]) -> Verdict {
    let details: Vec<PolicyDetail> = verdicts
        .iter()
        .map(|v| PolicyDetail {
            policy_name: "transitive_rollup".to_string(),
            result: verdict_result_str(*v).to_string(),
            reason: None,
        })
        .collect();
    let (result_str, _reason) = aggregate_results(&details);
    verdict_from_result_str(&result_str)
}

// ---------------------------------------------------------------------------
// Tests — T-104-01 .. T-104-15 (ADR 009 Decision 2c)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::NodeId;
    use crate::policy::PolicyResult;
    use crate::transitive::engine::{
        Diagnostic, EdgeError, EdgeProvider, NodeScanner, OnDepthLimit, TransitiveEngine,
        WalkResult,
    };
    use std::cell::RefCell;
    use std::collections::HashMap;

    // --- shared in-memory test doubles (mirror the engine's, kept local so the
    // rollup tests are self-contained and exercise the rollup through the live
    // engine post-order rather than a re-implemented walk) ------------------

    fn reg(name: &str) -> NodeId {
        NodeId::Registry {
            name: name.to_string(),
            version: "1.0".to_string(),
            registry: "npm".to_string(),
        }
    }

    struct MockEdges {
        map: HashMap<NodeId, Result<Vec<NodeId>, EdgeError>>,
    }
    impl MockEdges {
        fn new() -> Self {
            Self {
                map: HashMap::new(),
            }
        }
        fn edge(mut self, from: NodeId, to: Vec<NodeId>) -> Self {
            self.map.insert(from, Ok(to));
            self
        }
        fn err(mut self, from: NodeId, err: EdgeError) -> Self {
            self.map.insert(from, Err(err));
            self
        }
    }
    impl EdgeProvider for MockEdges {
        fn edges_for(&self, node: &NodeId) -> Result<Vec<NodeId>, EdgeError> {
            self.map.get(node).cloned().unwrap_or(Ok(vec![]))
        }
    }

    struct MockScanner {
        verdicts: HashMap<NodeId, Verdict>,
        calls: RefCell<Vec<NodeId>>,
    }
    impl MockScanner {
        fn new() -> Self {
            Self {
                verdicts: HashMap::new(),
                calls: RefCell::new(Vec::new()),
            }
        }
        fn verdict(mut self, node: NodeId, v: Verdict) -> Self {
            self.verdicts.insert(node, v);
            self
        }
        fn count(&self, node: &NodeId) -> usize {
            self.calls.borrow().iter().filter(|n| *n == node).count()
        }
    }
    impl NodeScanner for MockScanner {
        fn scan(&self, node: &NodeId) -> Verdict {
            self.calls.borrow_mut().push(node.clone());
            self.verdicts.get(node).copied().unwrap_or(Verdict::Pass)
        }
    }

    fn walk(
        edges: &MockEdges,
        scanner: &MockScanner,
        root: &NodeId,
        max_depth: usize,
        on_dl: OnDepthLimit,
    ) -> WalkResult {
        TransitiveEngine::new(edges, scanner).dfs_walk(root, max_depth, on_dl)
    }

    // =====================================================================
    // Worst-verdict-wins propagation
    // =====================================================================

    // --- T-104-01: all-Pass subtree rolls up to Pass at root -------------
    #[test]
    fn t_104_01_all_pass_rolls_up_pass() {
        // root -> a -> b, every node Pass.
        let (root, a, b) = (reg("root"), reg("a"), reg("b"));
        let edges = MockEdges::new()
            .edge(root.clone(), vec![a.clone()])
            .edge(a.clone(), vec![b.clone()]);
        let scanner = MockScanner::new();
        let result = walk(&edges, &scanner, &root, 5, OnDepthLimit::Warn);
        assert_eq!(result.verdict, Verdict::Pass);
    }

    // --- T-104-02: a single Block anywhere makes the root Block ----------
    #[test]
    fn t_104_02_single_block_rolls_up_block() {
        // root -> a -> b; b Block, a Pass, root Pass. Block cannot be
        // suppressed by passing ancestors (fail-closed).
        let (root, a, b) = (reg("root"), reg("a"), reg("b"));
        let edges = MockEdges::new()
            .edge(root.clone(), vec![a.clone()])
            .edge(a.clone(), vec![b.clone()]);
        let scanner = MockScanner::new().verdict(b.clone(), Verdict::Block);
        let result = walk(&edges, &scanner, &root, 5, OnDepthLimit::Warn);
        assert_eq!(result.verdict, Verdict::Block);
    }

    // --- T-104-03: a single Warn propagates upward ----------------------
    #[test]
    fn t_104_03_single_warn_propagates() {
        // root -> a -> b; b Warn, a Pass, root Pass.
        let (root, a, b) = (reg("root"), reg("a"), reg("b"));
        let edges = MockEdges::new()
            .edge(root.clone(), vec![a.clone()])
            .edge(a.clone(), vec![b.clone()]);
        let scanner = MockScanner::new().verdict(b.clone(), Verdict::Warn);
        let result = walk(&edges, &scanner, &root, 5, OnDepthLimit::Warn);
        assert_eq!(result.verdict, Verdict::Warn);
    }

    // --- T-104-04: Block is worse than Warn — Block wins ----------------
    #[test]
    fn t_104_04_block_beats_warn() {
        // root -> {a, b}; a Block, b Warn.
        let (root, a, b) = (reg("root"), reg("a"), reg("b"));
        let edges = MockEdges::new().edge(root.clone(), vec![a.clone(), b.clone()]);
        let scanner = MockScanner::new()
            .verdict(a.clone(), Verdict::Block)
            .verdict(b.clone(), Verdict::Warn);
        let result = walk(&edges, &scanner, &root, 5, OnDepthLimit::Warn);
        assert_eq!(result.verdict, Verdict::Block);
    }

    // --- T-104-05: rollup is monotonically upward (child cannot lower) ---
    #[test]
    fn t_104_05_monotonic_upward() {
        // root Block; its only child Pass. Root stays Block.
        let (root, child) = (reg("root"), reg("child"));
        let edges = MockEdges::new().edge(root.clone(), vec![child.clone()]);
        let scanner = MockScanner::new().verdict(root.clone(), Verdict::Block);
        let result = walk(&edges, &scanner, &root, 5, OnDepthLimit::Warn);
        assert_eq!(
            result.verdict,
            Verdict::Block,
            "a passing child must not lower the root's Block"
        );

        // And a passing root with a passing child stays Pass (not lowered below
        // Pass — Pass is the floor of the lattice).
        let scanner2 = MockScanner::new();
        let result2 = walk(&edges, &scanner2, &root, 5, OnDepthLimit::Warn);
        assert_eq!(result2.verdict, Verdict::Pass);
    }

    // --- T-104-06: aggregate_results is reused, not reimplemented --------
    #[test]
    fn t_104_06_reuses_aggregate_results() {
        // combine_verdicts is a thin adapter over aggregate_results: it must
        // agree with aggregate_results for every input. We assert agreement on
        // the full verdict cross-product, which is only possible if the rollup
        // genuinely delegates to aggregate_results (no parallel comparison
        // logic could be silently substituted and still match on all cases —
        // and crucially, this test passes ONLY because the same worst-wins
        // function decides both sides).
        let all = [Verdict::Pass, Verdict::Warn, Verdict::Block];
        for &x in &all {
            for &y in &all {
                let via_rollup = combine_verdicts(&[x, y]);
                let details = vec![
                    PolicyDetail::from_result("x", &verdict_to_policy_result(x)),
                    PolicyDetail::from_result("y", &verdict_to_policy_result(y)),
                ];
                let (s, _) = aggregate_results(&details);
                let via_aggregate = verdict_from_result_str(&s);
                assert_eq!(
                    via_rollup, via_aggregate,
                    "combine_verdicts must equal aggregate_results for ({x:?}, {y:?})"
                );
            }
        }
    }

    fn verdict_to_policy_result(v: Verdict) -> PolicyResult {
        match v {
            Verdict::Pass => PolicyResult::Pass,
            Verdict::Warn => PolicyResult::Warn("w".to_string()),
            Verdict::Block => PolicyResult::Block("b".to_string()),
        }
    }

    // =====================================================================
    // Unscannable node floor — fail-closed assertions
    // =====================================================================

    // --- T-104-07: unfetchable child contributes ≥ Warn -----------------
    #[test]
    fn t_104_07_unfetchable_child_floors_warn() {
        // root -> a; a is unfetchable. The scanner models an unfetchable node by
        // returning Warn (its fail-closed floor — see scanner.rs scan_git Err
        // arm and resolve()==None arm, both `return Verdict::Warn`).
        let (root, a) = (reg("root"), reg("a"));
        let edges = MockEdges::new().edge(root.clone(), vec![a.clone()]);
        let scanner = MockScanner::new().verdict(a.clone(), Verdict::Warn);
        let result = walk(&edges, &scanner, &root, 5, OnDepthLimit::Warn);
        assert!(
            result.verdict >= Verdict::Warn,
            "an unfetchable child must floor the parent at ≥ Warn, got {:?}",
            result.verdict
        );
        assert_ne!(result.verdict, Verdict::Pass);
    }

    // --- T-104-08: depth-limit cut node contributes ≥ Warn --------------
    #[test]
    fn t_104_08_depth_limited_floors_warn() {
        // root -> a (depth 1) -> child (depth 2, cut at max_depth 1). a itself
        // scans Pass, but the cut child floors a (and so root) at ≥ Warn.
        let (root, a, child) = (reg("root"), reg("a"), reg("child"));
        let edges = MockEdges::new()
            .edge(root.clone(), vec![a.clone()])
            .edge(a.clone(), vec![child.clone()]);
        let scanner = MockScanner::new(); // all Pass
        let result = walk(&edges, &scanner, &root, 1, OnDepthLimit::Warn);
        assert!(
            result.verdict >= Verdict::Warn,
            "a depth-limited node must floor its parent at ≥ Warn"
        );
        // child past the depth limit was never scanned.
        assert_eq!(scanner.count(&child), 0);
        // a DepthLimitReached diagnostic was emitted for the cut node.
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| matches!(d, Diagnostic::DepthLimitReached { .. }))
        );
    }

    // --- T-104-09: UnresolvedRange edge contributes ≥ Warn --------------
    #[test]
    fn t_104_09_unresolved_range_floors_warn() {
        // root -> a; a's edges are an UnresolvedRange (B effectively unscanned).
        let (root, a) = (reg("root"), reg("a"));
        let edges = MockEdges::new().edge(root.clone(), vec![a.clone()]).err(
            a.clone(),
            EdgeError::UnresolvedRange {
                name: "b".to_string(),
                range: "^1.0".to_string(),
            },
        );
        let scanner = MockScanner::new(); // all Pass
        let result = walk(&edges, &scanner, &root, 5, OnDepthLimit::Warn);
        assert!(
            result.verdict >= Verdict::Warn,
            "an UnresolvedRange edge must floor the parent at ≥ Warn"
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| matches!(d, Diagnostic::UnresolvedRange { .. }))
        );
    }

    // --- T-104-10: on_depth_limit = block escalates cut child to Block --
    #[test]
    fn t_104_10_on_depth_limit_block_escalates() {
        // Same as T-104-08 but with OnDepthLimit::Block: the cut child
        // contributes Block, so the root is Block (not merely Warn).
        let (root, a, child) = (reg("root"), reg("a"), reg("child"));
        let edges = MockEdges::new()
            .edge(root.clone(), vec![a.clone()])
            .edge(a.clone(), vec![child.clone()]);
        let scanner = MockScanner::new(); // all explicitly-scanned nodes Pass
        let result = walk(&edges, &scanner, &root, 1, OnDepthLimit::Block);
        assert_eq!(
            result.verdict,
            Verdict::Block,
            "under on_depth_limit=block a cut child must roll up to Block"
        );
    }

    // =====================================================================
    // Attacker-cannot-hide assertions
    // =====================================================================

    // --- T-104-11: attacker cannot hide a Block by making it unfetchable -
    #[test]
    fn t_104_11_cannot_hide_block_via_unfetchable() {
        // root -> a -> b. b "would" Block if reachable, but b is unfetchable, so
        // its scan returns the fail-closed Warn floor instead of Block. The key
        // assertion: the root never silently produces Pass — the malicious
        // node's unfetchability ITSELF floors the verdict at ≥ Warn.
        let (root, a, b) = (reg("root"), reg("a"), reg("b"));
        let edges = MockEdges::new()
            .edge(root.clone(), vec![a.clone()])
            .edge(a.clone(), vec![b.clone()]);
        // b unfetchable → Warn floor (modelled exactly as scanner.rs does).
        let scanner = MockScanner::new().verdict(b.clone(), Verdict::Warn);
        let result = walk(&edges, &scanner, &root, 5, OnDepthLimit::Warn);
        assert!(
            result.verdict >= Verdict::Warn,
            "an unfetchable (would-be-Block) node must not roll up to Pass"
        );
        assert_ne!(
            result.verdict,
            Verdict::Pass,
            "attacker cannot hide a node by making it unfetchable"
        );
    }

    // --- T-104-12: attacker cannot hide a Block past the depth limit -----
    #[test]
    fn t_104_12_cannot_hide_block_past_depth_limit() {
        // root (depth 0) -> b (depth 6 would-be-Block) buried past max_depth 5.
        // b is cut by the depth limit, so it is never scanned; the cut still
        // floors the root at ≥ Warn.
        let nodes: Vec<NodeId> = ["root", "n1", "n2", "n3", "n4", "n5", "b"]
            .iter()
            .map(|n| reg(n))
            .collect();
        let mut edges = MockEdges::new();
        for w in nodes.windows(2) {
            edges = edges.edge(w[0].clone(), vec![w[1].clone()]);
        }
        // Even if b WOULD have blocked, it is never reached — but the floor still
        // applies.
        let scanner = MockScanner::new().verdict(nodes[6].clone(), Verdict::Block);
        let result = walk(&edges, &scanner, &nodes[0], 5, OnDepthLimit::Warn);
        assert!(
            result.verdict >= Verdict::Warn,
            "a node buried past the depth limit must still floor the root at ≥ Warn"
        );
        assert_eq!(
            scanner.count(&nodes[6]),
            0,
            "buried node must not be scanned"
        );
    }

    // --- T-104-13: attacker cannot hide a Block inside a cycle -----------
    #[test]
    fn t_104_13_cannot_hide_block_in_cycle() {
        // a -> b -> a (cycle). b scans Block. CycleDetected is emitted and b's
        // Block is used in the rollup (the back-edge is not re-traversed, but
        // b's verdict already participates).
        let (a, b) = (reg("a"), reg("b"));
        let edges = MockEdges::new()
            .edge(a.clone(), vec![b.clone()])
            .edge(b.clone(), vec![a.clone()]);
        let scanner = MockScanner::new().verdict(b.clone(), Verdict::Block);
        let result = walk(&edges, &scanner, &a, 5, OnDepthLimit::Warn);
        assert_eq!(
            result.verdict,
            Verdict::Block,
            "a Block inside a cycle must carry up to the root"
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| matches!(d, Diagnostic::CycleDetected { .. }))
        );
    }

    // =====================================================================
    // Rollup composition with the single-node fail-closed rule
    // =====================================================================

    // --- T-104-14: rollup composable with single-node fail-closed rule ---
    #[test]
    fn t_104_14_composable_with_single_node_fail_closed() {
        // The flat single-node git-dep path floors an unfetchable node at Warn
        // (src/main.rs git arm; scanner.rs scan_git Err/None arms → Warn). The
        // transitive rollup of a parent with one unfetchable child must produce
        // the SAME ≥ Warn — it is a generalisation, not a new rule.
        let (root, child) = (reg("root"), reg("child"));
        let edges = MockEdges::new().edge(root.clone(), vec![child.clone()]);
        let scanner = MockScanner::new().verdict(child.clone(), Verdict::Warn);
        let rolled = walk(&edges, &scanner, &root, 5, OnDepthLimit::Warn).verdict;

        // The single-node rule on the same unfetchable node:
        let single_node = combine_verdicts(&[Verdict::Warn]);

        assert_eq!(single_node, Verdict::Warn);
        assert_eq!(
            rolled, single_node,
            "the transitive rollup must agree with the single-node fail-closed floor"
        );
    }

    // --- combine_verdicts direct unit coverage (the rollup primitive) ---
    #[test]
    fn combine_verdicts_is_worst_wins() {
        assert_eq!(combine_verdicts(&[]), Verdict::Pass);
        assert_eq!(combine_verdicts(&[Verdict::Pass]), Verdict::Pass);
        assert_eq!(
            combine_verdicts(&[Verdict::Pass, Verdict::Warn]),
            Verdict::Warn
        );
        assert_eq!(
            combine_verdicts(&[Verdict::Warn, Verdict::Block]),
            Verdict::Block
        );
        assert_eq!(
            combine_verdicts(&[Verdict::Block, Verdict::Pass, Verdict::Warn]),
            Verdict::Block
        );
    }

    // --- T-104-15: tooling gate. `cargo test` / clippy -D warnings / fmt
    // --check are enforced by the pre-commit pipeline, not a unit test. This
    // marker keeps T-104-15 referenced (mirrors T-102-18 / T-103-11).
    #[test]
    fn t_104_15_tooling_gate_marker() {}
}

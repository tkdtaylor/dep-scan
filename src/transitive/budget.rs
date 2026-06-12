//! Per-scan node budget — the `max_total_nodes` safety ceiling (ADR 009
//! Decision 3b mitigation 5, task 105 REQ-105-03/04/05/07).
//!
//! This is a **second line of defence** behind the depth limit (task 102) and
//! the visited-set dedup. Even if both are somehow defeated, the node budget
//! caps total work at a hard upper bound: once the number of **distinct** nodes
//! enqueued for scanning exceeds `max_total_nodes`, the scan **fails closed**
//! with a [`NodeBudgetExceeded`] diagnostic.
//!
//! ## Fail-closed posture (REQ-105-03 — non-negotiable)
//!
//! Silent truncation to `Pass` is **prohibited**: if the budget allowed the
//! first `max_total_nodes` nodes to pass and quietly dropped the rest, an
//! attacker could bury a malicious node past the ceiling and have the scan
//! report `Pass`. Instead, exceeding the budget is itself a fail-closed signal —
//! the caller turns [`BudgetCharge::Exceeded`] into a verdict floored at
//! **≥ `Warn`** (never `Pass`) and surfaces the diagnostic.
//!
//! ## Dedup (REQ-105-05)
//!
//! The budget is charged **at most once per distinct [`NodeId`]**. The counter
//! holds its own visited set keyed on the full `NodeId` (same identity the
//! task-102 engine uses), so a diamond dependency reachable from two paths is
//! counted exactly once. A node already charged is a no-op re-charge.
//!
//! ## `max_total_nodes = 0` (T-105-07)
//!
//! Task 107 rejects `0` at config-validation time, but the budget treats `0`
//! **defensively**: any non-empty graph — i.e. the very first charge — exceeds a
//! limit of `0` and fails immediately. The budget never trusts that the config
//! layer screened the value.
//!
//! The public surface is exercised by this module's tests and wired into the
//! live walk by task 108; the module-level allow mirrors the `transitive`
//! convention (see `engine.rs` / `scanner.rs`).
#![allow(dead_code)] // wired into the live walk by task 108

use std::collections::HashSet;

use crate::lockfile::NodeId;
use crate::transitive::engine::Verdict;

/// The outcome of charging one node against the budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetCharge {
    /// The node was counted (or was already counted — an idempotent re-charge of
    /// an already-visited `NodeId`). The walk may proceed.
    Counted,
    /// Charging this node pushed the distinct-node count past `max_total_nodes`.
    /// The scan must fail closed: the caller floors the verdict at ≥ `Warn` and
    /// surfaces the carried diagnostic. Carries the node count *after* this node
    /// and the configured limit, for the diagnostic message (REQ-105-04).
    Exceeded(NodeBudgetExceeded),
}

/// The `NodeBudgetExceeded` diagnostic (REQ-105-04).
///
/// Carries both the node count that tripped the ceiling **and** the configured
/// limit, so the message rendered by task 108 (and the JSON/native formats)
/// includes both numbers. The diagnostic value is produced here; output
/// rendering is task 108's concern, but the value must carry count + limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeBudgetExceeded {
    /// The distinct-node count at the moment the budget was exceeded (always
    /// `limit + 1` for the first node over the ceiling).
    pub count: u32,
    /// The configured `max_total_nodes` ceiling that was exceeded.
    pub limit: u32,
}

impl NodeBudgetExceeded {
    /// A human-readable message carrying both the node count and the limit.
    ///
    /// Used by both output formats (task 108 renders this string into the
    /// `--format json` and `--format native` outputs — REQ-105-04). Kept here so
    /// the count+limit invariant lives next to the data.
    pub fn message(&self) -> String {
        format!(
            "node budget exceeded: scan reached {} distinct nodes, exceeding the \
             configured max_total_nodes limit of {} (fail-closed: scan result is \
             at least Warn)",
            self.count, self.limit
        )
    }

    /// The fail-closed verdict floor a budget breach imposes on the scan
    /// (REQ-105-03). **Always `Warn` (never `Pass`)** — an over-budget scan is
    /// incomplete input, so silently treating it as `Pass` is prohibited; the
    /// breach itself floors the result at ≥ `Warn`. This is the single point that
    /// maps the breach to a verdict, mirroring the engine's other fail-closed
    /// floors (depth limit, unresolved range, unfetchable child).
    pub fn fail_closed_verdict(&self) -> Verdict {
        Verdict::Warn
    }
}

/// A fail-closed counter of distinct nodes enqueued during a transitive walk.
///
/// Construct with [`NodeBudget::new`] from the `max_total_nodes` config value
/// (task 107 supplies it; this counter only reads it). Call [`charge`] once per
/// node as it is enqueued; the counter deduplicates on `NodeId` and signals
/// [`BudgetCharge::Exceeded`] the instant the distinct count would surpass the
/// limit.
///
/// [`charge`]: NodeBudget::charge
#[derive(Debug)]
pub struct NodeBudget {
    /// The `max_total_nodes` ceiling. A value of `0` fails on the first charge.
    limit: u32,
    /// Distinct nodes charged so far, keyed on full `NodeId` (REQ-105-05 dedup).
    counted: HashSet<NodeId>,
}

impl NodeBudget {
    /// Construct a budget with the given `max_total_nodes` ceiling.
    pub fn new(max_total_nodes: u32) -> Self {
        Self {
            limit: max_total_nodes,
            counted: HashSet::new(),
        }
    }

    /// The number of distinct nodes counted so far.
    pub fn counted(&self) -> u32 {
        self.counted.len() as u32
    }

    /// Charge one node against the budget.
    ///
    /// - If `node` was already charged, this is an idempotent no-op returning
    ///   [`BudgetCharge::Counted`] — the budget is never double-charged for a
    ///   diamond dep (REQ-105-05).
    /// - If `node` is new and counting it keeps the distinct count within
    ///   `limit`, the node is recorded and [`BudgetCharge::Counted`] returned.
    /// - If `node` is new and counting it would push the distinct count **past**
    ///   `limit`, the budget is exceeded: [`BudgetCharge::Exceeded`] is returned
    ///   with a [`NodeBudgetExceeded`] carrying count + limit. The node is **not**
    ///   recorded (the count reported is the would-be count, `limit + 1`), so the
    ///   scan fails closed rather than silently truncating (REQ-105-03).
    ///
    /// With `limit == 0`, the first distinct node fails immediately (T-105-07).
    pub fn charge(&mut self, node: &NodeId) -> BudgetCharge {
        // Dedup: an already-counted node is a no-op (diamond dep, REQ-105-05).
        if self.counted.contains(node) {
            return BudgetCharge::Counted;
        }
        // Would-be distinct count if we counted this new node.
        let would_be = self.counted.len() as u32 + 1;
        if would_be > self.limit {
            // Fail closed: do NOT record the node; report the would-be count so
            // the diagnostic shows the ceiling was crossed (limit + 1).
            return BudgetCharge::Exceeded(NodeBudgetExceeded {
                count: would_be,
                limit: self.limit,
            });
        }
        self.counted.insert(node.clone());
        BudgetCharge::Counted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(name: &str, version: &str) -> NodeId {
        NodeId::Registry {
            name: name.to_string(),
            version: version.to_string(),
            registry: "npm".to_string(),
        }
    }

    // --- T-105-05: exceeding max_total_nodes fails closed with diagnostic ---
    //
    // The budget half of T-105-05: charging past the limit yields Exceeded
    // (never a silent Counted), and the diagnostic carries count + limit. The
    // verdict-floor half (≥ Warn, never Pass) is asserted in pool.rs where the
    // budget is wired to a verdict.
    #[test]
    fn t_105_05_exceeding_limit_fails_closed_with_diagnostic() {
        let mut budget = NodeBudget::new(10);
        // First 10 distinct nodes are counted.
        for i in 0..10 {
            let charge = budget.charge(&reg(&format!("n{i}"), "1.0"));
            assert_eq!(charge, BudgetCharge::Counted, "node {i} within budget");
        }
        assert_eq!(budget.counted(), 10);
        // The 11th distinct node exceeds the budget — NOT silently dropped.
        let charge = budget.charge(&reg("n10", "1.0"));
        match charge {
            BudgetCharge::Exceeded(diag) => {
                assert_eq!(diag.count, 11, "count is the would-be 11th node");
                assert_eq!(diag.limit, 10, "limit is the configured ceiling");
            }
            BudgetCharge::Counted => {
                panic!("T-105-05: the 11th node must fail closed, not be silently counted")
            }
        }
        // The over-budget node was NOT recorded — the budget did not truncate to
        // a passing first-10 set; it refused to proceed.
        assert_eq!(budget.counted(), 10);
    }

    // --- T-105-05 (fail-closed callout): a budget breach floors ≥ Warn, never
    // Pass. Silent truncation to Pass would let an attacker hide a malicious node
    // past the budget — prohibited. The breach maps to Warn, and crucially NOT to
    // Pass, regardless of how the first `limit` nodes scanned.
    #[test]
    fn t_105_05_budget_breach_floors_warn_never_pass() {
        let mut budget = NodeBudget::new(1);
        assert_eq!(budget.charge(&reg("ok", "1.0")), BudgetCharge::Counted);
        let BudgetCharge::Exceeded(diag) = budget.charge(&reg("over", "1.0")) else {
            panic!("the 2nd node must exceed a limit of 1");
        };
        let floor = diag.fail_closed_verdict();
        assert!(
            floor >= Verdict::Warn,
            "T-105-05: a budget breach must floor the scan at ≥ Warn"
        );
        assert_ne!(
            floor,
            Verdict::Pass,
            "T-105-05: silent truncation to Pass is prohibited"
        );
    }

    // --- T-105-06 (value half): diagnostic message includes count AND limit ---
    #[test]
    fn t_105_06_diagnostic_message_includes_count_and_limit() {
        let mut budget = NodeBudget::new(2);
        let _ = budget.charge(&reg("a", "1.0"));
        let _ = budget.charge(&reg("b", "1.0"));
        let BudgetCharge::Exceeded(diag) = budget.charge(&reg("c", "1.0")) else {
            panic!("third node must exceed a limit of 2");
        };
        let msg = diag.message();
        assert!(
            msg.contains('3'),
            "message must include the node count (3): {msg}"
        );
        assert!(
            msg.contains('2'),
            "message must include the configured limit (2): {msg}"
        );
    }

    // --- T-105-07: max_total_nodes = 0 fails immediately ---
    #[test]
    fn t_105_07_zero_limit_fails_immediately() {
        let mut budget = NodeBudget::new(0);
        // Any non-empty graph: the very first node exceeds a limit of 0.
        let charge = budget.charge(&reg("only", "1.0"));
        match charge {
            BudgetCharge::Exceeded(diag) => {
                assert_eq!(diag.count, 1, "the first node is count 1");
                assert_eq!(diag.limit, 0, "limit is 0");
            }
            BudgetCharge::Counted => {
                panic!("T-105-07: a limit of 0 must fail on the first node")
            }
        }
        assert_eq!(budget.counted(), 0, "nothing was counted under a 0 budget");
    }

    // --- T-105-08: diamond dedup — D counted once, budget consumption 4 not 5 -
    #[test]
    fn t_105_08_diamond_dedup_counts_distinct_nodes_once() {
        // Diamond A -> {B, C}; B -> {D}; C -> {D}. 4 distinct nodes.
        let (a, b, c, d) = (
            reg("a", "1.0"),
            reg("b", "1.0"),
            reg("c", "1.0"),
            reg("d", "1.0"),
        );
        let mut budget = NodeBudget::new(100);
        // Enqueue order a DFS would produce: A, B, D, C, then D again (re-visit).
        assert_eq!(budget.charge(&a), BudgetCharge::Counted);
        assert_eq!(budget.charge(&b), BudgetCharge::Counted);
        assert_eq!(budget.charge(&d), BudgetCharge::Counted);
        assert_eq!(budget.charge(&c), BudgetCharge::Counted);
        // Second encounter of D (the diamond join) must NOT consume budget again.
        assert_eq!(budget.charge(&d), BudgetCharge::Counted);
        assert_eq!(
            budget.counted(),
            4,
            "diamond dep D counted once: budget consumption is 4, not 5"
        );
    }

    // --- dedup keys on the full NodeId (name + version), not name alone ---
    #[test]
    fn budget_keys_on_full_node_id() {
        let mut budget = NodeBudget::new(100);
        // Same name, different versions are distinct nodes.
        assert_eq!(budget.charge(&reg("foo", "1.0")), BudgetCharge::Counted);
        assert_eq!(budget.charge(&reg("foo", "2.0")), BudgetCharge::Counted);
        assert_eq!(budget.counted(), 2, "foo@1.0 and foo@2.0 are distinct");
    }
}

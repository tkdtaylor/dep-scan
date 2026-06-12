//! Transitive dependency resolution (ADR 009).
//!
//! Task 102 provides the **pure algorithmic core** of the transitive walker: a
//! visited-set depth-first search over abstract [`EdgeProvider`] and
//! [`NodeScanner`] traits, with depth-limit enforcement, cycle detection, and
//! diagnostic production. It performs **zero I/O** — all data flows through the
//! injected trait objects, which task 103 will implement against real lockfiles,
//! manifests, and git fetches.
//!
//! The full transitive verdict rollup (worst-verdict-wins propagation into
//! `aggregate_results`) is task 104; this task only previews the fail-closed
//! floors at the edges (depth limit / unresolved range → parent ≥ `Warn`).

pub mod engine;
pub mod providers;
pub mod scanner;

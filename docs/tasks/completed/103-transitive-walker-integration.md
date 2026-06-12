# Task 103 — Transitive walker integration

**Status:** completed
**Depends on:** 100 (lockfile graph reader), 101 (manifest edge reader),
               102 (DFS engine traits)
**ADR:** 009 (piece 3b — concrete provider wiring)
**Scope:** medium
**Touches:** `src/transitive/providers.rs` (new — concrete EdgeProvider impls),
            `src/transitive/scanner.rs` (new — concrete NodeScanner impl),
            `src/vcs/fetch.rs` (called on scan path for git sub-trees),
            `src/main.rs` (minimal — exposes the wired walker for task 108)

## Objective

Wire the concrete `EdgeProvider` implementations (the lockfile graph reader from
task 100 and the manifest edge reader from task 101) and the concrete
`NodeScanner` (wrapping `run_git_tree_policies` from task 098) into the DFS
engine from task 102. This is the first task where a real git sub-tree fetch
happens on the scan path, mediated by the `VcsFetcher::fetch` from task 096.

All integration tests use local fixtures or a local git daemon — **zero external
network**.

## Background

ADR 009 Decision 1: registry edges come from the lockfile (`LockfileEdgeProvider`
from task 100); git sub-tree edges come from the fetched tree's manifest
(`ManifestEdgeProvider` from task 101). The two sources are reconciled by NodeId
identity at insertion into the visited set — they both produce `NodeId` values;
the DFS engine sees no difference.

Reuse targets:
- `run_git_tree_policies` (task 098) — per-node policy pipeline for git nodes.
- `classify_ref` (task 094) — determines whether a git dep is pinned or mutable.
- `VcsFetcher::fetch` (task 096) — the fetch client; called on the scan path only.
- `FetchedTree` (task 096) — the materialized tree consumed by `ManifestEdgeProvider`.

## Requirements

### REQ-103-01: `LockfileEdgeProvider` implements `EdgeProvider`
Wraps the `DependencyGraph` from task 100. Returns the pre-parsed edges for any
`NodeId` found in the graph; returns an empty edge set for nodes not in the
lockfile (they may appear via manifest edges at a deeper level).

### REQ-103-02: `ManifestEdgeProvider` implements `EdgeProvider`
Takes a `FetchedTree`. Calls `manifest_edges_from_tree` (task 101). If the
manifest is absent or unparseable, returns `EdgeError` (not a silent empty set).

### REQ-103-03: Concrete `NodeScanner` routes by NodeId variant
- `NodeId::Git` → `VcsFetcher::fetch` → `run_git_tree_policies` (via task 098).
  Then `classify_ref` (task 094) to decide caching.
- `NodeId::Registry` → existing registry scan pipeline.
- Mutable-ref git deps are never cached (task 097 invariant respected here).
- Pinned-SHA git deps are cached after first scan.

### REQ-103-04: Fetch happens only on the scan path
No fetch occurs during edge discovery. `ManifestEdgeProvider` reads bytes
already in the `FetchedTree`; a new fetch is only triggered when the concrete
`NodeScanner` encounters an un-visited git `NodeId` not in cache.

### REQ-103-05: All integration tests use local fixtures / local git daemon
Zero external network. Verified by T-103-01.

## Acceptance criteria

- [ ] `LockfileEdgeProvider::edges_for` returns correct edges (T-103-02..03)
- [ ] `ManifestEdgeProvider::edges_for` returns correct edges (T-103-04)
- [ ] ManifestEdgeProvider fail-closed on missing manifest (T-103-05)
- [ ] Concrete NodeScanner invokes run_git_tree_policies for git nodes (T-103-06)
- [ ] Concrete NodeScanner routes to registry pipeline for registry nodes (T-103-07)
- [ ] Two-level offline walk completes correctly (T-103-08)
- [ ] Mutable-ref git dep is not cached (T-103-09)
- [ ] Pinned-SHA git dep is cached after first scan (T-103-10)
- [ ] Zero external network in all tests (T-103-01)
- [ ] All T-103-01 through T-103-11 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/103-transitive-walker-integration-test-spec.md`

## Out of scope

- Verdict rollup propagation (task 104)
- Fetch pool and node budget (task 105)
- subtree_digest cache column (task 106)
- Config parsing and CLI flag (task 107)
- Main.rs scan-arm wiring (task 108)

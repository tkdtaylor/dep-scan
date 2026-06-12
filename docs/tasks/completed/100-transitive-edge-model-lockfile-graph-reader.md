# Task 100 — Transitive edge model + lockfile graph reader

**Status:** backlog
**Depends on:** — (first task in the transitive epic)
**ADR:** 009 (piece 1 — Decision 1, lockfile-first source of truth)
**Scope:** medium
**Touches:** `src/lockfile.rs` (add `NodeId`, `DependencyGraph`, edge-extraction
            functions for package-lock.json and Cargo.lock), `src/lib.rs` or
            equivalent (export new types)

## Objective

Define the in-memory `NodeId` and `DependencyGraph` types used throughout the
transitive epic, and extend `src/lockfile.rs` to expose **edges** between
resolved entries for the two ecosystems whose lockfiles encode a graph:
**package-lock.json** (npm v1/v2/v3) and **Cargo.lock**. The flat-list parsers
already present (`parse_package_lock_json`, `parse_cargo_lock`) are **reused
and extended**, not replaced.

PyPI (`requirements.txt`) and Go (`go.sum`) are **flat** formats — they encode
no dependency edges. This task explicitly produces depth-0 nodes with empty
edge sets for these ecosystems and documents that as the correct, asserted
outcome. It is not a silent gap.

This task is **pure parsing** — zero network I/O.

## Background

ADR 009 Decision 1 (lockfile-first): when a lockfile is present, it is the
authoritative source of the resolved transitive edge set. dep-scan already
parses lockfiles into flat resolved `(name, version)` entries. This task
turns "scan the flat list" into "walk the graph the lockfile already encodes."

The `NodeId` type reuses the existing cache identity (ADR 009 *Reuse the
identity*):
- Registry: `(name, version, registry)` — matches `src/cache.rs` `insert` key
- Git: `(name, commit_sha, "git")` — matches `src/cache.rs:261` `insert_git` key

No third identity variant is introduced.

## Requirements

### REQ-100-01: Define `NodeId` enum
Two variants matching the cache identity:
- `NodeId::Registry { name: String, version: String, registry: String }`
- `NodeId::Git { name: String, commit_sha: String }`

`NodeId` must implement `Hash + Eq + Clone + Debug` so it is usable as a
`HashSet`/`HashMap` key.

### REQ-100-02: Define `DependencyGraph` struct
In-memory directed graph exposing:
- `DependencyGraph::new() -> Self`
- `fn nodes(&self) -> impl Iterator<Item = &NodeId>`
- `fn edges_from(&self, node: &NodeId) -> &[NodeId]` (or equivalent)
- `fn from_edges(edges: impl IntoIterator<Item = (NodeId, NodeId)>) -> Self`

Building a graph from a cyclic edge set must not infinite-loop (cycle traversal
is the walker's job, not the graph builder's).

### REQ-100-03: npm package-lock.json edge extraction
Extend `parse_package_lock_json` (or add a sibling function) to return a
`DependencyGraph` for lockfile versions v1, v2, and v3. Each edge maps a
resolved `NodeId` to its resolved transitive dependencies.

An `requires`/`dependencies` entry that references a name absent from the
resolved packages must emit a diagnostic (not panic) and be recorded as an
unresolvable edge. It must not be silently treated as Pass.

### REQ-100-04: Cargo.lock edge extraction
Extend `parse_cargo_lock` to return a `DependencyGraph`. Each
`[[package]].dependencies` line maps to an edge. Git-sourced entries
(`source = "git+…#commit_sha"`) produce `NodeId::Git`. No extra fetch.

### REQ-100-05: PyPI / Go explicit empty-edge contract
`requirements.txt` and `go.sum` parsers return a `DependencyGraph` with all
nodes present but **all edge sets empty**. The empty-edge behaviour is
documented in code comments as intentional, not a bug.

### REQ-100-06: Zero network I/O
No lockfile-to-graph function performs any file I/O beyond reading the bytes
passed in, and no network call is ever made. Verified by T-100-11 and T-100-15.

## Acceptance criteria

- [ ] `NodeId` with `Hash + Eq + Clone + Debug` compiles and passes T-100-01..04
- [ ] `DependencyGraph` passes T-100-05..07
- [ ] npm v1/v2/v3 edge extraction passes T-100-08..11
- [ ] Cargo.lock edge extraction passes T-100-12..15
- [ ] PyPI and Go explicit-empty contract passes T-100-16..17
- [ ] Zero network I/O asserted (T-100-11, T-100-15)
- [ ] Cyclic lockfile does not infinite-loop during graph build (T-100-07)
- [ ] Missing resolved entry emits diagnostic, not panic (T-100-10)
- [ ] All pre-existing lockfile tests still pass (non-regression)
- [ ] All T-100-01 through T-100-18 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/100-transitive-edge-model-lockfile-graph-reader-test-spec.md`

## Out of scope

- Manifest edge reading from fetched git trees (task 101)
- The DFS walk itself (task 102)
- Any network fetch (task 103)
- Config changes (task 107)

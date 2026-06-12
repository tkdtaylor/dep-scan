# Task 101 — Manifest edge reader for fetched git sub-trees

**Status:** backlog
**Depends on:** task 100 (NodeId, DependencyGraph), task 096 (FetchedTree)
**ADR:** ADR 009 Decision 1 (lockfile-first, manifest-fallback)

## Goal

Implement a pure in-memory reader that extracts direct dependency edges from a
`FetchedTree` (the already-materialised git sub-tree from task 096) without
any additional network I/O.  This is the "manifest-fallback" half of ADR 009
Decision 1: when a git-sourced dependency's transitive children are not
covered by the consuming project's lockfile, their edges come from parsing the
sub-tree's own manifest (`package.json` or `Cargo.toml`).

## Requirements

- **REQ-101-01** Zero network I/O — all reads are from bytes already in the
  `FetchedTree`; no filesystem access beyond what the tree already holds.
- **REQ-101-02** `package.json` `dependencies` field → `NodeId::Registry`
  edges with `registry = "npm"`.  Version range strings (e.g. `^1.2.0`) are
  stored verbatim as `UnresolvedRange` markers.  `devDependencies` are
  excluded.
- **REQ-101-03** `Cargo.toml` `[dependencies]` → `NodeId::Registry` (registry
  `"crates"`) for plain version deps; `NodeId::Git` for git deps with
  `rev = "<sha>"` or `git = "<url>"`.  A workspace root with no
  `[dependencies]` is a valid empty-edge result, not an error.
- **REQ-101-04** Absent or unparseable manifest → `Err(ManifestError)` or an
  explicit error diagnostic.  A silent empty edge set is never returned when
  a manifest is expected but malformed.
- **REQ-101-05** `devDependencies` in `package.json` are always excluded.
- **REQ-101-06** Ecosystem hint: when both `package.json` and `Cargo.toml`
  are present, a caller-supplied `Ecosystem` hint selects exactly one —
  no duplicate edges.

## Deliverables

- New `src/vcs/manifest.rs` module exposing:
  - `Ecosystem` enum (`Npm`, `Cargo`)
  - `ManifestError` error type
  - `UnresolvedRange` — represents an unresolved version range edge
  - `ManifestEdge` — either a resolved `NodeId` or an `UnresolvedRange`
  - `manifest_edges_from_tree(tree, ecosystem) -> Result<Vec<ManifestEdge>, ManifestError>`
- `src/vcs/mod.rs` updated to `pub mod manifest;`
- Tests T-101-01 through T-101-12 in the module (TDD — tests first)

## Out of scope

- Python manifests (`pyproject.toml`, `setup.py`) — explicitly excluded
- Semver range resolution — `UnresolvedRange` stores the string verbatim
- Recursive transitive walk — that is task 103
- Fetching additional trees — only bytes in the existing `FetchedTree`

# Test Spec — Task 103: Transitive walker integration

## Context

ADR 009 piece 3b. Wires concrete `EdgeProvider` implementations (the lockfile
graph reader from task 100 and the manifest edge reader from task 101) and a
concrete `NodeScanner` (reusing `run_git_tree_policies` from task 098) into the
DFS engine from task 102. This is the first task where a real git sub-tree fetch
happens on the scan path. All integration tests run against local fixtures or a
local git daemon — zero external network access.

---

## Zero-external-network contract

### T-103-01: Integration walk uses only local fixtures or local git daemon
- All tests in this task run against pre-staged local git repositories or
  `FetchedTree` fixtures.
- No call to a public internet endpoint is made.
- Assert: tests pass in a network-isolated environment (stub transport or
  local daemon only).
- (Fail-closed callout: network calls only occur on the explicit scan path;
  this test ensures that the integration plumbing does not accidentally
  trigger network during edge discovery.)

---

## Lockfile EdgeProvider wiring

### T-103-02: Lockfile EdgeProvider returns correct edges for npm package-lock.json
- Stage a fixture `package-lock.json` with a two-level dep tree
  (A depends on B; B depends on C).
- Construct `LockfileEdgeProvider::from_bytes(bytes)`.
- `provider.edges_for(&A_node)` returns `{B_node}`;
  `provider.edges_for(&B_node)` returns `{C_node}`.
- Conforms to the `EdgeProvider` trait contract expected by the DFS engine.

### T-103-03: Lockfile EdgeProvider wired into DFS engine produces full walk
- Same fixture; feed into `dfs_walk(root=A, max_depth=5, edge_provider, scanner)`.
- All three nodes A, B, C are visited.

---

## Manifest EdgeProvider wiring (git sub-trees)

### T-103-04: Manifest EdgeProvider returns correct edges from a FetchedTree
- Create a local git repo fixture with a `package.json` listing dep B.
- Fetch it via `VcsFetcher::fetch` (against local daemon or fixture path).
- `ManifestEdgeProvider::from_fetched_tree(&tree)` returns `{B_node}`.

### T-103-05: Manifest EdgeProvider fail-closed on missing manifest
- A `FetchedTree` fixture with no manifest file.
- `ManifestEdgeProvider::from_fetched_tree(&tree)` returns a diagnostic.
- The DFS engine receives an error/diagnostic edge set, not a silent empty set.
- (Fail-closed callout: absent manifest = unscannable; the parent rollup floors
  the result at ≥ Warn, never Pass.)

---

## NodeScanner wiring (run_git_tree_policies reuse)

### T-103-06: NodeScanner invokes run_git_tree_policies for git nodes
- A local fixture git repo containing a malicious `postinstall.js`.
- The concrete `NodeScanner` calls `run_git_tree_policies` (task 098 function).
- The returned verdict is Warn or Block (not Pass).

### T-103-07: NodeScanner invokes the registry scan pipeline for registry nodes
- A fixture registry node (inline mock, not a real registry call).
- The concrete `NodeScanner` routes to the registry scan path.
- The returned verdict matches the mock scan result.

---

## End-to-end offline integration walk

### T-103-08: Full two-level walk: direct clean dep with malicious transitive child
- Graph: root (registry) → dep-A (npm, clean) → dep-B (git, malicious install script).
- Use local fixtures for both the lockfile and the git sub-tree.
- `dfs_walk` visits root, dep-A, dep-B.
- dep-B scan returns Block (from `run_git_tree_policies`).
- dep-A rollup is Block (worst-verdict-wins from task 104 — this test previews
  the rollup but the assertion here is that dep-B's Block is returned correctly).

### T-103-09: Walk with classify_ref — mutable-ref git dep is never cached
- A fixture git dep with a mutable-ref URL (branch name, not commit SHA).
- The concrete `NodeScanner` calls `classify_ref` (task 094) before deciding
  whether to cache the result.
- After the scan, no cache entry is written for the mutable-ref dep.
- (Fail-closed callout: caching a mutable-ref verdict would serve stale content
  on the next scan — always re-fetch.)

### T-103-10: Walk with classify_ref — pinned-SHA git dep is cached after first scan
- A fixture git dep with a pinned commit SHA URL.
- First scan: cache miss → `run_git_tree_policies` runs → result cached.
- Second scan: cache hit → `run_git_tree_policies` not called again.
- Assert via mock call count on the policy runner.

---

## Tooling gate

### T-103-11: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

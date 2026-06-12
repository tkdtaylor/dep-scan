# Test Spec — Task 100: Transitive edge model + lockfile graph reader

## Context

ADR 009 piece 1 (Decision 1). Defines the in-memory `NodeId` and
`DependencyGraph` types and extends `src/lockfile.rs` to expose edges (not just
flat entries) for **package-lock.json (npm)** and **Cargo.lock**. PyPI
(`requirements.txt`) and Go (`go.sum`) are flat formats that encode no edges;
they yield depth-0 nodes with an explicit empty edge set. This is a pure
parsing task — zero network I/O.

---

## NodeId type

### T-100-01: Registry NodeId round-trips through equality
- Construct `NodeId::Registry { name: "lodash", version: "4.17.21", registry: "npm" }`.
- A second `NodeId::Registry` with identical fields compares equal.
- A `NodeId::Registry` with a different version is not equal.

### T-100-02: Git NodeId round-trips through equality
- Construct `NodeId::Git { name: "my-lib", commit_sha: "abc123def456" }`.
- A second `NodeId::Git` with the same fields compares equal.
- A `NodeId::Git` with a different `commit_sha` is not equal.

### T-100-03: NodeId is usable as a HashSet key
- Insert several `NodeId` values (mix of Registry and Git) into a `HashSet<NodeId>`.
- Lookup by value returns the expected membership results.
- Confirms `Hash + Eq` are correctly derived / implemented.

### T-100-04: NodeId matches the cache identity scheme
- `NodeId::Registry { name, version, registry }` maps 1-to-1 to the
  `(name, version, registry)` cache key from `src/cache.rs`.
- `NodeId::Git { name, commit_sha }` maps 1-to-1 to the `(name, commit_sha, "git")`
  cache key from `insert_git` (task 097).
- No third identity variant exists in the type definition.

---

## DependencyGraph type

### T-100-05: Empty graph has no nodes and no edges
- `DependencyGraph::new()` returns a graph with zero nodes and zero edges.
- `graph.nodes().count() == 0`; `graph.edges_from(any_node_id).is_empty()`.

### T-100-06: Graph exposes edges_from for a known node
- Insert node A with edges to B and C.
- `graph.edges_from(&A)` returns exactly `{B, C}`.
- `graph.edges_from(&B)` returns an empty set (B has no outgoing edges).

### T-100-07: Graph build from a cyclic lockfile does not infinite-loop
- Construct a graph from a synthetic `LockfileEdgeSet` that contains A→B and B→A.
- `DependencyGraph::from_edges(...)` returns successfully (no panic, no hang).
- The graph encodes both edges; cycle traversal is the walker's responsibility,
  not the graph builder's. (Fail-closed callout: the graph represents the edges
  faithfully; the DFS walker in task 102 is responsible for cycle detection.)

---

## npm package-lock.json edge extraction

### T-100-08: v1 package-lock.json extracts edges for a simple direct dep
- Parse a minimal v1 `package-lock.json`:
  ```json
  {
    "lockfileVersion": 1,
    "dependencies": {
      "express": {
        "version": "4.18.2",
        "requires": { "accepts": "~1.3.8" },
        "dependencies": {
          "accepts": { "version": "1.3.8", "requires": {} }
        }
      }
    }
  }
  ```
- `graph.edges_from(&NodeId::Registry { name:"express", version:"4.18.2", registry:"npm" })`
  contains `NodeId::Registry { name:"accepts", version:"1.3.8", registry:"npm" }`.

### T-100-09: v2/v3 package-lock.json extracts edges via `packages` map
- Parse a minimal v2/v3 `package-lock.json`:
  ```json
  {
    "lockfileVersion": 3,
    "packages": {
      "node_modules/express": {
        "version": "4.18.2",
        "dependencies": { "accepts": "^1.3.8" }
      },
      "node_modules/accepts": { "version": "1.3.8" }
    }
  }
  ```
- `graph.edges_from(express_node)` contains the `accepts` node at version `1.3.8`.
- The resolved version for the edge target is read from the `packages` map (not
  from the semver range string).

### T-100-10: npm edge extraction — dep referenced in `requires` but absent from resolved packages emits a diagnostic, not a panic
- A v1 lockfile where `express` has `"requires": { "orphaned": "^1.0.0" }` but no
  corresponding resolved entry.
- Parse does not panic; the edge to `orphaned` is either omitted with a diagnostic
  logged or represented as `UnresolvedRange` — either way, the graph is returned.
- (Fail-closed callout: an absent resolved entry must not be silently treated as
  Pass — it is an unresolvable edge that the walker will roll up as ≥ Warn.)

### T-100-11: npm edge extraction is zero-network
- The `lockfile_to_graph` function for package-lock.json reads only the bytes
  passed in — no file I/O, no network calls.
- Assert: mocking the network (no-op or failure) does not change the parse result.

---

## Cargo.lock edge extraction

### T-100-12: Cargo.lock [[package]].dependencies edges extracted correctly
- Parse a minimal `Cargo.lock`:
  ```toml
  [[package]]
  name = "my-crate"
  version = "1.0.0"
  dependencies = ["serde 1.0.190 (registry+https://github.com/rust-lang/crates.io-index)"]

  [[package]]
  name = "serde"
  version = "1.0.190"
  source = "registry+https://github.com/rust-lang/crates.io-index"
  ```
- `graph.edges_from(my_crate_node)` contains `NodeId::Registry { name:"serde", version:"1.0.190", registry:"crates" }`.

### T-100-13: Cargo.lock git source dependency is represented as NodeId::Git
- Parse a `Cargo.lock` entry with `source = "git+https://github.com/foo/bar#abc123"`.
- The resolved NodeId for that dep is `NodeId::Git { name:..., commit_sha:"abc123" }`.
- Matches the `(name, commit_sha, "git")` cache identity.

### T-100-14: Cargo.lock dependency with no version suffix still resolves
- A `dependencies` entry like `"log"` (no version or source hint) matches the
  single `[[package]]` entry named `log` in the lockfile.
- The edge is recorded; no panic on the missing version annotation.

### T-100-15: Cargo.lock edge extraction is zero-network
- Same assertion as T-100-11 for `Cargo.lock`. No I/O beyond the bytes passed in.

---

## Flat ecosystems — explicit empty-edge contract

### T-100-16: requirements.txt yields nodes with empty edge sets
- Parse `requirements.txt` with two lines: `requests==2.31.0` and `urllib3==2.0.7`.
- `graph.nodes()` returns both as `NodeId::Registry` entries.
- `graph.edges_from(requests_node)` returns an empty set.
- `graph.edges_from(urllib3_node)` returns an empty set.
- This is explicitly documented as the correct outcome: requirements.txt encodes
  no dependency edges. (Not a silent gap — asserted and documented.)

### T-100-17: go.sum yields nodes with empty edge sets
- Parse a `go.sum` with two entries.
- Same assertions as T-100-16: both nodes present, both edge sets empty.
- Explicitly documented: go.sum is a flat hash manifest, not a graph encoding.

---

## Tooling gate

### T-100-18: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.
- The existing flat-list `parse_*` functions still pass all pre-existing tests
  (non-regression: the edge-model extension is additive, not a replacement).

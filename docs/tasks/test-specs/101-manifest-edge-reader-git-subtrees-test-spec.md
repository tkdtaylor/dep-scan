# Test spec — Task 101: Manifest edge reader for fetched git sub-trees

**Status:** ready
**Module under test:** `src/vcs/manifest.rs` — `manifest_edges_from_tree`

---

## Acceptance criteria

All tests are pure in-memory (zero network, zero filesystem) using
`FetchedTree::from_files_for_test`.

---

### T-101-01 — package.json `dependencies` → NodeId::Registry edges

**Given** a `FetchedTree` containing a valid `package.json` with a
`dependencies` field listing `{ "express": "^4.18.0", "lodash": "1.2.3" }`.

**When** `manifest_edges_from_tree(tree, Ecosystem::Npm)` is called.

**Then** the result is `Ok`, containing two `ManifestEdge::Unresolved` entries
with names `"express"` (range `"^4.18.0"`) and `"lodash"` (range `"1.2.3"`).

**Assertion:** REQ-101-02 — npm `dependencies` become UnresolvedRange entries
with the version string preserved verbatim.

---

### T-101-02 — package.json `devDependencies` excluded

**Given** a `FetchedTree` containing a `package.json` with `devDependencies:
{ "jest": "^29.0.0" }` and no `dependencies` field.

**When** `manifest_edges_from_tree(tree, Ecosystem::Npm)` is called.

**Then** the result is `Ok(vec![])` — empty, no edges, no error.

**Assertion:** REQ-101-05 — devDependencies are always excluded.

---

### T-101-03 — package.json with both `dependencies` and `devDependencies`

**Given** a `FetchedTree` with a `package.json` where `dependencies` has
`{ "react": "^18.0.0" }` and `devDependencies` has `{ "typescript": "^5.0.0" }`.

**When** `manifest_edges_from_tree(tree, Ecosystem::Npm)` is called.

**Then** the result contains exactly one edge: `"react"` with range `"^18.0.0"`.
`"typescript"` does not appear.

**Assertion:** REQ-101-02 and REQ-101-05.

---

### T-101-04 — Cargo.toml plain version dep → NodeId::Registry

**Given** a `FetchedTree` containing a `Cargo.toml` with:
```toml
[package]
name = "mylib"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
```

**When** `manifest_edges_from_tree(tree, Ecosystem::Cargo)` is called.

**Then** the result is `Ok`, containing two `ManifestEdge::Resolved(NodeId::Registry)`
entries: `{ name: "serde", version: "1.0", registry: "crates" }` and
`{ name: "tokio", version: "1.0", registry: "crates" }`.

**Assertion:** REQ-101-03 — Cargo registry deps become NodeId::Registry with
`registry = "crates"`.

---

### T-101-05 — Cargo.toml git dep with `rev` → NodeId::Git

**Given** a `FetchedTree` containing a `Cargo.toml` with:
```toml
[dependencies]
mylib = { git = "https://github.com/example/mylib", rev = "abc123def456" }
```

**When** `manifest_edges_from_tree(tree, Ecosystem::Cargo)` is called.

**Then** the result contains one `ManifestEdge::Resolved(NodeId::Git { name: "mylib", commit_sha: "abc123def456" })`.

**Assertion:** REQ-101-03 — Cargo git dep with `rev` becomes NodeId::Git.

---

### T-101-06 — Cargo.toml workspace root with no `[dependencies]` → empty, no error

**Given** a `FetchedTree` containing a `Cargo.toml` with only `[workspace]`
and `[package]` sections and no `[dependencies]` section at all.

**When** `manifest_edges_from_tree(tree, Ecosystem::Cargo)` is called.

**Then** the result is `Ok(vec![])` — empty, no error.

**Assertion:** REQ-101-03 — workspace root with no `[dependencies]` is a valid
empty-edge result, not an error.

---

### T-101-07 — Absent manifest → ManifestError

**Given** a `FetchedTree` that contains no `package.json` (for Npm) or no
`Cargo.toml` (for Cargo) — e.g. a tree containing only `README.md`.

**When** `manifest_edges_from_tree(tree, Ecosystem::Npm)` is called.

**Then** the result is `Err(ManifestError)`.  The error message mentions the
expected manifest file name.

**Assertion:** REQ-101-04 — absent manifest → Err, never silent empty.

---

### T-101-08 — Malformed/invalid JSON manifest → ManifestError

**Given** a `FetchedTree` containing a `package.json` whose content is not
valid JSON (e.g. `"{ broken json "`).

**When** `manifest_edges_from_tree(tree, Ecosystem::Npm)` is called.

**Then** the result is `Err(ManifestError)` — not an empty `Ok`.

**Assertion:** REQ-101-04 — unparseable manifest → Err, never silent empty.

---

### T-101-09 — Malformed/invalid TOML manifest → ManifestError

**Given** a `FetchedTree` containing a `Cargo.toml` whose content is not valid
TOML (e.g. `"[broken toml"`).

**When** `manifest_edges_from_tree(tree, Ecosystem::Cargo)` is called.

**Then** the result is `Err(ManifestError)`.

**Assertion:** REQ-101-04 — unparseable TOML manifest → Err, never silent empty.

---

### T-101-10 — Ecosystem hint selects exactly one manifest (no duplicates)

**Given** a `FetchedTree` containing *both* a `package.json` (with one npm dep)
*and* a `Cargo.toml` (with one crates dep).

**When** `manifest_edges_from_tree(tree, Ecosystem::Npm)` is called,
**Then** only the npm dep edge is returned (no Cargo edges).

**When** `manifest_edges_from_tree(tree, Ecosystem::Cargo)` is called,
**Then** only the crates dep edge is returned (no npm edges).

**Assertion:** REQ-101-06 — ecosystem hint selects exactly one manifest.

---

### T-101-11 — Zero network I/O (structural guarantee)

**Given** a valid `FetchedTree` built with `from_files_for_test` (never
involves a real network fetch), containing a `package.json`.

**When** `manifest_edges_from_tree(tree, Ecosystem::Npm)` is called,

**Then** the call completes without panicking and returns `Ok`.  This test
verifies the structural guarantee: `manifest_edges_from_tree` accepts only
bytes already in the tree; it has no network call path.

**Assertion:** REQ-101-01 — zero network I/O; the function signature accepts
only a `&FetchedTree`, which is already a no-network type.

---

### T-101-12 — Cargo.toml git dep without `rev` → UnresolvedRange

**Given** a `FetchedTree` containing a `Cargo.toml` where a git dep specifies
only `git = "https://..."` with no `rev`, `branch`, or `tag` field — so no
pinned SHA is available.

**When** `manifest_edges_from_tree(tree, Ecosystem::Cargo)` is called.

**Then** the result contains one `ManifestEdge::Unresolved` entry for that dep
with an appropriate range/hint string (e.g. the git URL or an empty range),
indicating it could not be resolved to a `NodeId::Git` with a pinned SHA.

**Assertion:** REQ-101-03 — git dep without pinned SHA cannot become
`NodeId::Git`; it must be recorded as `UnresolvedRange`, not silently dropped
or error.

---

## Type contracts

```
pub enum Ecosystem { Npm, Cargo }

pub struct UnresolvedRange {
    pub name: String,
    pub range: String,  // verbatim version string / range from the manifest
}

pub enum ManifestEdge {
    Resolved(NodeId),
    Unresolved(UnresolvedRange),
}

pub enum ManifestError {
    NotFound { expected: String },
    ParseError { file: String, detail: String },
}

pub fn manifest_edges_from_tree(
    tree: &FetchedTree,
    ecosystem: Ecosystem,
) -> Result<Vec<ManifestEdge>, ManifestError>
```

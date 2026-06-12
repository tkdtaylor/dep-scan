# ADR 009 — Transitive resolution (ADR 008 piece 4)

**Status:** Proposed
**Date:** 2026-06-11
**Resolves:** ADR 008 piece 4 ("Transitive resolution") and its four *Open
questions* tagged `Transitive: …` and `Cache key for git sources / transitive
provenance`.
**Builds on:** task 096 (`VcsFetcher::fetch` + `FetchedTree`), task 097
(`(name, commit_sha, "git")` cache key + `source_kind` column), task 098
(`run_git_tree_policies` policy pipeline over fetched trees).

## Context

ADR 008 closes dep-scan's two structural blind spots — git/VCS-sourced
dependencies (axis 1) and the absence of any transitive walk (axis 2) — in four
pieces. Pieces 1–3 (git URL detection, the mutable-ref policy, the sandboxed VCS
client) have landed; piece 2's cache key is resolved in ADR 008's *Piece 2 cache
resolution* section (task 097). **Piece 4 — transitive resolution — was
deliberately left as a "separable epic" with genuine unresolved design
questions**, because committing to a resolution algorithm before the cache and
source-kind changes of pieces 1–3 settled risked a design that fights the cache
model.

Those changes have now settled. This ADR resolves *all four* of ADR 008's piece-4
open questions with concrete, non-TBD answers so the epic can be decomposed into
implementation tasks. It does **not** write any `src/` code; it is the design
contract the follow-up tasks implement against.

The four questions, verbatim from ADR 008 *Open questions*:

1. **Transitive: source of truth.** "Lockfile (already-resolved, complete, but
   may omit git sub-trees) vs. each package's own manifest (authoritative for
   edges but requires resolution and re-introduces version-range ambiguity)."
2. **Transitive: depth limit and cycle detection.** "Default max depth; cycle
   handling; performance budget when one scan fans out into hundreds of
   transitive nodes."
3. **Transitive: partial-failure rollup.** "How partial failures (one unfetchable
   node) roll up into the top-level verdict under fail-closed."
4. **Cache key impact.** ADR 008 *Consequences*: "The `(name, version, registry)`
   cache model does not represent … transitive provenance." The current model
   (extended by task 097 to `(name, commit_sha, "git")`) has no representation for
   "this verdict depended on these transitive children."

## Constraints (carried from ADR 008 and the project invariants)

Every decision below is bound by the same standing invariants as ADR 008, and the
design is checked against each:

- **Single static binary, no runtime dependencies.** The walk must not shell out
  to `npm ls`, `pip`, `cargo metadata`, or any language toolchain. Edge discovery
  is done by parsing manifests/lockfiles *we already parse* (or fetch-and-parse),
  in-process — never by invoking an external resolver. (Checked: T-099-11.)
- **Network only on explicit scan.** Reading a transitive manifest that requires a
  fetch (a git sub-tree, or a registry tarball we do not yet have) is a network
  call and happens **only inside the scan path**, never during lockfile parse or
  config load. (Checked: T-099-13.)
- **Fail-closed on unscannable input** (ADR 002/003/008). A transitive node that
  cannot be resolved, fetched, or scanned must **never** silently make its parent
  `Pass`. Worst-verdict-wins, with an unscannable node contributing at least
  `Warn`. (Checked: T-099-12.)
- **Reuse, do not reinvent, the existing identity.** The walk keys nodes, the
  visited set, and the cache on the *same* identity the cache already uses:
  registry deps `(name, version, registry)`, git deps `(name, commit_sha, "git")`
  (task 097, `src/cache.rs:261` `insert_git`). No new identity scheme is
  introduced.

---

## Decision 1 — Source of truth: lockfile-first, manifest-fallback (hybrid, lockfile-preferred)

**Decision: lockfile-first.** When a lockfile is present for an ecosystem, the
lockfile is the authoritative source of the resolved transitive edge set for that
ecosystem's registry deps. The walk reads edges from the lockfile we *already
parse* (`src/lockfile.rs`) and does **not** re-resolve version ranges. We fall
back to parsing a package's **own manifest** for its edges only in the two cases a
lockfile cannot cover:

1. **Git sub-trees.** A git-sourced dependency's transitive children are not in
   the consuming project's lockfile (the lockfile pins the git *commit*, not the
   sub-tree's own dependency graph). Their edges are read from the manifest inside
   the **already-fetched** `FetchedTree` (task 096) — e.g. the `package.json` /
   `Cargo.toml` / `pyproject.toml` materialised in the tree. This reuses the
   bytes piece 2 already pulled; no extra fetch is incurred for the *edge
   discovery* itself.
2. **No lockfile at all.** If the project has no lockfile (manifest-only repo),
   the walk reads direct edges from the top-level manifest and resolves
   transitively from there.

**Why lockfile-first and not manifest-first or pure-hybrid:**

- **It is already-resolved and complete.** A lockfile is the ecosystem's own
  resolver output: every transitive edge is present and pinned to an exact
  version. dep-scan already parses lockfiles into resolved `(name, version)`
  entries — the existing model *is* a flat lockfile reader. Lockfile-first turns
  "scan the flat list" into "walk the graph the lockfile already encodes," which
  is the smallest, most faithful extension of the current code.
- **It sidesteps version-range ambiguity entirely.** Manifest-first would force
  dep-scan to re-run semver resolution (`^1.2.0` → which exact version?) to even
  know *which* node to scan. That re-resolution (a) can disagree with what the
  user actually installed, scanning a *different* artifact than the one on disk —
  a correctness-and-trust regression — and (b) drags in a semver-resolution
  engine, exactly the kind of heavyweight in-process resolver the single-binary
  constraint pushes back on. Lockfile-first scans **the artifact the user
  installed**, which is the whole point of a supply-chain scanner.
- **It avoids the cost of re-resolution.** Re-resolution is both CPU (constraint
  solving) and potentially network (querying the registry for the version set).
  Lockfile-first pays neither: the edges are read straight from a file already in
  hand.

**The trade-off we accept:** a lockfile "may omit git sub-trees" (ADR 008's own
caveat). That is precisely the manifest-fallback case (1) above — and it is not a
real loss, because the git sub-tree's manifest lives in the `FetchedTree` we
already materialised, so we read its edges from there. The only residual gap is a
project that is *manifest-only with unpinned ranges* (case 2 with ranges); there,
to honor "scan what is installed" we do **not** guess a resolution — we record a
`UnresolvedRange` diagnostic for that edge and roll it up fail-closed (at least
`Warn`), rather than scanning a version the user may not have. Choosing a semver
crate to *optionally* resolve such ranges is explicitly deferred to a follow-up
task (and is out of scope here per T-099-09 — no crate is named).

**Reconciliation of the two sources (per T-099-02):** registry edges come from the
lockfile; git sub-tree edges come from the fetched tree's manifest. They are
reconciled by **identity at insertion into the visited set**: every discovered
edge is normalised to the cache identity (`(name, version, registry)` for registry
nodes, `(name, commit_sha, "git")` for git nodes) *before* it is enqueued, so a
node reached via the lockfile and the same node reached via a manifest collapse to
one visited-set entry and are scanned once. The two sources never produce
conflicting verdicts for one node because they resolve to one identity.

---

## Decision 2 — Depth limit, cycle detection, partial-failure rollup

### 2a. Depth limit: default `5`, configurable, fail-closed at the boundary

**Default maximum traversal depth = `5`.** Depth 0 is the set of direct lockfile
entries (today's behavior); each additional level walks one hop further. `5` is
chosen because:

- Empirically, the overwhelming majority of real-world malicious-transitive
  incidents (including the o3forms class ADR 008 motivates) are **one hop** away;
  a clean direct dep pulling a malicious indirect one. Depth `5` covers that and a
  generous margin without committing to "scan the entire universe."
- It bounds fan-out (see Decision 3) to a node count that keeps a scan inside the
  "fast, local-first" promise on a warm cache, while still reaching realistically
  deep payloads.
- It is a single small integer the operator can raise or lower; it is **not** a
  hardcoded constant. The value is read from configuration:
  `[transitive] max_depth = 5` (default `5`), mirroring how `vcs.fetch_timeout_secs`
  and the other `[vcs]` budgets are config-driven in task 096.

**What happens when the limit is reached (per T-099-03):** the walk does **not**
silently stop and call the parent `Pass`. When an edge would cross
`max_depth + 1`, the un-walked subtree root is recorded as a `DepthLimitReached`
diagnostic and the parent's verdict is rolled up **fail-closed to at least
`Warn`** for that edge — never `Pass`. A node beyond the depth limit is, by
definition, "unscanned input," and ADR 008's *Fail-closed on unscannable input*
constraint applies to it exactly as it does to an unfetchable node. The severity
is configurable: `[transitive] on_depth_limit = "warn"` (default) | `"block"`,
following the non-regressive-by-default posture of ADR 002 (warn by default, block
opt-in).

### 2b. Cycle detection: visited-set depth-first search keyed on cache identity

**Algorithm: visited-set DFS (depth-first search) with a path stack**, keyed on
the **same identity the cache uses**. Concretely:

- A `visited: HashSet<NodeId>` records every node already scanned (or in-flight),
  where `NodeId` is the cache identity: `(name, version, registry)` for registry
  nodes, `(name, commit_sha, "git")` for git nodes (task 097). Reusing the cache
  identity means the visited set and the cache agree on what "the same node" is —
  no second notion of identity can drift from the first.
- The walk is depth-first with a `path: Vec<NodeId>` (or a `HashSet` view of the
  current root-to-node path) representing the active DFS stack. Before descending
  into a child, the walker checks the child's `NodeId`:
  - **Already in `visited` but not on the current `path`** → a *diamond / re-visit*
    (the node was reached by another branch and already scanned). The walker
    **does not re-scan**; it reuses the already-computed verdict. This dedup is
    what keeps fan-out tractable (Decision 3).
  - **On the current `path`** → a **cycle**. The walker stops descending,
    records a `CycleDetected` diagnostic naming the back-edge, and does not
    recurse into the already-on-path node again.
- **Direct cycles (A → A)** and **indirect cycles (A → B → A)** are both caught by
  the single "is the child already on the current path?" test (per T-099-04): a
  self-edge puts A on the path and then sees A as its own child; an indirect cycle
  sees A reappear when B descends back into it. No special-casing is needed for
  the two cases — the path-membership test covers both.

**Verdict when a cycle is detected (per T-099-04):** a cycle is **not** a failure
by itself — a package legitimately appearing in a dependency diamond is normal.
The back-edge is simply **not traversed again** (the node it points to has already
been, or is currently being, scanned on this path), and its already-computed
verdict participates in the parent's rollup. So a clean cycle rolls up `Pass`; a
cycle through a node that independently scanned `Warn`/`Block` rolls up that worse
verdict via normal worst-verdict-wins. There is **no** path where breaking a cycle
*invents* a `Pass` for an unscanned node — the node on the path is always one we
are already scanning, never one we skip. This keeps cycle handling consistent with
fail-closed (T-099-12).

### 2c. Partial-failure rollup: worst-verdict-wins, unscannable node ≥ `Warn`

**Decision (per T-099-05):** the transitive verdict for a parent is the
**worst verdict across the parent itself and every node in its scanned subtree**,
using the *same* `aggregate_results` / worst-verdict-wins rule the flat scan
already applies (`src/main.rs`, "worst-verdict-wins aggregation" at the registry
and git arms). When a transitive node cannot be **fetched** (git fetch failure —
already fail-closed to `Warn`/`Block` in the git arm at
`src/main.rs:1081-1094`), cannot be **resolved** (an `UnresolvedRange` edge), or is
cut off by the **depth limit**, that node contributes **at least `Warn`** (or
`Block` under the relevant `… = "block"` config) to its parent's rollup — it is
**never** treated as `Pass`.

This is a strict generalisation of the existing single-node fail-closed rule to
the tree: ADR 008 already established that *one* unfetchable git dep is `Warn`/
`Block`, never `Pass`; this ADR says the same node, when it is a *transitive
child*, propagates that floor up to its ancestors. An attacker therefore cannot
hide a malicious node by making it unfetchable, nor by burying it past the depth
limit, nor inside a cycle — every one of those is fail-closed (T-099-12).

The propagation is "worst wins, monotonically upward": a child verdict can only
raise (never lower) an ancestor's verdict. A `Block` anywhere in the subtree makes
the root `Block`; a `Warn` (or any unscannable node) makes the root at least
`Warn` unless something worse already won.

---

## Decision 3 — Performance estimate and mitigations

### 3a. Worst-case node count and fetch-time estimate at depth 5

The fan-out concern ADR 008 names — "one scan fans out into hundreds of transitive
nodes" — is real and is in **direct tension with the "fast, local-first" product
promise** (ADR 008 *Consequences*: transitive scanning "risks slow scans —
directly in tension with the 'fast, local-first' product promise"). We name that
tension explicitly and design the mitigations around it.

**Naïve worst case (no dedup):** with branching factor `b` (direct deps per node)
and depth `d`, the tree has up to `b^0 + b^1 + … + b^d ≈ b^(d+1)` nodes. For a
typical npm package with `b ≈ 10` and `d = 5`:

```
1 + 10 + 100 + 1 000 + 10 000 + 100 000  ≈  111 111 nodes  (naïve, no dedup)
```

That is the number the "hundreds → tens of thousands" worry points at, and it is
why an undeduplicated walk is a non-starter.

**Realistic worst case (with visited-set dedup, Decision 2b):** real dependency
graphs are *graphs, not trees* — the same packages recur across branches. After
deduplication on the cache identity, the relevant bound is the count of **distinct
packages reachable within depth 5**, which for almost all real projects is in the
**low hundreds to low thousands**, not 10^5. Empirically a large npm project's
*entire* resolved graph (all depths) is typically 1–3k distinct packages, so depth
5 with dedup is bounded by roughly that whole-graph size:

```
≈ 1 000–3 000 distinct nodes  (deduped, whole large project)
```

**Fetch-time estimate.** Registry nodes that already appear in the project's
lockfile incur **no extra network fetch for edge discovery** (lockfile-first,
Decision 1) — their edges are read from the file. The costly nodes are **git
sub-trees** that must be fetched (task 096). At the task-096 default
`vcs.fetch_timeout_secs = 30` worst case per git fetch, but a realistic warm fetch
of a small repo in the low hundreds of milliseconds:

```
Registry edge read:        ~0 ms network (lockfile already parsed)
Git sub-tree fetch (warm): ~100–500 ms each
Git sub-tree fetch (cap):   30 s each (vcs.fetch_timeout_secs ceiling)
```

For a project with, say, 20 distinct git sub-trees at depth ≤ 5 on a **cold**
cache: `20 × ~300 ms ≈ 6 s` of git fetching, parallelised down (Decision 3b). On a
**warm** cache (immutable SHAs cache-hit per task 097), that drops to near-zero.
The pathological case — many distinct git sub-trees, all cold — is bounded by the
concurrency model and the per-fetch timeout, not unbounded.

### 3b. Mitigations (specific enough to scope tasks)

1. **Depth-limit enforcement (Decision 2a).** `max_depth = 5` caps the tree before
   it can reach 10^5 nodes. This is the first and hardest bound.
2. **Dedup via the visited set (Decision 2b).** Collapsing the graph on the cache
   identity turns the `b^(d+1)` tree into the (low-thousands) distinct-node graph.
   This is the single largest factor; it is *not* optional — without it depth 5 is
   infeasible.
3. **Reuse of the `(name, commit_sha, "git")` / `(name, version, registry)`
   cache (task 097).** Every node consults the cache *before* fetching or
   re-scanning. An immutable git SHA or a previously-scanned registry version is a
   verified cache hit (subject to the task-030 hash gate), so a warm re-scan of a
   large transitive graph is dominated by cache lookups, not fetches. Mutable refs
   are never cached (task 097) and always re-fetched — the one deliberate
   exception, consistent with fail-closed.
4. **Bounded concurrency.** Git sub-tree fetches (the only network cost) run on a
   **bounded worker pool** (a fixed concurrency limit, e.g. a configurable
   `[transitive] fetch_concurrency`, default a small N like 4–8) so a wide tree
   fetches in parallel without opening unbounded sockets. This composes with the
   per-fetch `vcs.fetch_timeout_secs` and the task-096 pack-size budgets, so total
   work is bounded by (timeout × ceil(distinct_git_nodes / concurrency)). The
   pool's *model* is fixed here; the *crate* (thread pool vs. async runtime) is a
   follow-up implementation choice (T-099-09 — not named here).
5. **Per-scan node budget (defence-in-depth).** A `[transitive] max_total_nodes`
   ceiling (default a few thousand) fails the *scan* closed with a diagnostic if a
   pathological graph blows past the deduped estimate, mirroring task 096's
   aggregate `max_total_files` / `max_total_bytes` budgets. This guarantees a hard
   upper bound on work even if the depth limit and dedup are somehow both
   defeated.

All five mitigations stay inside the single binary and only fetch on the explicit
scan path (T-099-11/13).

---

## Decision 4 — Cache key impact: bind the cached verdict to its scanned subtree

**The problem (ADR 008's open question).** Today a row is keyed
`(name, version, registry)` or `(name, commit_sha, "git")` and stores a single
verdict (`src/cache.rs`). That verdict, under transitive scanning, **depends on the
verdicts of the node's children**: a parent that scanned `Pass` did so *because*
its subtree scanned clean. If a child later turns malicious (e.g. a mutable git
sub-tree flips, or a child's own cache entry is invalidated), the parent's cached
`Pass` is now **stale and unsafe** — but nothing in the current key invalidates it.
A naïve "cache the parent verdict" scheme would re-serve a `Pass` for a parent
whose subtree is no longer clean: a fail-closed violation.

**Decision: a subtree-digest binding, additive and idempotent.** Extend the cache
row (additive `ALTER TABLE … ADD COLUMN`, exactly as tasks 029/032/097 did — only
when absent, no backfill, legacy rows read `NULL`) with **one new nullable
column**:

- `subtree_digest TEXT` — a `sha256:<hex>` digest computed over the **sorted set
  of child `NodeId`s and their verdicts** that the parent's verdict depended on.
  Concretely: for each direct child, take `(child_NodeId, child_verdict)`, sort
  deterministically, length-frame, and hash (reusing the framing discipline of
  `git_tree_content_hash` in `src/main.rs:152`). This digest is the *fingerprint
  of the subtree state the parent verdict was computed against.*

**Validity rule (fail-closed).** A cached transitive verdict for a node is a
**Hit** only if **both**:

1. the existing task-030 content-hash gate passes for the node itself (unchanged),
   **and**
2. the node's **recomputed** `subtree_digest` (from the *current* verdicts of its
   children) **equals** the stored `subtree_digest`.

If the subtree digest differs — because a child's verdict changed, a child was
added/removed, or a mutable-ref child re-fetched to a different tree — the parent's
cached row **fails the gate and the parent is re-scanned** (fail-closed), exactly
like a content-hash mismatch forces a re-fetch today (`verify_hash` in
`src/main.rs`). Because the digest is computed *bottom-up* (children before
parents, which the DFS post-order already gives us), a changed leaf naturally
propagates: the leaf's verdict changes → its parent's recomputed subtree digest no
longer matches the stored one → the parent re-scans → its verdict (and digest)
may change → the grandparent invalidates, and so on up to the root. **Invalidation
propagates upward by construction**, with no explicit dependency-tracking table to
keep consistent.

**Why a digest column and not a join table / dependency edges table:**

- It is **additive and idempotent** — one nullable column, the same migration
  shape the codebase has used three times (029/032/097), no schema redesign, no
  backfill, legacy and registry rows keep working with `subtree_digest = NULL`
  (which simply means "no transitive dependency was recorded for this verdict" —
  the flat-scan behavior, preserved exactly).
- It reuses the **existing fail-closed verify-then-honor cache discipline** (task
  030/097): "recompute a digest, compare to the stored one, mismatch ⇒ re-scan."
  No new invalidation mechanism is invented; the subtree digest is just a second
  fingerprint checked alongside the content hash.
- **Mutable-ref children stay uncacheable** (task 097): a mutable git sub-tree is
  never written to cache, so any parent depending on it can never produce a stable
  subtree digest and is itself effectively re-scanned each time — which is the
  correct fail-closed behavior for "the parent's safety depends on a thing that can
  change under us."

**Performance implication (per T-099-06).** Validating a cached parent requires
reading its children's current verdicts to recompute the subtree digest. Those
child lookups are themselves cache hits (cheap SQLite reads), so a warm re-scan is
"`N` lookups + `N` digest recomputations," not "`N` re-fetches." The cost of the
binding is bounded by the cache read path, not the fetch path — preserving the
warm-cache speed that mitigation 3 (Decision 3b) relies on.

---

## Follow-up implementation tasks (per T-099-08 / REQ-099-05)

This spike enables the following implementation tasks. These are **scope stubs**,
not backlog task files (the task-planner promotes them after this ADR is
accepted). Each is sized to the project's "one task, one responsibility" rule and
ordered by dependency.

1. **Transitive edge model + lockfile graph reader (Decision 1).** Extend
   `src/lockfile.rs` to expose the *edges* between resolved entries (not just the
   flat list) for the existing ecosystems, building the in-memory dependency graph
   from the lockfile. Scope: medium. Pure parsing; no network. *Depends on:* —.

2. **Manifest edge reader for fetched git sub-trees (Decision 1, fallback).** Read
   a `FetchedTree`'s own manifest (`package.json` / `Cargo.toml` / `pyproject`)
   to discover a git sub-tree's direct edges, normalising each to a cache
   `NodeId`. Scope: medium. Reuses task-096 `FetchedTree`; no extra fetch for edge
   discovery. *Depends on:* (1).

3. **Visited-set DFS walker with depth limit + cycle detection (Decision 2a/2b).**
   The core traversal: DFS keyed on the cache `NodeId`, `visited` dedup,
   path-stack cycle detection, `max_depth`/`on_depth_limit` config, and the
   `DepthLimitReached` / `CycleDetected` / `UnresolvedRange` diagnostics. Scope:
   large. *Depends on:* (1), (2).

4. **Transitive verdict rollup (Decision 2c).** Wire each scanned node's verdict
   into worst-verdict-wins propagation up the DFS post-order, with the
   unscannable-node ≥ `Warn` floor. Reuse `aggregate_results`. Scope: medium.
   *Depends on:* (3).

5. **Bounded-concurrency git fetch pool + per-scan node budget (Decision 3b).**
   The fetch concurrency limit (`[transitive] fetch_concurrency`) and the
   `max_total_nodes` safety ceiling. Scope: medium. *Depends on:* (3).

6. **`subtree_digest` cache column + bottom-up invalidation (Decision 4).**
   Additive migration in `src/cache.rs`, `insert`/`insert_git` extension to write
   the digest, and the two-gate (content-hash + subtree-digest) lookup validity
   check. Scope: medium. *Depends on:* (3), (4).

7. **`[transitive]` config block + CLI flag (Decisions 2a/3b).** `max_depth`,
   `on_depth_limit`, `fetch_concurrency`, `max_total_nodes`, and an enable/disable
   switch (transitive scanning gated behind config so the flat-scan default is
   non-regressive). Scope: small. *Depends on:* (3).

8. **(Deferred / optional) Manifest range resolution for lockfile-less projects.**
   Optionally resolve unpinned ranges in manifest-only repos instead of emitting
   `UnresolvedRange`. Requires choosing a semver resolution crate (deliberately
   *not* chosen here — T-099-09). Scope: large; lowest priority. *Depends on:*
   (3).

---

## Consistency check against ADR 008 constraints (explicit)

- **Single binary (T-099-11):** edge discovery is in-process lockfile/manifest
  parsing; no `npm ls` / `cargo metadata` / language toolchain is invoked. The
  fetch path reuses the task-096 pure-Rust `gix` client. ✔
- **Fail-closed (T-099-12):** every gap — unfetchable node, depth-limit cut,
  unresolved range, cache-stale parent — rolls up to **at least `Warn`**, never
  `Pass`. No path lets an unresolvable transitive dep silently pass. ✔
- **Network only on explicit scan (T-099-13):** edge discovery for registry deps
  reads an already-parsed lockfile (no I/O); git sub-tree fetches happen only
  inside the scan path via the task-096 client, never during lockfile parse or
  config load. ✔
- **No premature crate choice (T-099-09):** the design names *algorithms*
  (visited-set DFS, worst-verdict-wins, subtree-digest binding) and *config
  shapes*, not Rust crates. Semver-resolution and thread-pool/async-runtime crate
  selection are explicitly left to follow-up tasks. ✔

## References

- [ADR 008](008-git-vcs-dependency-handling.md) — git/VCS handling; **piece 4
  (transitive resolution)** and its *Open questions* (`Transitive: source of
  truth`, `Transitive: depth limit and cycle detection`, cache-key impact) that
  this ADR resolves; *Piece 2 cache resolution* (task 097) for the
  `(name, commit_sha, "git")` key this ADR's `NodeId` reuses.
- [ADR 002](002-detection-strategy.md) — non-regressive-by-default policy posture
  (warn default, block opt-in) reused for `on_depth_limit`.
- [ADR 003](003-content-hash-cache-integrity.md) — fail-closed cache posture and
  the verify-then-honor discipline the `subtree_digest` gate extends.
- `src/cache.rs:115-170` — `scanned_packages` schema and the additive-migration
  pattern (029/032/097) the `subtree_digest` column follows;
  `src/cache.rs:261` `insert_git` — the `(name, commit_sha, "git")` key reused as
  the git `NodeId`.
- `src/main.rs:152` `git_tree_content_hash` — the length-framed hashing discipline
  reused for the subtree digest; `src/main.rs:177` `run_git_tree_policies` — the
  per-node policy pipeline each walked node runs; `src/main.rs:1066,1081-1094` —
  the worst-verdict-wins aggregation and the single-node fail-closed rule this ADR
  generalises to the tree.

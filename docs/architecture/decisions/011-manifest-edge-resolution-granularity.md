# ADR 011 — Manifest edge resolution granularity (Resolved only for git+rev)

**Status:** Accepted
**Date:** 2026-06-11
**Builds on:** [ADR 009](009-transitive-resolution.md) Decision 1 (lockfile-first,
manifest-fallback), task 101 (manifest edge reader for fetched git sub-trees).
**Resolves:** the open question surfaced during task 101 implementation — when the
manifest edge reader returns a `ManifestEdge::Resolved(NodeId)` versus a
`ManifestEdge::Unresolved(UnresolvedRange)`.

## Context

Task 101 reads a fetched git sub-tree's own manifest (`package.json` / `Cargo.toml`)
to discover its direct dependency edges. A manifest expresses dependency versions as
**ranges**, not exact pins:

- npm `package.json`: `"lodash": "^4.17.0"` — a range.
- Cargo string form: `serde = "1.0"` — Cargo interprets this as `^1.0`, a range.
- Cargo table form: `tokio = { version = "1" }` — also a range (`^1`).
- Cargo git dep with `rev`: `{ git = "…", rev = "abc123" }` — a **pinned commit SHA**.
- Cargo git dep without `rev`: `{ git = "…" }` — a moving ref, **not pinned**.

The first task-101 implementation classified Cargo *string* deps as `Unresolved`
but Cargo *table-with-version* deps as `Resolved(NodeId::Registry)`. That split is
on manifest *syntax* (string vs table), not on whether the version is actually
**pinned** — `serde = "1.0"` and `tokio = { version = "1" }` are both ranges, so
classifying one Resolved and the other Unresolved is inconsistent and, worse,
manufactures a `NodeId::Registry { version: "1" }` whose `version` field holds a
**range string**, not the exact version the user installed.

ADR 009 Decision 1 is explicit that the scanner must not guess a resolution: it
scans *the artifact the user installed*, and for an unpinned manifest range it
records an `UnresolvedRange` diagnostic and rolls up fail-closed (≥ `Warn`) rather
than scanning a version the user may not have. Reliably deciding "is this spec an
exact pin or a range?" requires **semver parsing** — and ADR 009 (T-099-09) and
task 109 deliberately defer choosing a semver-resolution crate. Without that crate
the reader cannot safely distinguish `"=1.2.3"` (exact) from `"1.2.3"` (range
`^1.2.3`) in the general case.

## Decision

**The manifest edge reader emits `ManifestEdge::Resolved` only when a concrete
pinned identity is available without semver parsing. In practice that is exactly
one case: a Cargo git dependency with an explicit `rev = "<sha>"`, which yields
`NodeId::Git { name, commit_sha }`. Every other manifest edge is
`ManifestEdge::Unresolved(UnresolvedRange { name, range })`:**

| Manifest edge | Classification | NodeId |
|---|---|---|
| Cargo git dep with `rev = "<sha>"` | `Resolved` | `NodeId::Git { commit_sha }` |
| Cargo git dep without `rev` | `Unresolved` | — (range = git URL) |
| Cargo registry dep (string `serde = "1.0"`) | `Unresolved` | — (range = `"1.0"`) |
| Cargo registry dep (table `{ version = "1" }`) | `Unresolved` | — (range = `"1"`) |
| npm `dependencies` entry | `Unresolved` | — (range = the spec string) |

`UnresolvedRange.range` stores the version specifier verbatim (or the git URL for a
rev-less git dep), so a later resolver (task 109, once a semver crate is chosen) or
a lockfile (task 100, lockfile-first) can resolve it. devDependencies are excluded
(runtime edges only).

## Consequences

- **Consistent and fail-closed.** Classification depends on whether a *pinned
  identity exists*, not on manifest syntax. Every unpinned edge becomes an
  `UnresolvedRange` the walker rolls up ≥ `Warn` (ADR 009 Decision 2c) — an attacker
  cannot smuggle a malicious transitive dep through an unpinned manifest range,
  because an unpinned range is never silently `Pass`.
- **No invented identities.** The reader never produces a `NodeId::Registry` whose
  `version` is a range string, so the visited-set/cache identity (ADR 009: reuse the
  cache identity) always denotes an exact artifact, never a range.
- **Noisier on git sub-trees, by design.** A git sub-tree whose registry deps are
  not in the consuming project's lockfile yields all-`Unresolved` edges (≥ `Warn`).
  This is the correct fail-closed outcome: those versions are genuinely unknown
  until lockfile-first (task 100) pins them or the deferred resolver (task 109)
  resolves them. The common case — registry deps present in the project lockfile —
  is handled by the lockfile graph reader (task 100), not this path.
- **No semver crate pulled in early.** Honoring T-099-09: the reader needs no
  range-vs-pin parsing, so no semver-resolution crate is required for task 101.

## References

- [ADR 009](009-transitive-resolution.md) — Decision 1 (lockfile-first /
  manifest-fallback; "scan what is installed"; `UnresolvedRange` + ≥ `Warn` for
  unpinned ranges), T-099-09 (no premature crate choice).
- Task 101 test spec — `ManifestEdge` / `UnresolvedRange` / `ManifestError` type
  contracts and T-101-01..12 assertions updated to this rule.
- Task 109 — deferred semver range resolution (the eventual home of range→pin).

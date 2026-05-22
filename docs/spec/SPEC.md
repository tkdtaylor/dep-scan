# dep-scan — Authoritative Spec

**Project:** dep-scan
**Last updated:** 2026-05-22 (v1.2.0)

## What this directory is

`docs/spec/` is the **authoritative current-state snapshot** of dep-scan. It answers the question:

> "If the code were deleted tomorrow, what would I need to write down to rebuild it?"

The spec is dual-natured:

- **Output of current sessions** — every completed task that changes externally-observable behavior, the data model, an interface, or configuration MUST update the relevant spec file in the same commit.
- **Input to future sessions** — used for onboarding, drift audits against the code, and (in the limit) regenerating the codebase from scratch.

The code is one *realization* of this spec. If the spec and code disagree, one of them is wrong — fix the wrong one in that same change.

## Spec vs. ADRs vs. overview

| Doc | Purpose | Lifecycle |
|-----|---------|-----------|
| [`docs/spec/`](.) | What the system **does and is** today | Snapshot — supersede in place, never append |
| [`../architecture/decisions/`](../architecture/decisions/) | **Why** decisions were made | Append-only history; ADRs can be superseded by later ADRs |
| [`../architecture/overview.md`](../architecture/overview.md) | Narrative tour of the system | Snapshot, optimized for human reading |
| [`../architecture/diagrams.md`](../architecture/diagrams.md) | Visual structure and flows | Snapshot, part of the spec |

When [ADR 003](../architecture/decisions/003-content-hash-cache-integrity.md) describes the rationale for content-hash verification, the spec just records the resulting rules. The ADR preserves the reasoning trail; the spec preserves the current truth.

## The six sub-files

| File | Covers | Read this when |
|------|--------|---------------|
| [behaviors.md](behaviors.md) | What the system does — user-facing behaviors, policy verdicts, verification pipelines | You need to know what should happen when X |
| [architecture.md](architecture.md) | C4 element catalog — persons, systems, containers, components, cross-cutting decisions | You need a structured / queryable view of the architecture (paired with [`../architecture/diagrams.md`](../architecture/diagrams.md)) |
| [data-model.md](data-model.md) | Cache schema, content-hash format, in-memory `ScanContext` / `PackageMetadata` shape | You need to know what data exists and how it's structured |
| [interfaces.md](interfaces.md) | CLI surface, exit codes, JSON output schema, `Registry` + `Policy` traits, `RegistryError` variants | You need to know what calls into or out of the system |
| [configuration.md](configuration.md) | Layered config (defaults < TOML < env < CLI), env vars, defaults | You need to know what's tunable |
| [fitness-functions.md](fitness-functions.md) | Security invariants — the 27 `F-NNN` contracts the code must always satisfy | You're adding a continuous check, or wondering which test pins which invariant |

## Reading order

For a first reader:

1. **behaviors.md** — what dep-scan does (CLI flow, 11 policies, verification pipelines).
2. **interfaces.md** — the exact surface the user interacts with.
3. **data-model.md** — what dep-scan remembers between runs.
4. **fitness-functions.md** — the security invariants those three layers must never violate.

The remaining files (architecture, configuration) are deep-dives for the people working on those subsystems.

## How the spec is kept honest

- Every spec entry **MUST** be enforced by at least one test case. The test case carries a `T-NNN-NN` marker that points back to its origin task in [`../tasks/test-specs/`](../tasks/test-specs/). Adding a new spec line without an accompanying test marker is forbidden.
- When the code changes a contractual behavior, the spec is updated in the **same PR**. A drift audit (see `audit-project.md` in `$CLAUDE_SKILL_DIR/references/`) is run after every batch of LOW / MEDIUM / HIGH security tasks and before every release tag.
- Behaviors that are *descriptive* (current code structure, current dependency choices) live in `docs/architecture/`, not here. The spec is for contracts that the user, the policy pipeline, the cache, or the trust roots depend on.

## Versioning and stability

The spec is versioned alongside the dep-scan release tag. The current spec is **v1.2.0**. Breaking spec changes (e.g. changing a `Block` policy to `Warn`, dropping a CLI flag, changing the cache decision matrix) MUST increment the major or minor version per [SemVer](https://semver.org/spec/v2.0.0.html). Adding new flags, new policies, or new env vars in a backwards-compatible way is a patch or minor bump.

## System invariants (one-line summary)

The full list with verifying tests is in [fitness-functions.md](fitness-functions.md). The non-negotiables:

1. **Fail-closed verification.** Content-hash verification runs on every cache hit. `--force` does not bypass it. There is no flag to skip it.
2. **Input validation before subprocess / URL composition.** Package-name tokens starting with `-`, Go module paths, Go version strings, and PyPI provenance URLs are all validated *before* any subprocess or network operation that consumes them.
3. **Trust roots are pinned at build time.** Sigstore (Fulcio + Rekor) and sum.golang.org keys are embedded in the binary. Rotation requires a release. No runtime download of trust material is permitted.
4. **SHA-1 is structurally untrusted as a cache gate.** Cached `sha1:` rows always re-scan. New `pass`/`warn` rows for sha1-only packages store `NULL`.
5. **Local-first.** No network calls except when the user explicitly invokes a scan. No telemetry.

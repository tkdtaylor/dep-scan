# Task 090 — Dependency source model (`DependencySource` enum)

**Status:** backlog
**Depends on:** (none — foundational data-model change)
**ADR:** 008 (piece 1 — detect git/VCS URLs in lockfiles; data model prerequisite)
**Touches:** `src/lockfile.rs` (new enum + updated struct), `src/main.rs` (caller
            update to use `source` field)

## Objective

Introduce a `DependencySource` enum that distinguishes registry-sourced from
git-sourced dependencies, and embed it as a `source` field on
`LockfileDependency` (replacing the current flat `registry: RegistryType` field).
This is the pure data-model change that all subsequent ADR 008 tasks depend on.
No new parsing logic is added here; existing parsers continue to emit
`DependencySource::Registry` entries exactly as before.

## Background

`LockfileDependency` today has `registry: RegistryType`, which can only represent
npm/PyPI/crates/Go sources. When a git dep is later parsed (tasks 091/092), there
is nowhere to put the URL or ref — hence the model must change first. The scan
loop in `src/main.rs` routes every dep through a registry client by matching on
`RegistryType`; after this task it matches on `DependencySource::Registry` (same
logic, renamed). `DependencySource::Git` deps produced by future tasks pass
through a different arm (introduced in task 093).

## Requirements

### REQ-090-01: `DependencySource` enum
Add `pub enum DependencySource` to `src/lockfile.rs`:

```
DependencySource::Registry { registry: RegistryType }
DependencySource::Git { url: String, ref_: String }
```

The enum derives `Debug`, `Clone`, `PartialEq`. Provide accessor methods:
- `fn registry_type(&self) -> Option<RegistryType>`
- `fn git_ref(&self) -> Option<&str>`
- `fn git_url(&self) -> Option<&str>`

### REQ-090-02: `LockfileDependency` updated
Replace the `pub registry: RegistryType` field with `pub source: DependencySource`.
Update all four parsers to construct `DependencySource::Registry { registry: … }`
where they previously set `registry:`. No behavior change.

### REQ-090-03: All callers in `src/main.rs` compile cleanly
Update `PackageRef::from_lockfile_dep` and the scan loop to use `dep.source`
instead of `dep.registry`. The routing logic for existing registry-type deps must
be functionally identical after the rename.

### REQ-090-04: No silent drops
The refactor must not introduce any new silent-drop or panic paths. A
`DependencySource::Git` dep arriving in the scan loop from a future task must not
be silently discarded — implement a safe fallback (e.g. a no-op arm that logs a
warning) so this task's diff is complete without blocking on task 093's routing
work. That fallback is replaced by real routing in task 093.

## Acceptance criteria

- [ ] `DependencySource` enum exists with `Registry` and `Git` variants
- [ ] `LockfileDependency` has `source: DependencySource`, no `registry` field
- [ ] All four parsers produce `DependencySource::Registry` deps unchanged
- [ ] `cargo build` exits 0 (confirms removed `registry` field is fully migrated)
- [ ] `dep.registry` access does not compile (breaking change is intentional)
- [ ] Scan loop routes registry deps identically to before
- [ ] A `DependencySource::Git` dep in the scan loop does not panic (safe fallback)
- [ ] All T-090-01 through T-090-15 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/090-dependency-source-model-test-spec.md`

## Out of scope

- Actually parsing git URLs from npm/Cargo lockfiles (tasks 091/092)
- Surfacing git deps in scan output (task 093)
- Mutable-ref policy (task 094)
- Any VCS fetch logic

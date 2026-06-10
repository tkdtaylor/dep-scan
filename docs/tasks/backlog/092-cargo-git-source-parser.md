# Task 092 — Cargo lockfile git source parser

**Status:** backlog
**Depends on:** 090 (`DependencySource::Git` variant exists)
**ADR:** 008 (piece 1 — detect git/VCS URLs in lockfiles; Cargo side)
**Touches:** `src/lockfile.rs` (`parse_cargo_lock` only)

## Objective

Teach `parse_cargo_lock` to distinguish `git+` source entries from `registry+`
source entries, emitting `DependencySource::Git` for git-sourced crates instead
of mis-classifying them as `RegistryType::Crates`. Entries with no source field
(local path deps) continue to be skipped.

## Background

A Cargo.lock `source` field has one of three forms:
- Absent — local path dependency (skip, no change)
- `registry+<url>` — published to a registry (emit `Registry(Crates)`, no change)
- `git+<url>#<rev>` — fetched from a git repo (emit `Git`)

The current parser (lines 199–227 of `src/lockfile.rs`) already checks for the
presence of `source` to skip local deps, but does not distinguish `registry+` from
`git+`, so all non-local entries become `Crates` deps. This task adds that
distinction.

The `git+` prefix is a scheme modifier (mirroring npm's convention); it must be
stripped when storing the URL. The `#<rev>` fragment is the commit/tag/branch ref.
Cargo also supports `?branch=`, `?tag=`, and `?rev=` query parameters in the
source field; these must be preserved in the stored URL (they carry intent even
if the ref fragment supersedes them for pinning purposes).

## Requirements

### REQ-092-01: Distinguish `git+` from `registry+` source prefixes
When `source` is present and starts with `git+`, emit
`DependencySource::Git { url, ref_ }`. When it starts with `registry+`, emit
`DependencySource::Registry { registry: RegistryType::Crates }`. Unknown prefixes
are skipped without panic (fail-safe for future VCS types).

### REQ-092-02: Strip `git+` prefix; split `#` fragment as ref
Store the URL portion (after stripping `git+`) as `url`. The fragment after `#`
is `ref_`. If no `#` is present, `ref_` is an empty string.

### REQ-092-03: Query parameters in source URL are preserved
`?branch=`, `?tag=`, `?rev=` query strings form part of the URL component, not
the ref. They must be stored in `url`, not discarded.

### REQ-092-04: Version field is not required for git entries
A git-sourced crate may have an arbitrary or empty version field. The entry must
not be skipped solely because version is empty (the skip-if-no-source guard is
sufficient for local deps; the version guard should not apply to git sources).

### REQ-092-05: Local path deps (no source field) continue to be skipped
No behavior change for entries without a `source` key.

## Acceptance criteria

- [ ] `registry+` entries emit `DependencySource::Registry(Crates)`
- [ ] `git+https://` entries emit `DependencySource::Git`
- [ ] `git+ssh://` entries emit `DependencySource::Git`
- [ ] `git+` prefix stripped from stored URL; `#ref` split into `ref_`
- [ ] `?branch=`/`?tag=`/`?rev=` query params preserved in stored URL
- [ ] Entry with empty version + git source is emitted (not skipped)
- [ ] Entries with no `source` field still skipped
- [ ] Unknown source prefix skipped without panic
- [ ] All T-092-01 through T-092-16 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/092-cargo-git-source-parser-test-spec.md`

## Out of scope

- npm git URL parsing (task 091)
- Surfacing git deps in scan output (task 093)
- Mutable-ref policy (task 094)
- go.sum does not have a git-source concept in its lockfile format — no changes
  to `parse_go_sum`
- Any network fetch

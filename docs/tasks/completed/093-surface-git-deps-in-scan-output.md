# Task 093 — Surface git deps in scan output

**Status:** backlog
**Depends on:** 090 (source model), 091 (npm parser), 092 (Cargo parser)
**ADR:** 008 (piece 1 — visibility deliverable; closes the silent-drop / mis-route)
**Touches:** `src/main.rs` (scan loop routing), `src/types.rs` (if `CheckResult`
            needs a display-version field; assess during implementation)

## Objective

Wire `DependencySource::Git` dependencies through the scan loop so they produce
a `Warn` verdict with a message naming the URL and ref, instead of being silently
dropped or crashing. This is the piece-1 visibility deliverable from ADR 008:
dep-scan now *sees* git deps and tells the user about them. No code fetch occurs.

## Background

After tasks 090/091/092, the `all_packages` vector in `src/main.rs` may contain
entries with `DependencySource::Git`. The task-090 safe fallback stub handles
them without panic, but it does not produce useful output. This task replaces
that stub with real routing: a dedicated arm in the scan loop that constructs a
`Warn` `CheckResult` with a message describing the git source.

The ADR's fail-closed posture requires that a git dep not be passed silently
when it cannot be scanned (no VCS fetch yet). `Warn` is the appropriate default:
it surfaces the dep without blocking installs by default, consistent with the
"non-regressive by default" pattern from ADR 002.

## Requirements

### REQ-093-01: Dedicated git-dep arm in the scan loop
In `src/main.rs`, add a `DependencySource::Git` arm that constructs a `CheckResult`
with:
- `verdict: Verdict::Warn`
- `message` containing the URL and ref
- `package_name` matching `dep.name`
- A display version that uses the ref (e.g. the commit SHA or branch name) so
  the output row is human-readable

### REQ-093-02: Git dep does not reach any registry client
The `DependencySource::Git` arm must return before any registry client is
instantiated or called. Zero network calls for git deps in this task.

### REQ-093-03: Verdict is never `Pass` for an unscanned git dep
The `Warn` verdict must not be downgraded to `Pass` by any code path in this
task. The message must make clear the dep is git-sourced and has not been
fetched/scanned yet.

### REQ-093-04: Registry dep routing is unchanged
The `DependencySource::Registry` arm must be functionally identical to the
pre-task scan loop routing.

### REQ-093-05: Output formats include git dep rows
Both `--format native` and `--format json` must include a row/element for each
git dep with its warn verdict and message.

## Acceptance criteria

- [ ] A git dep in a lockfile produces a `Warn` verdict with URL + ref in message
- [ ] Zero registry client calls for git deps
- [ ] Exit code non-zero when git dep is present (at least one `Warn`)
- [ ] Git dep appears in `--format native` and `--format json` output
- [ ] Multiple git deps each produce individual `Warn` verdicts
- [ ] Registry deps are unaffected
- [ ] All T-093-01 through T-093-13 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/093-surface-git-deps-in-scan-output-test-spec.md`

## Out of scope

- Mutable-ref policy (task 094 — layers on top of this visibility)
- VCS fetch / sandboxing (task 097)
- Cache integration for git sources (task 098)
- Any host allow/deny policy (task 096)

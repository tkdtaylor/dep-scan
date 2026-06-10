# Task 091 — npm lockfile git URL parser

**Status:** backlog
**Depends on:** 090 (`DependencySource::Git` variant exists on `LockfileDependency`)
**ADR:** 008 (piece 1 — detect git/VCS URLs in lockfiles; npm side)
**Touches:** `src/lockfile.rs` (`parse_package_lock_json` + helper functions)

## Objective

Teach `parse_package_lock_json` to recognise git-sourced npm dependencies from
the `resolved` field and emit `DependencySource::Git` entries instead of
dropping them or mis-routing them to the npm registry. Handle all URL forms npm
uses: `git+https://`, `git+ssh://`, `git+http://`, and the shorthand forms
`github:user/repo#ref`, `gitlab:user/repo#ref`, `bitbucket:user/repo#ref`.

## Background

The npm parser currently skips any entry with an empty `version` field (lines
88–95 of `src/lockfile.rs`). git dependencies often have either no version or a
placeholder SemVer string; the `resolved` field is the authoritative source. When
a git `resolved` URL is present, the entry must be classified as
`DependencySource::Git` regardless of what `version` contains.

The `git+` prefix in npm `resolved` URLs is a scheme modifier, not part of the
actual URL; it must be stripped when storing the URL in `DependencySource::Git`.
The fragment after `#` is the ref (commit SHA, branch, or tag).

Shorthand forms (`github:`, `gitlab:`, `bitbucket:`) must be expanded to their
canonical HTTPS URLs so downstream tasks (e.g. host-policy validation in task
096) operate on a uniform representation.

## Requirements

### REQ-091-01: Detect git resolved URLs in v2/v3 and v1 formats
Both the `packages` (v2/v3) and `dependencies` (v1) parsers must inspect the
`resolved` field and classify the entry as `Git` when the field starts with
`git+https://`, `git+ssh://`, `git+http://`, or one of the shorthand prefixes
(`github:`, `gitlab:`, `bitbucket:`).

### REQ-091-02: Strip `git+` scheme prefix, extract ref from `#` fragment
For `git+<scheme>://…#<ref>` forms: store `<scheme>://…` as `url` and `<ref>` as
`ref_`. If there is no `#`, store `ref_` as an empty string.

### REQ-091-03: Expand shorthand forms to canonical HTTPS URLs
- `github:user/repo#ref` → `url = "https://github.com/user/repo"`, `ref_ = "ref"`.
- `gitlab:user/repo#ref` → `url = "https://gitlab.com/user/repo"`.
- `bitbucket:user/repo#ref` → `url = "https://bitbucket.org/user/repo"`.

No hardcoded additional hosts beyond these three established shorthand forms.

### REQ-091-04: Entry previously dropped due to empty version is now emitted
When `resolved` is a git URL, the entry is emitted as a `Git` dep regardless of
whether `version` is empty. The version-is-empty guard must not apply to
git-resolved entries.

### REQ-091-05: Non-git `resolved` URLs continue to produce Registry deps
Existing `https://registry.npmjs.org/…` resolved URLs must not be affected.
Entries without a `resolved` field continue to behave as before.

### REQ-091-06: Degenerate input does not panic
Malformed `resolved` values (empty string, no host, wrong JSON type) must be
handled without panics. Degenerate git URLs are stored as-is; wrong JSON types
cause the entry to be skipped.

## Acceptance criteria

- [ ] `git+https://`, `git+ssh://`, `git+http://` resolved URLs emit `Git` deps
- [ ] `github:`, `gitlab:`, `bitbucket:` shorthands expand correctly
- [ ] Entry with empty `version` + git `resolved` is no longer dropped
- [ ] Entry with placeholder version + git `resolved` emits `Git`, not `Registry`
- [ ] Package name is preserved (including scoped `@org/pkg` names)
- [ ] Non-git resolved URLs unaffected
- [ ] Malformed `resolved` values do not panic
- [ ] All T-091-01 through T-091-19 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/091-npm-git-url-parser-test-spec.md`

## Out of scope

- Cargo git URL parsing (task 092)
- Surfacing git deps in scan output / routing (task 093)
- Mutable-ref policy (task 094)
- Host validation / allow-deny policy (task 096)
- Any network fetch

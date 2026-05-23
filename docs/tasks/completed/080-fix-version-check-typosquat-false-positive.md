# Task 080 — Fix typosquatting false-positive on `version_check`

**Status:** backlog
**Depends on:** none
**Source:** Surfaced by task 067 dogfood run (commit `d13dc57`); one of five remaining real-block verdicts on dep-scan's own Cargo.lock
**Touches:** `src/typosquat.rs`

## Severity: LOW (data correctness)

This is a wrong-data bug, not a logic bug. The popular-crates list in
`src/typosquat.rs` records `"version-check"` (with a hyphen). The actual
crate on crates.io is `version_check` (with an underscore) — there is no
`version-check` crate. So when dep-scan scans `version_check`, the
typosquatting policy computes edit distance to a non-existent "popular"
name and reports a false positive at distance 0.08.

## Objective

Correct the popular-crates list entry to the canonical crate name
`version_check`.

## Background

[`src/typosquat.rs:568`](../../src/typosquat.rs#L568):

```rust
"semver",
"version-check",      // ← should be "version_check"
"cargo",
```

Crates.io has only `version_check` (underscore). Cargo's normalization of
package names allows hyphens and underscores to alias for *retrieval*, but
the **canonical published name** is what crates.io stores and serves; in
this case that's `version_check`.

Dogfood evidence: our own `Cargo.lock` pins `version_check@0.9.5`. The
typosquatting policy fires because:

1. Loop iterates over `POPULAR_CRATES`.
2. Hits `"version-check"`.
3. Computes Levenshtein distance from `"version_check"` to
   `"version-check"` = 1 character difference.
4. Normalized similarity score is 0.08 (within the warn / block threshold).
5. Emits `Block` with "is suspiciously similar to popular package
   'version-check'".

The crate dep-scan is scanning IS the popular package. The list just has
the wrong name.

## Behavior

1. In `src/typosquat.rs`, change `"version-check"` to `"version_check"` in
   the `POPULAR_CRATES` array.
2. Audit the rest of `POPULAR_CRATES` for similar hyphen-vs-underscore
   mismatches (one quick pass; flag any that look wrong but leave
   refactoring to a separate task if you find more than 2-3).
3. Re-run the dogfood scan locally; the `version_check` block should be
   gone (other 4 blocks remain — addressed by tasks 079/081).

## Acceptance criteria

- [ ] `src/typosquat.rs` `POPULAR_CRATES` array contains `"version_check"`,
      not `"version-check"`.
- [ ] No new false positives introduced (rerun `cargo test`).
- [ ] Local dogfood scan no longer reports a typosquat block on
      `version_check`.
- [ ] If audit found other obvious wrong-name entries, they're either
      fixed in this commit or filed as a follow-up task with names listed.

## Out of scope

- Adding a "canonical name normalization" feature to the typosquatting
  policy (hyphen↔underscore alias handling). That's a separate design
  decision — for v1.2 the right move is to fix the data.
- Auditing the npm/PyPI/Go popular-name lists for similar issues. Those
  ecosystems have different naming conventions; investigate separately if
  another false-positive surfaces.

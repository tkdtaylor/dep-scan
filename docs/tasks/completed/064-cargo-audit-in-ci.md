# Task 064 — Add `cargo audit` step to CI

**Status:** backlog
**Depends on:** none
**Source:** post-v1.2.0 holistic review (Tier A #2)
**Touches:** `.github/workflows/ci.yml`

## Objective

Run `cargo audit` on every push to `main` and every pull request, failing the
build on any unpatched RustSec advisory. dep-scan is a supply-chain security
tool; not auditing its own dependencies in CI is a credibility hole.

## Background

The project already runs `cargo audit` locally before each release, but the
discipline depends on the human remembering. CI enforcement closes that gap.
There is a maintained GitHub Action — `rustsec/audit-check@v2` — which runs
`cargo install cargo-audit` + `cargo audit` and parses results into GitHub
annotations.

Two failure-mode considerations:

1. **A new advisory drops between release tags.** This is the *expected* signal
   — we *want* CI to start failing so we know to patch.
2. **A transitive advisory has no patched version.** We've seen this with
   `time` (RUSTSEC-2026-0009 before 0.3.47). The right response is a
   `cargo update`-driven patch or a documented `[advisories.ignore]` entry in
   `.cargo/audit.toml` with a justification.

## Behavior

1. Add a new job `audit` to `.github/workflows/ci.yml`, parallel to the
   existing `test` / `clippy` / `fmt` jobs.
2. The job runs `rustsec/audit-check@v2` with a `token: ${{ secrets.GITHUB_TOKEN }}`.
3. Job is **required to pass** for the CI status check.
4. Document in CLAUDE.md (under "Commands") that suppressing an advisory
   requires a `.cargo/audit.toml` entry with a justification comment — never
   `--ignore` on the command line.

## Acceptance criteria

- [ ] `.github/workflows/ci.yml` defines an `audit` job
- [ ] Job uses `rustsec/audit-check@v2`
- [ ] Job runs on the same triggers as the existing jobs (push to main, PRs)
- [ ] Workflow YAML is valid (parses without error)
- [ ] Running the workflow against current `main` succeeds (no unpatched advisories)

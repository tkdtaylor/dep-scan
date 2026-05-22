# Task 067 — Dog-food: dep-scan scans its own `Cargo.lock` in CI

**Status:** backlog
**Depends on:** 064 (cargo audit), 065 (multi-OS matrix), 066 (MSRV pin) — all
land in the same workflow file; ordering matters so failures in this job are
interpretable against a stable baseline.
**Source:** post-v1.2.0 holistic review (Tier A "dog-food" item)
**Touches:** `.github/workflows/ci.yml`

## Objective

After the test/clippy/fmt/audit jobs pass, build dep-scan and run it against
its own `Cargo.lock`. The same heuristics dep-scan asks users to trust (age,
typosquatting, vulnerability, popularity, maintainer change) get applied to
its own dependency tree on every PR.

## Background

A security tool that doesn't eat its own dog food is a credibility problem.
The check is also a real signal: if a new transitive dep gets added in a PR
that fails dep-scan's heuristics, we want to know before the merge.

Failure semantics need to be thought through:

- **`block` verdicts:** fail CI. These are unambiguous policy violations.
- **`warn` verdicts:** by default, dep-scan exits `1` on warns. For the
  dog-food job that's too noisy — popular crates we ship today (e.g. `rcgen`
  in dev-deps) might produce maintainer-change or popularity warns that don't
  represent supply-chain risk.

Two options for the warn-handling problem:

A. Run dep-scan with `--json` and post-process: fail only on `block` verdicts,
   surface `warn` verdicts as GitHub Actions annotations.
B. Maintain a per-project `dep-scan.toml` in the repo that disables
   warn-prone policies for this specific run.

Recommend A — keeps the production policies on, just changes the CI gate.

## Behavior

1. Add a new job `dogfood` to `.github/workflows/ci.yml`, depending on `test`
   (so we only run dep-scan if its own tests pass).
2. The job builds dep-scan in release mode, then runs:
   ```
   ./target/release/dep-scan check \
     --lockfile Cargo.lock --lockfile-type crates --json
   ```
3. Parse the JSON; fail the job if any package's aggregate `result` is
   `"block"`. Print `warn` verdicts as `::warning::` GitHub Actions annotations.
4. Job runs on `ubuntu-latest` only — this is a self-check, not a portability
   check.

## Acceptance criteria

- [ ] `.github/workflows/ci.yml` defines a `dogfood` job
- [ ] Job depends on `test`
- [ ] Job builds dep-scan and runs `check --lockfile Cargo.lock --lockfile-type crates --json`
- [ ] Job fails the build on any `block` verdict
- [ ] Job emits `::warning::` annotations on `warn` verdicts (not failures)
- [ ] Running the workflow against current `main` succeeds (no `block` verdicts
      on our own deps)

## Out of scope

- Scanning `package-lock.json` (we don't ship one).
- Adding new policies to handle the dogfood case — production policies apply
  uniformly.
- Running dep-scan against dev-only deps separately — `cargo check --lockfile`
  shows everything; the verdict pipeline handles dev-deps the same way.

## Post-implementation note (2026-05-22)

The CI infrastructure landed at commit `75e4d3e` as designed.  However, the
acceptance criterion "Running dep-scan against current main succeeds (no block
verdicts)" is **blocked by task 078** — a pre-existing source-code bug means
the lockfile scanner discards the pinned version from `Cargo.lock` and queries
registry "latest" instead, producing false-positive age-policy blocks on any
recently-published crate.

The dogfood CI job itself is correct; T-067-08 will be re-verified once task
078 lands. Coverage-tracker reflects this with `9/10 | ⏳ T-067-08 blocked by 078`.
**Do not push** until task 078 lands and the dogfood scan returns zero block
verdicts locally.

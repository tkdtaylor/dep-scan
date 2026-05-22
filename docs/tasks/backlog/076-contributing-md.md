# Task 076 — Add `CONTRIBUTING.md`

**Status:** backlog
**Depends on:** none (but ideally lands after 070 (SECURITY) so the cross-link
makes sense)
**Source:** post-v1.2.0 holistic review (Tier C / Community)
**Touches:** `CONTRIBUTING.md` (new), `README.md` (link)

## Objective

Document the contribution workflow so external contributors know how to
build, test, and submit changes. Without it, a new contributor has to
reverse-engineer the project's TDD-first / task-spec-paired discipline from
the source tree.

## Background

Conventions worth documenting:

1. **Test-spec-before-implementation.** Every task has a paired
   `NNN-name-test-spec.md`. No PR without one.
2. **Conventional-commits-ish format.** `feat:`, `test:`, `docs:`, `fix:`
   prefixes; one task per commit; no batching.
3. **CI gates.** All four (fmt, clippy, test, audit) must pass locally
   before pushing.
4. **MSRV.** 1.88; pinned in CI via task 066.
5. **Where to find the task list.** `docs/tasks/backlog/` and
   `coverage-tracker.md`.
6. **How to propose new features.** Open a GitHub issue first; if accepted,
   it gets a task file via the task-planner workflow.
7. **Security reports go elsewhere.** Link to `SECURITY.md`.

## Behavior

Create `CONTRIBUTING.md` at repo root. Structure:

```
# Contributing to dep-scan

Thanks for your interest…

## Quick start
  - Fork, clone, install Rust 1.88+, cargo test

## Workflow
  - One task, one commit
  - Test spec before implementation
  - Commit messages: feat/test/docs/fix prefix

## Local CI gates (must all pass before pushing)
  - cargo fmt --check
  - cargo clippy --all-targets --all-features -- -D warnings
  - cargo test
  - cargo audit

## Proposing a new feature
  - Open an issue describing the use case
  - Wait for acceptance before writing code
  - Acceptance includes a task file in docs/tasks/backlog/

## Reporting security issues
  - Don't open a public issue. See SECURITY.md.

## Code of conduct
  - See CODE_OF_CONDUCT.md (if 077 has landed).
```

## Acceptance criteria

- [ ] `CONTRIBUTING.md` exists at repo root
- [ ] Documents all four local CI gates with exact commands
- [ ] States MSRV (1.88) and how it's enforced
- [ ] Explains the test-spec-first rule with a pointer to
      `docs/tasks/test-specs/`
- [ ] Links to SECURITY.md for security reports
- [ ] README.md gets a "Contributing" link near the top (or in a footer)
- [ ] GitHub auto-detects the file and shows the contribute prompt on PRs

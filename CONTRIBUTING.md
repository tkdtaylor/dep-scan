# Contributing to dep-scan

Thanks for your interest in dep-scan. This document explains how to build,
test, and submit changes.

## Quick start

```bash
# Fork and clone
git clone https://github.com/<your-fork>/dep-scan
cd dep-scan

# Install Rust 1.88+ via rustup
rustup toolchain install 1.88

# Build and test
cargo build
cargo test
```

## Workflow

dep-scan uses a TDD-first, task-driven workflow:

1. **Open an issue first** before writing code. New features need a task file
   (see [Proposing features](#proposing-a-new-feature) below).
2. **Write the test spec before any implementation.** Every task has a paired
   `docs/tasks/test-specs/NNN-name-test-spec.md`. No PR without one.
3. **One task, one commit.** Do not batch unrelated changes.
4. **Commit message format:** use a conventional prefix — `feat:`, `fix:`,
   `test:`, `docs:`, `chore:` — followed by a concise summary.

## Local CI gates

All four must pass before pushing. Running them locally saves a CI round-trip.

```bash
cargo fmt --check                                    # formatting
cargo clippy --all-targets --all-features -- -D warnings  # lints
cargo test                                           # tests
cargo audit                                          # known advisories
```

**Minimum Supported Rust Version (MSRV):** 1.88. This is pinned in
`Cargo.toml` (`rust-version = "1.88"`) and enforced in CI.

## Test-spec-first rule

Every task has a paired test spec in `docs/tasks/test-specs/`. The spec
defines "done" — write it before any implementation code. PRs that add
behavior without a test spec will be sent back.

Browse existing specs in [`docs/tasks/test-specs/`](docs/tasks/test-specs/)
and the task tracker in
[`docs/tasks/test-specs/coverage-tracker.md`](docs/tasks/test-specs/coverage-tracker.md).

## Proposing a new feature

1. Open a GitHub issue describing the use case and the problem it solves.
2. Wait for acceptance (a maintainer will comment or add a task file).
3. Once accepted, a task file lands in `docs/tasks/backlog/` with a paired
   test spec stub. You can claim it or the maintainer will assign it.

Do not start writing code before the task file exists.

## Reporting security issues

Do **not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for the disclosure process.

## Code of conduct

All contributors are expected to follow the project's
[Code of Conduct](CODE_OF_CONDUCT.md).

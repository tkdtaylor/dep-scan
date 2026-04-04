# Task 024 — Install subcommand implementation

**Status:** backlog
**Depends on:** 023

## Objective

Implement the `dep-scan install` command that scans packages then executes the underlying package manager.

## Acceptance criteria

- [ ] dep-scan install <packages> --registry npm scans then runs npm install
- [ ] Blocks install if any policy violations (exit 1)
- [ ] --force flag bypasses policy violations with warning
- [ ] Supports all 4 registries (npm, pypi, crates, go)
- [ ] Uses std::process::Command to exec the real package manager
- [ ] Tests for scan-gate logic and command construction
- [ ] All tests pass, clippy clean, fmt clean

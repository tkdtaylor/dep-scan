# Task 024 — Install subcommand implementation

**Status:** done
**Depends on:** 023

## Objective

Implement the `dep-scan install` command that scans packages then executes the underlying package manager.

## Acceptance criteria

- [x] dep-scan install <packages> --registry npm scans then runs npm install
- [x] Blocks install if any policy violations (exit 1)
- [x] --force flag bypasses policy violations with warning
- [x] Supports all 4 registries (npm, pypi, crates, go)
- [x] Uses std::process::Command to exec the real package manager
- [x] Tests for scan-gate logic and command construction
- [x] All tests pass, clippy clean, fmt clean

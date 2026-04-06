# Task 023 — Lockfile parser

**Status:** backlog
**Depends on:** v0.3 complete

## Objective

Parse lockfile formats to extract dependency lists, enabling `dep-scan check --lockfile <path>`.

## Acceptance criteria

- [x] src/lockfile.rs: parse package-lock.json, requirements.txt, Cargo.lock, go.sum
- [x] Auto-detect format from filename
- [x] --lockfile-type flag for override
- [x] --lockfile <path> flag on check subcommand
- [x] Combine --lockfile with explicit package names
- [x] Skip comments, flags, blank lines in requirements.txt
- [x] Handle malformed input gracefully with clear errors
- [x] All tests pass, clippy clean, fmt clean

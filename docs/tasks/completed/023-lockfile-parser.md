# Task 023 — Lockfile parser

**Status:** backlog
**Depends on:** v0.3 complete

## Objective

Parse lockfile formats to extract dependency lists, enabling `dep-scan check --lockfile <path>`.

## Acceptance criteria

- [ ] src/lockfile.rs: parse package-lock.json, requirements.txt, Cargo.lock, go.sum
- [ ] Auto-detect format from filename
- [ ] --lockfile-type flag for override
- [ ] --lockfile <path> flag on check subcommand
- [ ] Combine --lockfile with explicit package names
- [ ] Skip comments, flags, blank lines in requirements.txt
- [ ] Handle malformed input gracefully with clear errors
- [ ] All tests pass, clippy clean, fmt clean

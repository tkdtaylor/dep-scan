# Task 026 — GitHub Actions release workflow

**Status:** backlog
**Depends on:** none

## Objective

Automated cross-platform binary builds on tag push with GitHub release creation.

## Acceptance criteria

- [x] .github/workflows/release.yml exists
- [x] Triggers on push tag v*
- [x] Builds for: Linux x86_64, Linux ARM64, macOS x86_64, macOS ARM64, Windows x86_64
- [x] Creates GitHub release with all binary artifacts
- [x] Generates SHA256 checksums file
- [x] Valid YAML workflow

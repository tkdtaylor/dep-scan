# Task 015 — Dependency confusion heuristics

**Status:** backlog
**Depends on:** 010

## Objective

Warn when a public package name matches patterns typically used for internal/private packages.

## Acceptance criteria

- [x] src/policy/dependency_confusion.rs: `DependencyConfusionPolicy` implements `Policy`
- [x] Check package name against configurable internal namespace patterns
- [x] Default patterns: `internal-`, `private-`, `corp-`
- [x] Warn if match found
- [x] Config: `[dependency_confusion]` section with `internal_prefixes` list
- [x] Pure string matching, no external data needed
- [x] Tests: matching names, non-matching, custom prefixes
- [x] All tests pass, clippy clean, fmt clean

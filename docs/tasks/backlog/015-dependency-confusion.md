# Task 015 — Dependency confusion heuristics

**Status:** backlog
**Depends on:** 010

## Objective

Warn when a public package name matches patterns typically used for internal/private packages.

## Acceptance criteria

- [ ] src/policy/dependency_confusion.rs: `DependencyConfusionPolicy` implements `Policy`
- [ ] Check package name against configurable internal namespace patterns
- [ ] Default patterns: `internal-`, `private-`, `corp-`
- [ ] Warn if match found
- [ ] Config: `[dependency_confusion]` section with `internal_prefixes` list
- [ ] Pure string matching, no external data needed
- [ ] Tests: matching names, non-matching, custom prefixes
- [ ] All tests pass, clippy clean, fmt clean

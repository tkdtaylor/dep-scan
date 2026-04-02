# Task 013 — Typosquatting detection

**Status:** backlog
**Depends on:** 010

## Objective

Detect packages with names suspiciously similar to popular packages using edit distance and heuristics.

## Acceptance criteria

- [ ] src/typosquat.rs: Edit distance engine with normalized Levenshtein, keyboard proximity, affix normalization
- [ ] Embedded popular package lists (top 500 npm, top 500 PyPI)
- [ ] src/policy/typosquatting.rs: `TyposquattingPolicy` implements `Policy`
- [ ] Skip if package IS in popular list (it's the real package)
- [ ] Warn if distance < warn threshold (default 0.15 normalized)
- [ ] Block if distance < block threshold (default 0.08 normalized)
- [ ] Message includes the similar popular package name
- [ ] Config: `[typosquatting]` section with thresholds
- [ ] Tests: known typosquats, legitimate names, exact matches
- [ ] All tests pass, clippy clean, fmt clean

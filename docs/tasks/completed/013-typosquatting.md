# Task 013 — Typosquatting detection

**Status:** done
**Depends on:** 010

## Objective

Detect packages with names suspiciously similar to popular packages using edit distance and heuristics.

## Acceptance criteria

- [x] src/typosquat.rs: Edit distance engine with normalized Levenshtein, affix normalization
- [x] Embedded popular package lists (150+ npm, 150+ PyPI)
- [x] src/policy/typosquatting.rs: `TyposquattingPolicy` implements `Policy`
- [x] Skip if package IS in popular list (it's the real package)
- [x] Warn if distance < warn threshold (default 0.15 normalized)
- [x] Block if distance < block threshold (default 0.08 normalized)
- [x] Message includes the similar popular package name
- [x] Wired into main.rs via config.policies.check_typosquatting
- [x] Tests: known typosquats, legitimate names, exact matches
- [x] All tests pass, clippy clean, fmt clean

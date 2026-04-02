# Task 014 — Maintainer change detection

**Status:** completed
**Depends on:** 010

## Objective

Detect suspicious maintainer changes by comparing current maintainers against a cached baseline.

## Acceptance criteria

- [x] Cache: new `maintainer_history` table with CREATE TABLE IF NOT EXISTS
- [x] Cache methods: `record_maintainers`, `get_previous_maintainers`
- [x] src/policy/maintainer.rs: `MaintainerChangePolicy` implements `Policy`
- [x] First scan: record baseline, return Pass
- [x] Subsequent scans: compare current vs cached
- [x] Warn if maintainers added or removed
- [x] Block if ALL maintainers changed (complete takeover)
- [x] After check, update cached maintainer list
- [x] Tests: first scan, no change, additions, removals, complete changeover
- [x] All tests pass, clippy clean, fmt clean

# Task 014 — Maintainer change detection

**Status:** backlog
**Depends on:** 010

## Objective

Detect suspicious maintainer changes by comparing current maintainers against a cached baseline.

## Acceptance criteria

- [ ] Cache: new `maintainer_history` table with CREATE TABLE IF NOT EXISTS
- [ ] Cache methods: `record_maintainers`, `get_previous_maintainers`
- [ ] src/policy/maintainer.rs: `MaintainerChangePolicy` implements `Policy`
- [ ] First scan: record baseline, return Pass
- [ ] Subsequent scans: compare current vs cached
- [ ] Warn if maintainers added or removed
- [ ] Block if ALL maintainers changed (complete takeover)
- [ ] After check, update cached maintainer list
- [ ] Tests: first scan, no change, additions, removals, complete changeover
- [ ] All tests pass, clippy clean, fmt clean

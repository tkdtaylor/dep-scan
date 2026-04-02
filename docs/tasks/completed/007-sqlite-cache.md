# Task 007 — SQLite hash cache

**Status:** backlog
**Depends on:** 004

## Objective

Implement a local SQLite cache for storing scan results so already-scanned packages can be skipped.

## Acceptance criteria

- [ ] src/cache.rs: `Cache` struct wrapping rusqlite Connection
- [ ] Schema: `scanned_packages(name TEXT, version TEXT, registry TEXT, result TEXT, scanned_at TEXT, PRIMARY KEY(name, version, registry))`
- [ ] `Cache::new(path)` creates/opens DB and auto-creates table
- [ ] `lookup(name, version, registry)` returns cached result or None
- [ ] `insert(name, version, registry, result)` upserts a cache entry
- [ ] `invalidate(name, version, registry)` removes a cache entry
- [ ] `clear()` removes all entries
- [ ] Tests use in-memory SQLite (`:memory:`)
- [ ] All tests pass, clippy clean, fmt clean

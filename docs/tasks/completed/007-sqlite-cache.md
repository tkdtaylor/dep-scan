# Task 007 — SQLite hash cache

**Status:** backlog
**Depends on:** 004

## Objective

Implement a local SQLite cache for storing scan results so already-scanned packages can be skipped.

## Acceptance criteria

- [x] src/cache.rs: `Cache` struct wrapping rusqlite Connection
- [x] Schema: `scanned_packages(name TEXT, version TEXT, registry TEXT, result TEXT, scanned_at TEXT, PRIMARY KEY(name, version, registry))`
- [x] `Cache::new(path)` creates/opens DB and auto-creates table
- [x] `lookup(name, version, registry)` returns cached result or None
- [x] `insert(name, version, registry, result)` upserts a cache entry
- [x] `invalidate(name, version, registry)` removes a cache entry
- [x] `clear()` removes all entries
- [x] Tests use in-memory SQLite (`:memory:`)
- [x] All tests pass, clippy clean, fmt clean

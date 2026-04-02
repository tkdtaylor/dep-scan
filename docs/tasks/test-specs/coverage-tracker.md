# Test Coverage Tracker

**Project:** dep-scan

## Rules

- Test specs are written **before** implementation begins — no exceptions
- A task is only "complete" when all its test cases pass
- Each row maps a task ID to its spec file and current test status

## Coverage

| Task ID | Feature | Spec file | Tests written | Status |
|---------|---------|-----------|---------------|--------|
| 002 | CLI skeleton with clap | 002-cli-skeleton-test-spec.md | 11/11 | Done |
| 003 | Configuration system | 003-config-system-test-spec.md | 10/10 | Done |
| 004 | Package metadata types + registry trait | 004-types-and-registry-trait-test-spec.md | 6/6 | Done |
| 005 | npm registry client | 005-npm-registry-client-test-spec.md | 8/8 | Done |
| 006 | PyPI registry client | 006-pypi-registry-client-test-spec.md | 12/12 | Done |
| 007 | SQLite hash cache | 007-sqlite-cache-test-spec.md | 10/10 | Done |
| 008 | Minimum package age policy | 008-age-policy-test-spec.md | 7/7 | Done |
| 009 | Check subcommand integration | 009-check-integration-test-spec.md | 8/8 | Done |
| 010 | ScanContext + multi-policy pipeline | 010-multi-policy-pipeline-test-spec.md | 11/11 | Done |
| 011 | OSV.dev vulnerability client + policy | 011-osv-vulnerability-test-spec.md | 10/10 | Done |
| 012 | Install script extraction + analysis | 012-install-script-analysis-test-spec.md | 12/12 | Done |
| 013 | Typosquatting detection | 013-typosquatting-test-spec.md | 20/20 | Done |
| 014 | Maintainer change detection | 014-maintainer-change-test-spec.md | 9/9 | Done |
| 015 | Dependency confusion heuristics | 015-dependency-confusion-test-spec.md | 11/11 | Done |
| 016 | v0.2 integration tests | 016-v2-integration-test-spec.md | 7/7 | Done |

## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ | Done |
| ⏳ | In progress |
| ❌ | Not started |
| ⚠️ | Blocked |

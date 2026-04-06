# Task 016 — v0.2 integration tests + output polish

**Status:** backlog
**Depends on:** 011, 012, 013, 014, 015

## Objective

End-to-end integration tests for all v0.2 policies together, plus output formatting polish.

## Acceptance criteria

- [x] tests/check_v2_integration.rs: Multi-policy end-to-end tests
- [x] Test: package with vulnerability + recent age shows multiple violations
- [x] Test: suspicious install script triggers block
- [x] Test: clean package passes all policies
- [x] Test: typosquatting match triggers warn
- [x] Test: config toggles disable individual policies
- [x] Human-readable output is well-formatted with all policy results
- [x] JSON output has stable schema for CI/CD
- [x] Exit codes correct with multiple policy results
- [x] All tests pass, clippy clean, fmt clean

# Task 016 — v0.2 integration tests + output polish

**Status:** backlog
**Depends on:** 011, 012, 013, 014, 015

## Objective

End-to-end integration tests for all v0.2 policies together, plus output formatting polish.

## Acceptance criteria

- [ ] tests/check_v2_integration.rs: Multi-policy end-to-end tests
- [ ] Test: package with vulnerability + recent age shows multiple violations
- [ ] Test: suspicious install script triggers block
- [ ] Test: clean package passes all policies
- [ ] Test: typosquatting match triggers warn
- [ ] Test: config toggles disable individual policies
- [ ] Human-readable output is well-formatted with all policy results
- [ ] JSON output has stable schema for CI/CD
- [ ] Exit codes correct with multiple policy results
- [ ] All tests pass, clippy clean, fmt clean

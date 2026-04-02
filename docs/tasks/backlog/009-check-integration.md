# Task 009 — check subcommand integration

**Status:** backlog
**Depends on:** 005, 006, 007, 008

## Objective

Wire up the `check` subcommand end-to-end: parse args, load config, query registry, check cache, run policies, and report results.

## Acceptance criteria

- [ ] `dep-scan check <package> --registry npm` queries npm registry and runs age policy
- [ ] Results displayed in human-readable table format
- [ ] `--json` flag outputs structured JSON
- [ ] Cache is checked first; cache hits skip registry query
- [ ] New scan results are stored in cache
- [ ] Exit code 0 = all pass, 1 = policy violations found, 2 = runtime error
- [ ] Multiple packages can be checked in a single invocation
- [ ] Tests: assert_cmd end-to-end with wiremock mock registry
- [ ] All tests pass, clippy clean, fmt clean

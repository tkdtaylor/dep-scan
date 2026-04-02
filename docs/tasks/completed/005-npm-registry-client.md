# Task 005 — npm registry client

**Status:** backlog
**Depends on:** 004

## Objective

Implement the npm registry client that fetches package metadata from the npm registry API.

## Acceptance criteria

- [ ] src/registry/npm.rs: `NpmRegistry` struct with configurable `base_url`
- [ ] Implements `Registry` trait
- [ ] Fetches from `{base_url}/{package_name}` endpoint
- [ ] Parses npm JSON response into `PackageMetadata`
- [ ] Extracts: name, latest version, publish time from `time` field, maintainers array
- [ ] Handles 404 (NotFound), rate limiting, network errors
- [ ] Base URL is configurable (not hardcoded)
- [ ] Tests use wiremock with realistic npm JSON fixtures
- [ ] All tests pass, clippy clean, fmt clean

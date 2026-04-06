# Task 005 — npm registry client

**Status:** backlog
**Depends on:** 004

## Objective

Implement the npm registry client that fetches package metadata from the npm registry API.

## Acceptance criteria

- [x] src/registry/npm.rs: `NpmRegistry` struct with configurable `base_url`
- [x] Implements `Registry` trait
- [x] Fetches from `{base_url}/{package_name}` endpoint
- [x] Parses npm JSON response into `PackageMetadata`
- [x] Extracts: name, latest version, publish time from `time` field, maintainers array
- [x] Handles 404 (NotFound), rate limiting, network errors
- [x] Base URL is configurable (not hardcoded)
- [x] Tests use wiremock with realistic npm JSON fixtures
- [x] All tests pass, clippy clean, fmt clean

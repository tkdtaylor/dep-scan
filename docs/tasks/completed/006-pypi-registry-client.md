# Task 006 — PyPI registry client

**Status:** backlog
**Depends on:** 004

## Objective

Implement the PyPI registry client that fetches package metadata from the PyPI JSON API.

## Acceptance criteria

- [x] src/registry/pypi.rs: `PyPiRegistry` struct with configurable `base_url`
- [x] Implements `Registry` trait
- [x] Fetches from `{base_url}/pypi/{package_name}/json` endpoint
- [x] Parses PyPI JSON response into `PackageMetadata`
- [x] Extracts: name, version, upload_time, author/maintainer
- [x] Handles 404 (NotFound), rate limiting, network errors
- [x] Base URL is configurable (not hardcoded)
- [x] Tests use wiremock with realistic PyPI JSON fixtures
- [x] All tests pass, clippy clean, fmt clean

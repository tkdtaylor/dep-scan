# Task 006 — PyPI registry client

**Status:** backlog
**Depends on:** 004

## Objective

Implement the PyPI registry client that fetches package metadata from the PyPI JSON API.

## Acceptance criteria

- [ ] src/registry/pypi.rs: `PyPiRegistry` struct with configurable `base_url`
- [ ] Implements `Registry` trait
- [ ] Fetches from `{base_url}/pypi/{package_name}/json` endpoint
- [ ] Parses PyPI JSON response into `PackageMetadata`
- [ ] Extracts: name, version, upload_time, author/maintainer
- [ ] Handles 404 (NotFound), rate limiting, network errors
- [ ] Base URL is configurable (not hardcoded)
- [ ] Tests use wiremock with realistic PyPI JSON fixtures
- [ ] All tests pass, clippy clean, fmt clean

# Task 018 — crates.io registry client

**Status:** done
**Depends on:** 017

## Objective

Implement the crates.io registry client that fetches package metadata from the crates.io API.

## Acceptance criteria

- [x] src/registry/crates.rs: CratesRegistry with configurable base_url
- [x] Implements Registry trait
- [x] Fetches {base_url}/api/v1/crates/{name}
- [x] Sets User-Agent header to "dep-scan/{version}"
- [x] Parses: name, max_version, description, published_at, maintainers, downloads, repository
- [x] Handles 404, 429, network errors
- [x] Wired into main.rs dispatch for RegistryType::Crates
- [x] Tests with wiremock using realistic crates.io JSON
- [x] All tests pass, clippy clean, fmt clean

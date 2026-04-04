# Task 018 — crates.io registry client

**Status:** backlog
**Depends on:** 017

## Objective

Implement the crates.io registry client that fetches package metadata from the crates.io API.

## Acceptance criteria

- [ ] src/registry/crates.rs: CratesRegistry with configurable base_url
- [ ] Implements Registry trait
- [ ] Fetches {base_url}/api/v1/crates/{name}
- [ ] Sets User-Agent header to "dep-scan/{version}"
- [ ] Parses: name, max_version, description, published_at, maintainers, downloads, repository
- [ ] Handles 404, 429, network errors
- [ ] Wired into main.rs dispatch for RegistryType::Crates
- [ ] Tests with wiremock using realistic crates.io JSON
- [ ] All tests pass, clippy clean, fmt clean

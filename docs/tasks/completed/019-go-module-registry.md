# Task 019 — Go module proxy client

**Status:** done
**Depends on:** 017

## Objective

Implement the Go module proxy client that fetches package metadata from proxy.golang.org.

## Acceptance criteria

- [x] src/registry/go.rs: GoRegistry with configurable base_url
- [x] Implements Registry trait
- [x] URL-encodes module paths (github.com/user/repo)
- [x] Fetches version list from {base_url}/{module}/@v/list
- [x] Fetches version info from {base_url}/{module}/@v/{version}.info
- [x] Parses: name (module path), version, published_at (Time field)
- [x] Handles 404, 410 (gone), network errors
- [x] Maintainers/downloads left as empty/None (not available from proxy)
- [x] Wired into main.rs dispatch for RegistryType::Go
- [x] Tests with wiremock
- [x] All tests pass, clippy clean, fmt clean

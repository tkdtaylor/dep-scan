# Task 019 — Go module proxy client

**Status:** backlog
**Depends on:** 017

## Objective

Implement the Go module proxy client that fetches package metadata from proxy.golang.org.

## Acceptance criteria

- [ ] src/registry/go.rs: GoRegistry with configurable base_url
- [ ] Implements Registry trait
- [ ] URL-encodes module paths (github.com/user/repo)
- [ ] Fetches version list from {base_url}/{module}/@v/list
- [ ] Fetches version info from {base_url}/{module}/@v/{version}.info
- [ ] Parses: name (module path), version, published_at (Time field)
- [ ] Handles 404, 410 (gone), network errors
- [ ] Maintainers/downloads left as empty/None (not available from proxy)
- [ ] Wired into main.rs dispatch for RegistryType::Go
- [ ] Tests with wiremock
- [ ] All tests pass, clippy clean, fmt clean

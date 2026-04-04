# Task 017 — RegistryType expansion + config

**Status:** backlog
**Depends on:** v0.2 complete

## Objective

Add Crates and Go variants to RegistryType, expand config with registry URLs, and update all dispatch points.

## Acceptance criteria

- [ ] RegistryType enum has Crates and Go variants
- [ ] Display: Crates → "crates", Go → "go"
- [ ] FromStr: "crates"/"crates.io" → Crates, "go"/"gomod" → Go
- [ ] RegistryConfig has crates_url (default https://crates.io) and go_proxy_url (default https://proxy.golang.org)
- [ ] Env var overrides: DEP_SCAN_CRATES_URL, DEP_SCAN_GO_PROXY_URL
- [ ] registry_to_ecosystem() maps Crates → "crates.io", Go → "Go"
- [ ] main.rs dispatch has match arms for Crates/Go (can use todo!() temporarily)
- [ ] RegistryType derives PartialEq, Eq if not already
- [ ] All existing tests pass, new tests for parsing/display/config
- [ ] clippy clean, fmt clean

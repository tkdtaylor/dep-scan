# Task 017 — RegistryType expansion + config

**Status:** done
**Depends on:** v0.2 complete

## Objective

Add Crates and Go variants to RegistryType, expand config with registry URLs, and update all dispatch points.

## Acceptance criteria

- [x] RegistryType enum has Crates and Go variants
- [x] Display: Crates → "crates", Go → "go"
- [x] FromStr: "crates"/"crates.io" → Crates, "go"/"gomod" → Go
- [x] RegistryConfig has crates_url (default https://crates.io) and go_proxy_url (default https://proxy.golang.org)
- [x] Env var overrides: DEP_SCAN_CRATES_URL, DEP_SCAN_GO_PROXY_URL
- [x] registry_to_ecosystem() maps Crates → "crates.io", Go → "Go"
- [x] main.rs dispatch has match arms for Crates/Go (can use todo!() temporarily)
- [x] RegistryType derives PartialEq, Eq if not already
- [x] All existing tests pass, new tests for parsing/display/config
- [x] clippy clean, fmt clean

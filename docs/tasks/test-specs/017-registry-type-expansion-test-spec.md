# Test Spec — Task 017: RegistryType expansion + config

## Unit tests

### T-017-01: RegistryType Display for new variants
- RegistryType::Crates.to_string() == "crates"
- RegistryType::Go.to_string() == "go"

### T-017-02: RegistryType FromStr for new variants
- "crates".parse() == Ok(Crates)
- "crates.io".parse() == Ok(Crates)
- "go".parse() == Ok(Go)
- "gomod".parse() == Ok(Go)
- Case insensitive: "CRATES", "Go"

### T-017-03: Existing variants still work
- "npm".parse() == Ok(Npm), "pypi".parse() == Ok(PyPI)

### T-017-04: Config defaults for new registry URLs
- Default config has crates_url = "https://crates.io"
- Default config has go_proxy_url = "https://proxy.golang.org"

### T-017-05: Env var overrides for new URLs
- DEP_SCAN_CRATES_URL overrides crates_url
- DEP_SCAN_GO_PROXY_URL overrides go_proxy_url

### T-017-06: registry_to_ecosystem for new types
- Crates → "crates.io"
- Go → "Go"

### T-017-07: RegistryType PartialEq works
- RegistryType::Crates == RegistryType::Crates
- RegistryType::Go != RegistryType::Npm

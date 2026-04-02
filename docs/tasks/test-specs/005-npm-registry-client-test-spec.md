# Test Spec — Task 005: npm registry client

## Unit tests (wiremock)

### T-005-01: Fetch metadata for existing package
- Setup: wiremock returns realistic npm JSON for "lodash"
- Expected: PackageMetadata with correct name, version, published_at, maintainers

### T-005-02: Package not found returns NotFound
- Setup: wiremock returns 404
- Expected: RegistryError::NotFound

### T-005-03: Rate limited returns RateLimited
- Setup: wiremock returns 429
- Expected: RegistryError::RateLimited

### T-005-04: Network error returns NetworkError
- Setup: wiremock on unreachable port or connection refused
- Expected: RegistryError::NetworkError

### T-005-05: Malformed JSON returns ParseError
- Setup: wiremock returns 200 with invalid JSON
- Expected: RegistryError::ParseError

### T-005-06: Extracts publish time from time field
- Setup: wiremock returns npm JSON with `time.modified` and version-specific times
- Expected: published_at matches the latest version's publish time

### T-005-07: Extracts maintainers list
- Setup: wiremock returns npm JSON with maintainers array
- Expected: maintainers list populated correctly

### T-005-08: Custom base URL is used
- Setup: wiremock on custom port
- Expected: NpmRegistry hits the configured base URL, not hardcoded default

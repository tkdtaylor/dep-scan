# Test Spec — Task 018: crates.io registry client

## Unit tests (wiremock)

### T-018-01: Fetch metadata for existing crate
- wiremock returns realistic crates.io JSON for "serde"
- Expected: correct name, version, description, published_at, downloads, repository_url

### T-018-02: Crate not found returns NotFound
- wiremock returns 404
- Expected: RegistryError::NotFound

### T-018-03: Rate limited returns RateLimited
- wiremock returns 429
- Expected: RegistryError::RateLimited

### T-018-04: Malformed JSON returns ParseError
- wiremock returns 200 with invalid JSON
- Expected: RegistryError::ParseError

### T-018-05: User-Agent header is set
- wiremock verifies request has User-Agent containing "dep-scan"

### T-018-06: Custom base URL is used
- wiremock on custom port, CratesRegistry points at it
- Expected: request arrives at wiremock

### T-018-07: Extracts downloads count
- wiremock returns crate with downloads: 50000000
- Expected: metadata.downloads == Some(50000000)

### T-018-08: Extracts maintainer from published_by
- wiremock response has versions[0].published_by.login = "dtolnay"
- Expected: maintainers contains "dtolnay"

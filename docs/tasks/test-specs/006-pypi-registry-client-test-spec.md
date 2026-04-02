# Test Spec — Task 006: PyPI registry client

## Unit tests (wiremock)

### T-006-01: Fetch metadata for existing package
- Setup: wiremock returns realistic PyPI JSON for "requests"
- Expected: PackageMetadata with correct name, version, published_at, maintainers

### T-006-02: Package not found returns NotFound
- Setup: wiremock returns 404
- Expected: RegistryError::NotFound

### T-006-03: Rate limited returns RateLimited
- Setup: wiremock returns 429
- Expected: RegistryError::RateLimited

### T-006-04: Malformed JSON returns ParseError
- Setup: wiremock returns 200 with invalid JSON
- Expected: RegistryError::ParseError

### T-006-05: Extracts upload_time correctly
- Setup: wiremock returns PyPI JSON with upload_time in releases
- Expected: published_at matches the latest version's upload_time

### T-006-06: Extracts author/maintainer
- Setup: wiremock returns PyPI JSON with author and maintainer_email
- Expected: maintainers list populated

### T-006-07: Custom base URL is used
- Setup: wiremock on custom port
- Expected: PyPiRegistry hits `{base_url}/pypi/{name}/json`

### T-006-08: Handles package with no releases
- Setup: wiremock returns PyPI JSON with empty releases
- Expected: appropriate error or metadata with no version

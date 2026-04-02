# Test Spec -- Task 006: PyPI registry client

## Unit tests (wiremock)

### T-006-01: Fetch metadata for existing package
- Setup: wiremock returns realistic PyPI JSON for "requests" (info + releases with two versions)
- Call: `registry.get_metadata("requests", None)`
- Expected: PackageMetadata with name="requests", version="2.31.0", description="Python HTTP for Humans.", published_at set, maintainers non-empty, repository_url="https://github.com/psf/requests"

### T-006-02: Package not found returns NotFound
- Setup: wiremock returns 404 for /pypi/nonexistent-pkg/json
- Call: `registry.get_metadata("nonexistent-pkg", None)`
- Expected: RegistryError::NotFound("nonexistent-pkg")

### T-006-03: Rate limited returns RateLimited
- Setup: wiremock returns 429 for /pypi/requests/json
- Call: `registry.get_metadata("requests", None)`
- Expected: RegistryError::RateLimited

### T-006-04: Malformed JSON returns ParseError
- Setup: wiremock returns 200 with body "this is not valid json {{{"
- Call: `registry.get_metadata("requests", None)`
- Expected: RegistryError::ParseError

### T-006-05: Extracts upload_time correctly
- Setup: wiremock returns PyPI JSON where version 2.31.0 has upload_time_iso_8601 "2023-05-22T15:12:44.145Z"
- Call: `registry.get_metadata("requests", None)`
- Expected: published_at matches "2023-05-22T15:12:44.145+00:00" (earliest of the release files)

### T-006-06: Extracts author/maintainer
- Setup: wiremock returns PyPI JSON with author="Author Name" and maintainer="Maintainer Name"
- Call: `registry.get_metadata("some-package", None)`
- Expected: maintainers = ["Author Name", "Maintainer Name"]

### T-006-07: Custom base URL is used
- Setup: wiremock on dynamic port, mock expects exactly 1 request at /pypi/flask/json
- Call: `PyPiRegistry::new(server.uri())`, then `get_metadata("flask", None)`
- Expected: metadata.name="flask", version="3.0.0"; wiremock verifies 1 request received

### T-006-08: Handles package with no releases
- Setup: wiremock returns PyPI JSON with empty releases map {}
- Call: `registry.get_metadata("empty-pkg", None)`
- Expected: metadata returned with name="empty-pkg", version="0.0.0", published_at=None

## Additional tests

### T-006-09: Fetch specific version
- Setup: wiremock returns realistic PyPI JSON with multiple versions
- Call: `registry.get_metadata("requests", Some("2.30.0"))`
- Expected: metadata.version="2.30.0", published_at matches "2023-05-03T11:30:00+00:00"

### T-006-10: Non-existent version returns NotFound
- Setup: wiremock returns PyPI JSON (200 OK)
- Call: `registry.get_metadata("requests", Some("99.99.99"))`
- Expected: RegistryError::NotFound containing "requests@99.99.99"

### T-006-11: Author-only maintainers list
- Setup: wiremock returns PyPI JSON with author="Kenneth Reitz" and empty maintainer
- Call: `registry.get_metadata("requests", None)`
- Expected: maintainers = ["Kenneth Reitz"]

### T-006-12: Repository URL falls back to home_page
- Setup: wiremock returns PyPI JSON with project_urls=null and home_page="https://example.com/old-pkg"
- Call: `registry.get_metadata("old-pkg", None)`
- Expected: repository_url = Some("https://example.com/old-pkg")

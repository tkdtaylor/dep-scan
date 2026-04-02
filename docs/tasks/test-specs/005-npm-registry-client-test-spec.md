# Test Spec — Task 005: npm registry client

## Unit tests (wiremock)

### T-005-01: Fetch metadata for existing package
- Setup: wiremock returns realistic npm JSON for "lodash" (200 OK)
- Call: `NpmRegistry::get_metadata("lodash", None)`
- Expected: `Ok(PackageMetadata)` with:
  - name == "lodash"
  - version == "4.17.21" (from dist-tags.latest)
  - description == "Lodash modular utilities."
  - published_at == Some(2021-02-20T15:42:16.891Z) (from time["4.17.21"])
  - maintainers == ["jdalton"]
  - repository_url == Some("https://github.com/lodash/lodash.git") (git+ prefix stripped)

### T-005-02: Package not found returns NotFound
- Setup: wiremock returns 404 for "nonexistent-pkg-xyz"
- Call: `NpmRegistry::get_metadata("nonexistent-pkg-xyz", None)`
- Expected: `Err(RegistryError::NotFound(_))` containing the package name

### T-005-03: Rate limited returns RateLimited
- Setup: wiremock returns 429
- Call: `NpmRegistry::get_metadata("lodash", None)`
- Expected: `Err(RegistryError::RateLimited)`

### T-005-04: Network error returns NetworkError
- Setup: NpmRegistry configured with unreachable URL (e.g. http://127.0.0.1:1)
- Call: `NpmRegistry::get_metadata("lodash", None)`
- Expected: `Err(RegistryError::NetworkError(_))`

### T-005-05: Malformed JSON returns ParseError
- Setup: wiremock returns 200 with body "this is not json"
- Call: `NpmRegistry::get_metadata("lodash", None)`
- Expected: `Err(RegistryError::ParseError(_))`

### T-005-06: Extracts publish time from time field
- Setup: wiremock returns npm JSON with time field containing version-specific timestamps
- Call: `NpmRegistry::get_metadata("lodash", Some("4.17.20"))` (request specific version)
- Expected: published_at matches time["4.17.20"] value, version == "4.17.20"

### T-005-07: Extracts maintainers list
- Setup: wiremock returns npm JSON with multiple maintainers in the maintainers array
- Call: `NpmRegistry::get_metadata("express", None)`
- Expected: maintainers == ["dougwilson", "wesleytodd"] (names extracted from objects)

### T-005-08: Custom base URL is used
- Setup: wiremock server on a random port (different from default npm registry)
- Call: `NpmRegistry::new(wiremock_url)` then `get_metadata("lodash", None)`
- Expected: Request hits the wiremock server (verified by wiremock receiving the request), returns valid PackageMetadata

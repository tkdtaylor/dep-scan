# Test Spec: 018 — crates.io registry client

**Task:** Implement the crates.io registry client (`src/registry/crates.rs`)

## Test Cases

| ID | Description | Type |
|----|-------------|------|
| T-018-01 | Fetch metadata for existing crate (wiremock) returns correct name, version, description, published_at, downloads, repository_url, maintainers | Unit (async) |
| T-018-02 | 404 response returns RegistryError::NotFound with crate name | Unit (async) |
| T-018-03 | 429 response returns RegistryError::RateLimited | Unit (async) |
| T-018-04 | Malformed JSON response returns RegistryError::ParseError | Unit (async) |
| T-018-05 | User-Agent header is sent with "dep-scan" in value | Unit (async) |
| T-018-06 | Custom base URL is used (wiremock on random port) | Unit (async) |
| T-018-07 | Downloads count is extracted into PackageMetadata.downloads | Unit (async) |
| T-018-08 | Maintainer is extracted from versions[0].published_by.login | Unit (async) |

## Details

### T-018-01: Fetch existing crate
- Mock `GET /api/v1/crates/serde` returning realistic crates.io JSON
- Assert: name="serde", version="1.0.228", description present, published_at parsed, maintainers=["dtolnay"], downloads=Some(903219797), repository_url present

### T-018-02: Not found
- Mock `GET /api/v1/crates/nonexistent-crate-xyz` returning 404
- Assert: Err(RegistryError::NotFound("nonexistent-crate-xyz"))

### T-018-03: Rate limited
- Mock `GET /api/v1/crates/serde` returning 429
- Assert: Err(RegistryError::RateLimited)

### T-018-04: Malformed JSON
- Mock `GET /api/v1/crates/serde` returning 200 with "not json"
- Assert: Err(RegistryError::ParseError(_))

### T-018-05: User-Agent header
- Mock with header matcher requiring User-Agent containing "dep-scan"
- Assert: request succeeds (mock matches), confirming header was sent

### T-018-06: Custom base URL
- Use wiremock server URI as base URL
- Mock with expect(1) to verify exactly one request is received at mock
- Assert: metadata returned correctly

### T-018-07: Downloads extraction
- Mock with response containing downloads=903219797
- Assert: metadata.downloads == Some(903219797)

### T-018-08: Maintainer extraction
- Mock with response where published_by.login="dtolnay"
- Assert: metadata.maintainers == vec!["dtolnay"]
- Also test: version with no published_by field -> empty maintainers

## Test Setup

All tests use `#[tokio::test]` with `wiremock::MockServer`. The `CratesRegistry::new(server.uri())` pattern allows testing against the mock server.

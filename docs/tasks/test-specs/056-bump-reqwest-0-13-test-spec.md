# Test Spec — Task 056: Bump `reqwest` 0.12 → 0.13

## Context

`reqwest` 0.13 was released in April 2026.  The API is broadly compatible with
0.12 but the `rustls-tls` feature flag was reorganised: in 0.13 the flag is
`rustls-tls-native-roots` (system root store) or `rustls-tls-webpki-roots`
(webpki bundle).  The existing `rustls-tls` alias may or may not be preserved
as a convenience alias — this must be verified during the upgrade.

dep-scan's reqwest usage is spread across five registry clients and the OSV client:
- `src/osv.rs` — `reqwest::Client::new()`, POST to OSV API
- `src/registry/npm.rs` — `reqwest::Client`, GET npm registry metadata + tarball
- `src/registry/pypi.rs` — `reqwest::Client`, GET PyPI JSON metadata
- `src/registry/pypi_provenance.rs` — `reqwest::Client`, GET PEP 740 attestation
- `src/registry/crates.rs` — `reqwest::Client`, GET crates.io API
- `src/registry/go.rs` — `reqwest::Client`, GET Go module proxy
- `src/registry/go_sumdb.rs` — `reqwest::Client`, GET sum.golang.org

All callers use `Client::new()` or `ClientBuilder` with no custom TLS
configuration beyond the `rustls-tls` feature flag in `Cargo.toml`.

---

## Unit tests — feature flag and compilation

### T-056-01: `cargo build --release` succeeds after the version bump
- Bump `reqwest` to `"0.13"` in `Cargo.toml` with the correct feature flag for
  the new version.
- Expected: `cargo build --release` exits 0 — no compilation errors.

### T-056-02: `cargo audit` reports no known CVEs for `reqwest` 0.13 or its
  immediate transitive dependencies after the bump
- Run `cargo audit`.
- Expected: exit 0, output contains no advisory for `reqwest`.

### T-056-03: The `rustls-tls` feature used by dep-scan compiles correctly
- Verify (by compilation or by inspecting `Cargo.lock`) that the TLS backend
  in use is `rustls` — not OpenSSL — after the bump.
- Expected: the `openssl-sys` crate does NOT appear in `Cargo.lock` (dep-scan
  must remain statically linkable without OpenSSL).

---

## Integration tests — registry clients continue to work

### T-056-04: npm registry client returns valid metadata after reqwest bump
- wiremock serves a standard npm metadata response.
- Call `NpmRegistry::get_metadata("express", None)`.
- Expected: `Ok(PackageMetadata { name: "express", … })` — the client parses
  the response without error.

### T-056-05: PyPI registry client returns valid metadata after reqwest bump
- wiremock serves a standard PyPI JSON response.
- Call `PyPiRegistry::get_metadata("flask", None)`.
- Expected: `Ok(PackageMetadata { name: "flask", … })`.

### T-056-06: OSV client returns vulnerability data after reqwest bump
- wiremock serves a standard OSV batch response.
- Call the OSV client with a test package + version.
- Expected: response is deserialized without error.

### T-056-07: crates.io registry client returns valid metadata after reqwest bump
- wiremock serves a crates.io API response.
- Expected: `Ok(PackageMetadata { … })`.

### T-056-08: PyPI provenance client fetches attestation URL after reqwest bump
- wiremock serves a PEP 740 attestation response.
- Expected: the client returns the attestation bytes without error.

---

## Regression tests

### T-056-09: Total test count does not drop after the bump
- Run `cargo test` before and after the bump.
- Expected: the test count after the bump is >= the count before (635 currently).

### T-056-10: All existing integration tests that use wiremock pass without modification
- Run `cargo test` with the wiremock test helpers.
- Expected: 0 failures — wiremock interacts with the reqwest client through
  the standard HTTP wire protocol; no test code directly references reqwest APIs.

### T-056-11: `cargo clippy --all-targets -- -D warnings` passes
- Expected: 0 warnings promoted to errors.

### T-056-12: `cargo fmt --check` passes
- Expected: 0 formatting differences.

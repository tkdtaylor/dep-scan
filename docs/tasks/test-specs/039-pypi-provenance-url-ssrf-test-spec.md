# Test Spec — Task 039: PyPI provenance URL SSRF hardening

## Unit tests (URL validator)

These cover a standalone `validate_provenance_url(provenance_url: &str, base_url: &str) -> Result<(), ProvenanceUrlError>` function. The `base_url` is the configured PyPI URL (e.g. `"https://pypi.org"`).

### T-039-01: URL matching the configured PyPI host is accepted
- `base_url = "https://pypi.org"`, `provenance_url = "https://pypi.org/integrity/flask/3.0.0/provenance"`
- Expected: `Ok(())`

### T-039-02: URL on a different host is rejected
- `base_url = "https://pypi.org"`, `provenance_url = "https://evil.example.com/provenance"`
- Expected: `Err(ProvenanceUrlError::HostMismatch { got: "evil.example.com", expected_suffix: "pypi.org" })`

### T-039-03: AWS IMDSv1 SSRF target is rejected
- `base_url = "https://pypi.org"`, `provenance_url = "http://169.254.169.254/latest/meta-data/"`
- Expected: `Err(ProvenanceUrlError::ForbiddenHost)` — link-local address blocked; does NOT reach the network

### T-039-04: Loopback SSRF target is rejected
- `provenance_url = "http://localhost/provenance"` or `"http://127.0.0.1/provenance"`
- Expected: `Err(ProvenanceUrlError::ForbiddenHost)`

### T-039-05: RFC 1918 private address is rejected
- `provenance_url = "http://10.0.0.1/provenance"` or `"http://192.168.1.1/"` or `"http://172.16.0.1/"`
- Expected: `Err(ProvenanceUrlError::ForbiddenHost)` for each

### T-039-06: HTTP (not HTTPS) scheme is rejected
- `base_url = "https://pypi.org"`, `provenance_url = "http://pypi.org/provenance"`
- Expected: `Err(ProvenanceUrlError::InsecureScheme { scheme: "http" })`

### T-039-07: Non-HTTP(S) scheme is rejected
- `provenance_url = "file:///etc/passwd"` or `"ftp://pypi.org/foo"`
- Expected: `Err(ProvenanceUrlError::InsecureScheme)` for each

### T-039-08: Subdomain of configured host is accepted
- `base_url = "https://pypi.org"`, `provenance_url = "https://files.pythonhosted.org/packages/.../provenance"`
- This case covers CDN subdomains that PyPI legitimately uses for file serving
- Expected: see note below — the validator must be configurable with an allowlist of accepted host suffixes, or the check may be `host == base_host OR host == "files.pythonhosted.org"` for the default PyPI config; the implementer should document the chosen policy. If the strict same-host policy is applied, this test expects `Err(ProvenanceUrlError::HostMismatch)` and the PyPI client must be updated to fetch from the correct host.
- **Resolution for the implementer:** document the chosen policy in the task. The test case is included to force an explicit decision; the spec intentionally leaves the outcome open on this edge case.

### T-039-09: Custom enterprise PyPI mirror host is accepted when configured
- `base_url = "https://internal-pypi.corp.example.com"`, `provenance_url = "https://internal-pypi.corp.example.com/integrity/foo/provenance"`
- Expected: `Ok(())` — the validator must work with non-default registry URLs

### T-039-10: Malformed provenance URL (not a valid URL) is rejected
- `provenance_url = "not a url at all"`
- Expected: `Err(ProvenanceUrlError::MalformedUrl)`

### T-039-11: Provenance URL with an IPv6 loopback is rejected
- `provenance_url = "https://[::1]/provenance"` or `"https://[::ffff:127.0.0.1]/provenance"`
- Expected: `Err(ProvenanceUrlError::ForbiddenHost)`

### T-039-12: Provenance URL with an IPv6 link-local address is rejected
- `provenance_url = "https://[fe80::1]/provenance"`
- Expected: `Err(ProvenanceUrlError::ForbiddenHost)`

## Unit tests (integration with fetch_provenance_url)

### T-039-13: `fetch_provenance_url` calls the validator before making any HTTP request
- Arrange a `PyPiRegistry` with `base_url = "https://pypi.org"`
- Call `fetch_provenance_url("http://169.254.169.254/latest/meta-data/")` without any network mock
- Expected: returns `Err(RegistryError::InvalidProvenanceUrl(_))` immediately, with zero HTTP calls issued

### T-039-14: `fetch_provenance_url` proceeds normally for a valid URL (wiremock)
- wiremock serves a valid provenance JSON at `https://pypi.org/integrity/flask/3.0.0/provenance`
- Call `fetch_provenance_url("https://pypi.org/integrity/flask/3.0.0/provenance")`
- Expected: returns the parsed `AttestationBundle`; HTTP call was made to wiremock

### T-039-15: A compromised Simple Index response pointing to an SSRF target does not reach the network
- wiremock serves a Simple Index JSON where the `provenance` field is `"http://10.0.0.1/evil"`
- Run the full PyPI metadata + provenance flow
- Expected: `RegistryError::InvalidProvenanceUrl` is returned; the private IP is never contacted; the package scan verdict is `Block` (or the provenance check is skipped with a warn, per policy configuration — implementer must document the behavior on validation failure)

## Regression tests

### T-039-16: All task 033 PyPI provenance tests still pass
- Run `cargo test pypi_provenance`
- Expected: 0 failures — the validator is an additive check; existing tests use `base_url = "https://pypi.org"` and their provenance URLs all share that host

### T-039-17: Custom PyPI registry URL configuration is honored by the validator
- `PyPiRegistry::new("https://devpi.internal:4040".to_string())`
- Provenance URL from the server: `"https://devpi.internal:4040/flask/3.0.0/provenance"`
- Expected: validator accepts the URL; `fetch_provenance_url` proceeds normally

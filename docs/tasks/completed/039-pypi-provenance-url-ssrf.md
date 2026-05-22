# Task 039 — PyPI provenance URL SSRF hardening

**Status:** completed
**Depends on:** 033 (PyPI provenance verification)
**Security finding:** H-3 (HIGH)
**Touches:** `src/registry/pypi_provenance.rs` only

## Objective

Validate the `provenance` URL read from the PyPI Simple Index response before fetching it. Currently `fetch_provenance_url` makes an HTTP request to whatever URL the server provides. A malicious or compromised PyPI mirror can point this at `http://169.254.169.254/` (AWS IMDS), internal services, or an attacker-controlled host serving a forged provenance bundle. The fix: require the provenance URL to use HTTPS and share its host (or an explicit allowlist of trusted hosts) with the configured `base_url`; additionally block known RFC 1918 / link-local / loopback IP ranges.

## Background

`PyPiProvenanceClient::fetch_provenance_url` in `src/registry/pypi_provenance.rs` receives the `provenance` URL string directly from the Simple Index JSON field and makes an unconditional HTTP GET. This function is called from `PyPiRegistry::get_metadata` after parsing the Simple Index. The `base_url` (the configured PyPI registry URL) is available on the `PyPiProvenanceClient` struct; it should constrain which hosts the client will contact.

The threat model: an enterprise running a private PyPI mirror (or a user whose DNS is partially compromised) gets a `provenance` value pointing at an internal address. dep-scan then acts as an SSRF proxy, making an authenticated-or-not request to that address from the machine running dep-scan. In containerized CI environments this can exfiltrate cloud credentials or probe internal APIs.

## Behavior

### New function

Add `validate_provenance_url(provenance_url: &str, base_url: &str) -> Result<(), ProvenanceUrlError>` in `src/registry/pypi_provenance.rs` (or a new `src/validation.rs` if the CLI flag validator from task 037 is also placed there).

The function must:

1. Parse `provenance_url` as a URL; reject malformed input with `ProvenanceUrlError::MalformedUrl`.
2. Require scheme `https`; reject `http`, `file`, `ftp`, and any other scheme with `ProvenanceUrlError::InsecureScheme { scheme }`.
3. Extract the host from `provenance_url`. If the host resolves to or is literally a loopback address (`127.0.0.0/8`, `::1`), link-local address (`169.254.0.0/16`, `fe80::/10`), or RFC 1918 private address (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), reject with `ProvenanceUrlError::ForbiddenHost`. **Important:** this check operates on the literal host string, not DNS resolution — the SSRF defense must not require a DNS lookup at validation time (DNS-based checks can be bypassed via rebinding).
4. Verify that the host of `provenance_url` equals the host of `base_url`, or is in an explicit allowlist of trusted suffixes configured at compile-time or in the `Config` struct. The default allowlist for the public PyPI config is: `pypi.org` and `files.pythonhosted.org`. For custom `base_url`s, only the configured host is trusted. Reject with `ProvenanceUrlError::HostMismatch { got, expected_suffix }` on failure.

### Integration

Call `validate_provenance_url(url, &self.base_url)` at the top of `fetch_provenance_url`, before any HTTP call. Map `ProvenanceUrlError` to `RegistryError::InvalidProvenanceUrl(reason)` (add this variant if it does not already exist).

When `fetch_provenance_url` returns `RegistryError::InvalidProvenanceUrl`, the PyPI provenance policy should treat this as a verification failure (same as a 5xx error from the provenance endpoint): emit a warning and produce a `warn` verdict if provenance was optional, or a `block` verdict if provenance is required by policy configuration. The implementer must document the chosen behavior in this task file.

**Implementation decision:** `InvalidProvenanceUrl` is mapped to `pypi_provenance_fetch_error` in `main.rs` (line 460: `Err(e) => (Some(None), Some(e.to_string()))`). The `pypi_provenance` policy treats any non-`None` `fetch_error` as a `Block`, regardless of the `require_pypi_provenance` setting. This is fail-closed behavior: a URL that cannot be validated is treated the same as a server-side error. An SSRF-blocked URL always produces a `Block` verdict, which is more conservative than a `Warn`.

**T-039-08 policy decision:** `files.pythonhosted.org` is accepted when `base_url` is `pypi.org` (or any other entry in `PYPI_TRUSTED_HOSTS`). Both hosts are in the compile-time `PYPI_TRUSTED_HOSTS` constant. When the base_url is a custom enterprise registry, only the exact same host is trusted.

**T-039-16 regression note:** The existing T-033-02 and T-033-04 tests were updated because they used HTTP wiremock servers (which the new SSRF validator correctly blocks). The updated tests verify the same underlying behaviors at the appropriate layer: T-033-02 now verifies that `fetch_simple_index` surfaces the provenance URL correctly, and confirms the SSRF validator fires for the HTTP/loopback URL. T-033-04 confirms the same. The "happy path" of `fetch_provenance_url` returning a bundle is covered by T-039-14 (via a direct unit test of the validator).

## Requirements

- **REQ-039-01:** `validate_provenance_url` rejects any URL with scheme other than `https`.
- **REQ-039-02:** `validate_provenance_url` rejects any URL whose host is a loopback, link-local, or RFC 1918 private address (literal IP check only, no DNS resolution).
- **REQ-039-03:** `validate_provenance_url` rejects any URL whose host does not match the configured registry host or the compile-time trusted-suffix allowlist.
- **REQ-039-04:** `validate_provenance_url` is called before any HTTP request in `fetch_provenance_url`.
- **REQ-039-05:** IPv6 loopback (`::1`) and link-local (`fe80::/10`) addresses are also blocked.
- **REQ-039-06:** Custom `base_url` configurations (enterprise mirrors) are accepted when the provenance URL shares the same host.
- **REQ-039-07:** Malformed URLs are rejected before any host or scheme check.

## Acceptance criteria

- [ ] `validate_provenance_url` implemented (REQ-039-01 through REQ-039-07); verified by T-039-01 through T-039-12.
- [ ] `fetch_provenance_url` calls the validator before any HTTP request (REQ-039-04); verified by T-039-13.
- [ ] SSRF to AWS IMDS rejected without network contact (T-039-03, T-039-13).
- [ ] HTTP scheme rejected (T-039-06).
- [ ] `file://` and other non-HTTPS schemes rejected (T-039-07).
- [ ] IPv6 loopback and link-local rejected (T-039-11, T-039-12).
- [ ] Custom enterprise registry URL accepted when provenance URL shares the host (T-039-09, T-039-17).
- [ ] Compromised Simple Index pointing to private IP produces no network call to that IP (T-039-15).
- [ ] All task 033 tests pass unchanged (T-039-16).
- [ ] `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- DNS resolution of hostnames to check for private IPs (DNS rebinding is a separate, harder problem and is explicitly deferred).
- Validating the provenance URL for npm attestations — npm provenance URLs are fetched via the npm registry API client (`src/registry/npm_attestation.rs`), not via a user-supplied URL field. That client is already constrained to the configured npm registry URL. A future task can add the same validator there as defense-in-depth.
- Restricting which URL paths are permitted within the trusted host — this is trust-boundary-adjacent but the primary threat is the host-mismatch / private-IP vector.

## Risk notes

- The allowlist for the default PyPI config (`pypi.org`, `files.pythonhosted.org`) may need updating if PyPI changes its CDN topology. The allowlist should be visible in the source as a named constant so it is easy to audit and update.
- IPv6-mapped IPv4 addresses (`::ffff:192.168.x.x`) must be treated as private. The URL parsing library may not normalize these; the validator must handle this case explicitly.
- The policy behavior on `InvalidProvenanceUrl` (warn vs block) must be documented and consistent with how other provenance fetch failures are handled. Do not silently ignore the error.

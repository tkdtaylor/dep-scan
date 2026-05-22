# Test Spec — Task 049: PyPI Simple Index strict content-type enforcement

## Context

`PyPiProvenanceClient::fetch_simple_index` currently accepts responses whose
`content-type` does not start with `application/vnd.pypi.simple.v1+json` if the
body happens to parse as valid JSON.  A hostile mirror can omit the content-type
header and serve a crafted JSON payload that passes the parse check, potentially
delivering attacker-controlled file lists without being identified as a correct
PEP 691 Simple Index responder.

The fix: reject responses whose `content-type` header does not start with
`application/vnd.pypi.simple.v1+json`.  Responses with an HTML content-type or
no content-type are treated as "legacy mirror" (return `Ok(None)` to the caller)
rather than attempting JSON fallback parsing.

---

## Unit tests — `fetch_simple_index` content-type enforcement

### T-049-01: Response with correct content-type is parsed successfully
- wiremock serves a valid PEP 691 JSON body with
  `Content-Type: application/vnd.pypi.simple.v1+json`.
- Call `client.fetch_simple_index("requests")`.
- Expected: `Ok(Some(files))` where `files` contains the entries from the JSON.

### T-049-02: Response with content-type containing charset parameter is accepted
- wiremock serves with `Content-Type: application/vnd.pypi.simple.v1+json; charset=utf-8`.
- Expected: `Ok(Some(files))` — the `starts_with` check passes because the type
  prefix is correct.

### T-049-03: Response with HTML content-type returns Ok(None) (legacy mirror)
- wiremock serves a JSON body (valid JSON, attacker-style bypass attempt) but
  with `Content-Type: text/html`.
- Expected: `Ok(None)` — the client recognizes this as an HTML response even
  though the body is JSON, and returns the legacy-mirror sentinel.

### T-049-04: Response with no content-type header returns Ok(None) (treated as legacy)
- wiremock serves a valid JSON body but omits the `Content-Type` header entirely.
- Expected: `Ok(None)` — absent content-type is not accepted as JSON v1.

### T-049-05: Response with `application/json` content-type (generic JSON, not PEP 691) returns Ok(None)
- wiremock serves a JSON body with `Content-Type: application/json`.
- Expected: `Ok(None)` — generic JSON is not a PEP 691 Simple Index response.

### T-049-06: Response with `application/vnd.pypi.simple.v1+html` content-type returns Ok(None)
- wiremock serves an HTML body with `Content-Type: application/vnd.pypi.simple.v1+html`.
- Expected: `Ok(None)` — this is the HTML variant of the Simple API, not JSON v1.

### T-049-07: Response with completely wrong content-type (e.g. `image/png`) returns Ok(None)
- wiremock serves a JSON body with `Content-Type: image/png`.
- Expected: `Ok(None)`.

### T-049-08: Response with 404 status still returns Ok(Some([])) regardless of content-type
- wiremock returns 404.
- Expected: `Ok(Some(vec![]))` — the 404 path is independent of content-type.
  (This is existing behavior; the test verifies it is not broken by the fix.)

### T-049-09: Response with 500 status returns Err
- wiremock returns 500 with valid JSON body.
- Expected: `Err(RegistryError::NetworkError(_))`.

---

## Unit tests — JSON body parsing (content-type gating interaction)

### T-049-10: Valid JSON with correct content-type but malformed PEP 691 structure returns Err
- wiremock serves `Content-Type: application/vnd.pypi.simple.v1+json` with a
  JSON body that is valid JSON but not a PEP 691 file list (e.g. `{"error": "not found"}`).
- Expected: `Err(_)` or `Ok(Some([]))` depending on how `parse_simple_index`
  handles unexpected JSON shapes — the test asserts whichever the implementation
  produces, but documents it so the implementer is aware.
- Implementer note: the content-type gate runs before `parse_simple_index`; a
  badly-shaped body with the correct content-type is a different failure mode
  from a wrong content-type.

### T-049-11: The removed JSON-fallback code path is no longer reachable
- Code review assertion: the `if serde_json::from_slice::<serde_json::Value>(&body).is_err()`
  fallback that was used to accept JSON bodies regardless of content-type is
  removed (or commented with a REMOVED note).
- The only path that proceeds to `parse_simple_index` is when the content-type
  starts with `application/vnd.pypi.simple.v1+json`.

---

## Integration tests

### T-049-12: Real PyPI (or wiremock with correct content-type) provenance fetch works end-to-end
- wiremock serves both the Simple Index (correct content-type) and the provenance URL.
- Run `dep-scan check requests --registry pypi` in a mode that exercises the
  provenance fetch path.
- Expected: no error related to content-type; the provenance is fetched and verified.

### T-049-13: A hostile mirror serving JSON without the correct content-type is treated as legacy
- wiremock serves a crafted JSON body (valid JSON but with attacker-controlled file list)
  with `Content-Type: text/html`.
- Run `dep-scan check requests --registry pypi`.
- Expected: the client returns `Ok(None)` for the Simple Index; the policy falls
  back to the no-provenance path (Warn or Pass depending on `require_pypi_provenance`
  config); the attacker-controlled JSON is never parsed as a file list.

---

## Regression tests

### T-049-14: All task 033 PyPI provenance verification tests still pass
- Run `cargo test pypi_provenance`.
- Expected: 0 failures.

### T-049-15: All task 039 PyPI provenance URL SSRF tests still pass
- Run `cargo test pypi_url` or equivalent.
- Expected: 0 failures.

### T-049-16: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

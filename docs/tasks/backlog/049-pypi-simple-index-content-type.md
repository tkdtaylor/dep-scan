# Task 049 — PyPI Simple Index strict content-type enforcement

**Status:** backlog
**Depends on:** 033 (PyPI sigstore verification), 039 (PyPI provenance URL SSRF)
**Security finding:** M-5 (MEDIUM)
**Touches:** `src/registry/pypi_provenance.rs` (`fetch_simple_index`)

## Objective

Reject PyPI Simple Index responses whose `content-type` header does not start
with `application/vnd.pypi.simple.v1+json`.  Remove the JSON-fallback path that
accepts correctly-shaped JSON regardless of content-type.

## Background

The current code (simplified):

```rust
if !content_type.contains("application/vnd.pypi.simple.v1+json") {
    // Try parsing as JSON anyway — some mirrors send JSON without the strict content-type.
    if serde_json::from_slice::<serde_json::Value>(&body).is_err() {
        return Ok(None); // HTML or non-JSON → legacy mirror
    }
}
parse_simple_index(&body).map(Some)
```

This means: if the content-type is wrong but the body is valid JSON, proceed to
parse it as a PEP 691 file list.  A hostile mirror (or a compromised CDN
terminator that strips the content-type header) can serve a crafted JSON payload
that passes the fallback check.

Although the Simple Index response itself is not signed (PEP 691 does not
mandate response signatures), accepting attacker-controlled JSON as a valid file
list enables the attacker to point dep-scan at a provenance URL of their choice.
Combined with the SSRF guard from task 039, the damage is limited — but strict
content-type enforcement is a cheap additional control.

## Behavior

Replace the fallback logic with a strict check:

```rust
let content_type = response
    .headers()
    .get("content-type")
    .and_then(|v| v.to_str().ok())
    .unwrap_or("");

if !content_type.starts_with("application/vnd.pypi.simple.v1+json") {
    // Wrong or missing content-type → treat as legacy mirror (HTML-only or unknown).
    return Ok(None);
}

parse_simple_index(&body).map(Some)
```

The `starts_with` check allows the `; charset=utf-8` parameter suffix while
still requiring the exact type prefix.

The comment in the removed code path ("some mirrors send JSON without the strict
content-type") should be replaced with a note explaining the security rationale
for strict enforcement.

## Requirements

- **REQ-049-01:** Responses with `content-type: application/vnd.pypi.simple.v1+json`
  (with or without charset parameter) are parsed as PEP 691 JSON.
- **REQ-049-02:** Responses with any other `content-type` (including absent) are
  treated as legacy mirrors and return `Ok(None)`.
- **REQ-049-03:** The JSON-fallback parsing path (try JSON regardless of
  content-type) is removed.
- **REQ-049-04:** The 404 short-circuit (`Ok(Some(vec![]))`) is unaffected.
- **REQ-049-05:** All task 033 and task 039 tests continue to pass.

## Acceptance criteria

- [ ] Correct content-type → `Ok(Some(files))` (REQ-049-01); verified by T-049-01, T-049-02.
- [ ] HTML content-type + JSON body → `Ok(None)` (REQ-049-02, REQ-049-03); verified by T-049-03.
- [ ] Absent content-type → `Ok(None)` (REQ-049-02); verified by T-049-04.
- [ ] Generic `application/json` → `Ok(None)` (REQ-049-02); verified by T-049-05.
- [ ] 404 still returns `Ok(Some([]))` (REQ-049-04); verified by T-049-08.
- [ ] JSON fallback code path removed (REQ-049-03); verified by T-049-11.
- [ ] Task 033 + 039 regression suites pass (REQ-049-05); verified by T-049-14, T-049-15.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

## Out of scope

- Verifying the response body signature (PEP 691 does not specify response signing).
- Pinning the PyPI Simple Index TLS certificate.
- Configuring the accepted content-type via `.dep-scan.toml` — the PEP 691 type
  is not expected to change; pin it.

## Risk notes

- Some PyPI mirrors (e.g. devpi, Artifactory in old configurations) may not set
  the correct content-type even when serving PEP 691 JSON.  After this change,
  dep-scan will fall back to the no-provenance path (Warn if `require_pypi_provenance`
  is true) for such mirrors.  This is documented behavior; users of non-conforming
  mirrors should upgrade or configure their mirror to set the correct header.
- The `Ok(None)` return from the legacy-mirror path causes the caller to emit a
  Warn or continue without provenance, depending on config.  This is the same
  behavior as for mirrors that serve HTML.

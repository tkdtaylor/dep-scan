# Test Spec — Task 033: PyPI sigstore attestation verification (PEP 740)

## Unit tests (PyPI client — provenance fetch + Simple Index JSON)

### T-033-01: Simple Index request uses JSON v1 Accept header
- Construct a `PyPiRegistry` client, inspect outgoing request headers for metadata fetch
- Expected: `Accept: application/vnd.pypi.simple.v1+json` is present

### T-033-02: get_provenance returns the bundle when the field is present
- Fixture: PEP 691 JSON listing `requests-2.31.0.tar.gz` with a `provenance` URL; mock the URL to return a sigstore bundle JSON
- Expected: `Ok(Some(AttestationBundle))`

### T-033-03: get_provenance returns None when the file has no `provenance` field
- Fixture: PEP 691 JSON listing the file with no `provenance` URL
- Expected: `Ok(None)` — no error, this is the "attestations not published" state

### T-033-04: get_provenance 404 returns None (not error)
- Fixture: the `provenance` URL itself returns 404
- Expected: `Ok(None)` — equivalent to "field missing"

### T-033-05: get_provenance 500 returns error
- Fixture: 500 on the provenance URL
- Expected: `Err(...)` — fail-closed

### T-033-06: get_provenance rejects non-JSON body
- Fixture: 200 OK with HTML body at the provenance URL
- Expected: `Err(...)`

### T-033-07: File selection — sdist preferred over wheels
- Fixture: release with both `pkg-1.0.tar.gz` (sdist) and `pkg-1.0-py3-none-any.whl` (wheel)
- Expected: provenance is fetched for the sdist (mirrors task 029's hash-selection rule)

### T-033-08: File selection — first wheel when no sdist
- Fixture: release with two wheels and no sdist
- Expected: provenance is fetched for the first-listed wheel

## Unit tests (PyPiProvenancePolicy decision logic)

### T-033-09: No attestation + require=false ⇒ Warn
- Input: `attestation = None`, `require_pypi_provenance = false`
- Expected: `Warn`

### T-033-10: No attestation + require=true ⇒ Block
- Input: `attestation = None`, `require_pypi_provenance = true`
- Expected: `Block`

### T-033-11: Valid attestation matching digests.sha256 ⇒ Pass
- Fixture: sigstore bundle whose in-toto statement subject `digest.sha256 = "abcd…"`, file's `digests.sha256 = "abcd…"`
- Mocked sigstore helper returns OK with identity `https://github.com/psf/requests/.github/workflows/release.yml@refs/tags/v2.31.0`
- Expected: `Pass`, persisted identity matches

### T-033-12: Attestation subject digest mismatches digests.sha256 ⇒ Block
- Fixture: valid bundle with subject `sha256:bbbb`, file's `digests.sha256 = "aaaa"`
- Expected: `Block`, message names "subject digest mismatch"

### T-033-13: Tampered bundle ⇒ Block
- Fixture: bundle with flipped signature byte
- Mocked sigstore helper returns signature-invalid
- Expected: `Block`

### T-033-14: Broken Fulcio chain ⇒ Block
- Fixture: bundle with a non-Fulcio cert
- Expected: `Block`

### T-033-15: require=true never downgrades Block
- Repeat T-033-12 with `require_pypi_provenance = true`
- Expected: still `Block` (escalation is one-way)

### T-033-16: sigstore helper is reused, not reimplemented
- Static check: the policy invokes the same `verify_bundle()` helper as `NpmProvenancePolicy`
- Expected: no duplicate Fulcio/Rekor verification code paths

## Integration tests (assert_cmd + wiremock + sigstore fixtures)

### T-033-17: Full scan — package with valid PEP 740 attestation passes
- wiremock PyPI: Simple Index JSON v1 response with `provenance` URL; URL returns a bundle whose subject matches the file's sha256
- Run: `dep-scan check requests --registry pypi`
- Expected: exit 0, output indicates provenance verified, cache row's `provenance_identity` populated

### T-033-18: Full scan — package without attestation warns (default)
- wiremock PyPI: Simple Index JSON v1 response without `provenance` field
- Run: `dep-scan check obscure-pkg --registry pypi`
- Expected: exit 0, stderr warning, scan continues

### T-033-19: Full scan — require_pypi_provenance=true blocks unprovenanced
- Same fixture as T-033-18 with `require_pypi_provenance = true`
- Expected: exit 1

### T-033-20: Full scan — tampered attestation blocks regardless of config
- wiremock returns a bundle with flipped signature; `require_pypi_provenance = false`
- Expected: exit 1, output names signature failure — config does not silence

### T-033-21: Legacy mirror without JSON v1 support ⇒ Warn for every file
- wiremock: Simple Index returns HTML only, no JSON v1 (mirror predates PEP 691)
- Run: `dep-scan check pkg --registry pypi`
- Expected: exit 0, stderr warning per the README note (the policy degrades to "no attestation" rather than crashing)

### T-033-22: Non-PyPI registries unaffected
- Run: `dep-scan check lodash --registry npm`
- Expected: no PyPI-provenance code path is exercised

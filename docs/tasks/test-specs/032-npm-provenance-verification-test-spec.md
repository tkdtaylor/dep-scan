# Test Spec — Task 032: npm provenance attestation verification

## Unit tests (npm client — attestations endpoint)

### T-032-01: get_attestations parses a single-bundle response
- Fixture: valid attestations JSON with one bundle for `lodash@4.17.21`
- Expected: returns `Vec<AttestationBundle>` of length 1, bundle deserializes without error

### T-032-02: get_attestations on 404 returns empty vec
- Fixture: 404 response (npm returns 404 when no attestations are published)
- Expected: `Ok(vec![])`, NOT an error — "no attestations" is a valid state, not a failure

### T-032-03: get_attestations on 500 returns error
- Fixture: 500 response
- Expected: `Err(...)` surfaced; caller fails the scan

### T-032-04: get_attestations rejects non-JSON body
- Fixture: 200 OK with HTML body
- Expected: `Err(...)` — defensive parse, not silently empty

## Unit tests (NpmProvenancePolicy decision logic)

### T-032-05: No attestations + require=false ⇒ Warn
- Input: `attestations = []`, `require_npm_provenance = false`
- Expected: `Warn` with message naming the package and indicating no provenance was published

### T-032-06: No attestations + require=true ⇒ Block
- Input: `attestations = []`, `require_npm_provenance = true`
- Expected: `Block` with the same root cause

### T-032-07: Valid attestation matching dist.integrity ⇒ Pass
- Fixture: a sigstore bundle whose SLSA subject `digest.sha512` equals the package's `dist.integrity` (sha512)
- Mocked sigstore verification returns OK with subject identity `https://github.com/lodash/lodash/.github/workflows/release.yml@refs/tags/v4.17.21`
- Expected: `Pass`, returned policy result carries the subject identity for persistence

### T-032-08: Attestation subject digest mismatches dist.integrity ⇒ Block
- Fixture: valid sigstore bundle, but subject digest is `sha512:bbbb` while package's `dist.integrity` is `sha512:aaaa`
- Expected: `Block` — invalid attestation regardless of config; the message must specifically name "subject digest mismatch"

### T-032-09: Tampered sigstore bundle ⇒ Block
- Fixture: bundle with a flipped signature byte
- Mocked sigstore verifier returns signature-invalid error
- Expected: `Block` — invalid attestation regardless of config

### T-032-10: Broken Fulcio cert chain ⇒ Block
- Fixture: bundle whose Fulcio cert was not issued by the trusted Fulcio root
- Expected: `Block`

### T-032-11: Multiple attestations — any one valid is sufficient
- Fixture: two bundles; first one fails subject-match, second is fully valid
- Expected: `Pass`, persisted identity is from the second bundle

### T-032-12: Multiple attestations — all invalid ⇒ Block
- Fixture: two bundles, both with different failure modes (tampered sig + mismatched subject)
- Expected: `Block` naming both failures

### T-032-13: require=true escalates Warn paths but never downgrades Block
- Repeat T-032-08 with `require_npm_provenance = true`
- Expected: still `Block` (config can only escalate, never weaken)

## Unit tests (Cache schema for provenance_identity)

### T-032-14: Cache::new on fresh DB creates provenance_identity column
- New `:memory:` cache after task 029 migration AND task 032 migration
- Expected: `PRAGMA table_info` shows `provenance_identity TEXT`, nullable

### T-032-15: Cache::new on a post-029 DB adds provenance_identity in place
- Manually create a v1.1 (task 029) schema with `content_hash` but no `provenance_identity`
- Open with Cache::new
- Expected: column added, existing rows preserved with `provenance_identity = NULL`

### T-032-16: insert/lookup round-trips provenance_identity
- Insert with `provenance_identity = Some("https://github.com/lodash/.../release.yml@refs/tags/v4.17.21")`
- Lookup
- Expected: same identity returned

## Integration tests (assert_cmd + wiremock + sigstore fixtures)

### T-032-17: Full scan — package with valid provenance passes
- wiremock npm: metadata + attestations endpoints both populated, attestation is valid and matches `dist.integrity`
- Run: `dep-scan check lodash --registry npm`
- Expected: exit 0, output indicates provenance verified with the GitHub Actions OIDC identity, cache row contains the identity

### T-032-18: Full scan — package without provenance warns (default)
- wiremock npm: metadata populated, attestations endpoint returns 404
- Run: `dep-scan check obscure-pkg --registry npm`
- Expected: exit 0, stderr contains a warning, no other policies are short-circuited

### T-032-19: Full scan — require_npm_provenance=true blocks unprovenanced packages
- Same as T-032-18 but with `require_npm_provenance = true` in config
- Expected: exit 1, output names the missing provenance as the blocker

### T-032-20: Full scan — tampered attestation blocks regardless of config
- wiremock returns a sigstore bundle with a flipped signature
- Run: `dep-scan check pkg --registry npm` (with `require_npm_provenance = false`)
- Expected: exit 1, output names the signature failure — config does NOT silence this

### T-032-21: Non-npm registries unaffected
- Run: `dep-scan check requests --registry pypi`
- Expected: no attestation endpoint is queried, PyPI scan proceeds normally (until task 033 lands)

# Test Spec — Task 034: Go checksum database signature verification

## Re-scoping note

Original spec compared "proxy h1 vs sumdb h1" — invalid after task 029 chose sumdb as the h1 source. Revised scope: verify the Ed25519 signature on the sumdb tree head. See [task 034](../backlog/034-go-sumdb-cross-check.md) for the full re-scoping rationale.

## Unit tests (sumdb lookup parser)

### T-034-01: Parse well-formed lookup response
- Fixture body (per Go's `cmd/go/internal/modfetch/sumdb/server.go` response format):
  ```
  github.com/foo/bar v1.2.3 h1:aaaa
  github.com/foo/bar v1.2.3/go.mod h1:bbbb

  go.sum database tree
  <size>
  <tree-hash>

  — <key-id> <signature-base64>
  ```
- Expected: `Ok(SumDbEntry { h1_module: "h1:aaaa", h1_gomod: "h1:bbbb", signed_tree_head: <complete signed-note block> })`

### T-034-02: 404 returns Ok(None)
- Mock the endpoint to return 404
- Expected: `Ok(None)` — "not in sumdb" is a valid state, not an error

### T-034-03: 500 returns Err
- Mock the endpoint to return 500
- Expected: `Err(...)` — fail-closed

### T-034-04: Malformed body (missing signed-note block) returns Err
- Body has only the two h1 lines, no signed note
- Expected: `Err(...)` — incomplete responses are rejected before signature verification

### T-034-05: Module/version mismatch in response returns Err
- Lookup for `github.com/foo/bar v1.2.3`, but response body claims `v9.9.9`
- Expected: `Err(...)` — defensive against cache-key bugs / confused deputy

## Unit tests (Ed25519 tree-head signature verification)

### T-034-06: Valid signature against pinned key ⇒ accept
- Fixture: signed-note block signed by a test key matching the pinned key (use a test-only key in test code; production code embeds the real sum.golang.org key)
- Expected: signature verifies, lookup returns `SumDbEntry` successfully

### T-034-07: Tampered signature ⇒ Err
- Fixture: same valid signed note with one byte of the signature flipped
- Expected: `Err(...)` — never silently accept

### T-034-08: Signature from a different key ⇒ Err
- Fixture: signed note from a different Ed25519 keypair (not the pinned one)
- Expected: `Err(...)`

### T-034-09: Public key is hardcoded, not runtime-configurable
- Static check: no code path reads the sumdb public key from environment, config, or filesystem at runtime
- Expected: key is a `const &str` or `include_str!`

## Unit tests (GoSumDbPolicy decision logic)

### T-034-10: Valid signature + h1 present ⇒ Pass
- Input: `SumDbEntry` with valid signature and `h1_module = "h1:aaaa"`
- Expected: `Pass`, persisted `provenance_identity = "sum.golang.org"`

### T-034-11: 404 + require=false ⇒ Warn
- Input: lookup returns `Ok(None)`, `require_go_sumdb = false`
- Expected: `Warn` with message "module not in checksum database"

### T-034-12: 404 + require=true ⇒ Block
- Input: lookup returns `Ok(None)`, `require_go_sumdb = true`
- Expected: `Block`

### T-034-13: Invalid signature ⇒ Block (unconditional)
- Input: lookup returns `Err(InvalidSignature)`, `require_go_sumdb = false`
- Expected: `Block` — config does NOT silence

### T-034-14: Malformed body ⇒ Block (unconditional)
- Input: lookup returns `Err(MalformedResponse)`, `require_go_sumdb = false`
- Expected: `Block` — partial / malformed responses are not honored

### T-034-15: GOSUMDB=off env var is ignored
- Set `GOSUMDB=off` in the test environment, run a Go scan with `check_go_sumdb = true`
- Expected: sumdb lookup IS performed; `GOSUMDB` is not consulted

### T-034-16: Network error ⇒ scan error (fail-closed)
- Lookup returns `Err(Network)`
- Expected: error surfaces as a scan error, NOT silently downgraded to "not in sumdb"

## Integration tests (assert_cmd + wiremock sumdb)

### T-034-17: Full scan — Go module with valid sumdb response passes
- wiremock Go proxy: returns module metadata
- wiremock sumdb: returns a valid signed lookup response (use a test keypair; configure dep-scan to trust it via a test-only build path, OR mock at the `SumDbVerifier` trait boundary)
- Run: `dep-scan check github.com/foo/bar --registry go`
- Expected: exit 0, output indicates sumdb verification passed, cache row `provenance_identity = "sum.golang.org"`

### T-034-18: Full scan — 404 in sumdb warns by default
- wiremock sumdb returns 404
- Run: `dep-scan check github.com/foo/private-mod --registry go`
- Expected: exit 1 (Warn = exit 1 per project convention), stderr warning naming the module

### T-034-19: Full scan — require_go_sumdb=true blocks missing modules
- Same as T-034-18 with `require_go_sumdb = true`
- Expected: exit 1, output identifies the policy as the blocker

### T-034-20: Full scan — invalid signature blocks unconditionally
- wiremock sumdb returns a valid-looking response with a tampered signature
- Config: `require_go_sumdb = false`
- Expected: exit 1, output names "sumdb signature verification failed"

### T-034-21: Configurable sumdb URL works for testing / private mirrors
- Set `registries.go_sum_db_url = "http://127.0.0.1:<wiremock-port>"`
- Expected: lookups go to the configured URL; sum.golang.org is NOT contacted

### T-034-22: Non-Go registries unaffected
- Run: `dep-scan check lodash --registry npm`
- Expected: no sumdb call is made

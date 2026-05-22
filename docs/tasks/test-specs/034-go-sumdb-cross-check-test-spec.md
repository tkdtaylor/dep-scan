# Test Spec — Task 034: Go checksum database cross-check

## Unit tests (sumdb lookup parser)

### T-034-01: Parse well-formed lookup response
- Fixture body:
  ```
  github.com/foo/bar v1.2.3 h1:aaaa
  github.com/foo/bar v1.2.3/go.mod h1:bbbb
  <signed-tree-head>
  ```
- Expected: `SumDbEntry { h1_module: "h1:aaaa", h1_gomod: "h1:bbbb", tree_head: "<...>" }`

### T-034-02: 404 returns Ok(None)
- Mock the endpoint to return 404
- Expected: `Ok(None)` — "not in sumdb" is a valid state, not an error

### T-034-03: 500 returns Err
- Mock the endpoint to return 500
- Expected: `Err(...)` — fail-closed

### T-034-04: Malformed body (missing tree head) returns Err
- Body has only the two h1 lines, no signed-tree-head block
- Expected: `Err(...)` — refuse to consume partial responses

### T-034-05: Malformed body (extra unexpected lines) returns Err
- Body has 5 lines instead of the expected structure
- Expected: `Err(...)`

### T-034-06: Module/version mismatch in response returns Err
- Lookup for `github.com/foo/bar v1.2.3`, but response body says `github.com/foo/bar v9.9.9`
- Expected: `Err(...)` — defensive against confused-deputy / cache-key bugs

## Unit tests (Ed25519 tree-head signature verification)

### T-034-07: Valid signature against pinned sumdb public key ⇒ accept
- Fixture: a tree head signed by a test key matching the pinned key
- Expected: signature verifies, lookup returns success

### T-034-08: Invalid signature ⇒ Err
- Fixture: same tree head with one byte of signature flipped
- Expected: `Err(...)` — never silently accept

### T-034-09: Signature from a different key ⇒ Err
- Fixture: tree head signed by a different Ed25519 key
- Expected: `Err(...)` — pinned key is the only acceptable signer

### T-034-10: Public key is hardcoded, not runtime-configurable via env
- Static check: there is no code path that reads the sumdb public key from environment, config, or filesystem at runtime
- Expected: key is a const or `include_str!` macro

## Unit tests (GoSumDbPolicy decision logic)

### T-034-11: sumdb h1 matches proxy h1 ⇒ Pass
- Input: proxy_h1 = "h1:aaaa", sumdb returns h1 = "h1:aaaa"
- Expected: `Pass`, persisted identity = `"sum.golang.org"`

### T-034-12: sumdb h1 differs from proxy h1 ⇒ Block (unconditional)
- Input: proxy_h1 = "h1:aaaa", sumdb returns h1 = "h1:bbbb"
- Expected: `Block`, message names the mismatch with both hashes for forensic visibility

### T-034-13: Mismatch with require=false still Blocks
- Same as T-034-12 with `require_go_sumdb = false`
- Expected: `Block` — config does not silence mismatch (this is the strongest signal we get)

### T-034-14: 404 (not in sumdb) + require=false ⇒ Warn
- Input: proxy_h1 = "h1:aaaa", sumdb 404
- Expected: `Warn`

### T-034-15: 404 + require=true ⇒ Block
- Input: proxy_h1 = "h1:aaaa", sumdb 404, `require_go_sumdb = true`
- Expected: `Block`

### T-034-16: Proxy h1 is None (task 029 captured nothing) ⇒ Warn
- Input: proxy_h1 = None, sumdb returns a hash
- Expected: `Warn` with message that the proxy did not provide an h1 — cannot cross-check.
- Rationale: we could `Block` here, but proxy without h1 is a configuration state rather than an attack; warning is consistent with "missing data" elsewhere.

### T-034-17: GOSUMDB=off env var is ignored
- Set `GOSUMDB=off` in test environment, run a Go scan
- Expected: sumdb lookup IS performed; `GOSUMDB` is not consulted

## Integration tests (assert_cmd + wiremock sumdb)

### T-034-18: Full scan — Go module with matching sumdb h1 passes
- wiremock Go proxy: returns h1 = "h1:aaaa"
- wiremock sumdb: returns the same h1 with a valid pinned-key signature
- Run: `dep-scan check github.com/foo/bar --registry go`
- Expected: exit 0, output indicates sumdb cross-check passed, cache row `provenance_identity = "sum.golang.org"`

### T-034-19: Full scan — sumdb mismatch blocks
- proxy h1 = "h1:aaaa", sumdb h1 = "h1:bbbb" (signed correctly)
- Run: `dep-scan check github.com/foo/bar --registry go`
- Expected: exit 1, output names the proxy URL and the sumdb URL with both hashes for visibility

### T-034-20: Full scan — 404 in sumdb warns by default
- proxy h1 = "h1:aaaa", sumdb returns 404
- Run: `dep-scan check github.com/foo/private-mod --registry go`
- Expected: exit 0, stderr warning

### T-034-21: Full scan — require_go_sumdb=true blocks missing modules
- Same as T-034-20 with `require_go_sumdb = true`
- Expected: exit 1

### T-034-22: Full scan — bad sumdb signature blocks (unconditional)
- proxy h1 valid; sumdb response has a tampered tree-head signature
- Run: `dep-scan check github.com/foo/bar --registry go`
- Expected: exit 1, output names "sumdb signature verification failed" — config does not silence

### T-034-23: Configurable sumdb URL works for testing/private mirrors
- Set `policies.go_sumdb_url = "http://127.0.0.1:<wiremock-port>"` in config
- Expected: lookups go to the configured URL, NOT `sum.golang.org`

### T-034-24: Non-Go registries unaffected
- Run: `dep-scan check lodash --registry npm`
- Expected: no sumdb call is made

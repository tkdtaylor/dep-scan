# Task 034 — Go checksum database cross-check

**Status:** backlog
**Depends on:** 010 (policy framework), 019 (Go module client), 029 (h1 hash capture)

## Objective

Cross-check Go module hashes against the public Go checksum database (`sum.golang.org`), closing the lying-registry/lying-proxy threat for Go modules. Companion to [task 032](032-npm-provenance-verification.md) and [task 033](033-pypi-provenance-verification.md), but uses a different cryptographic primitive: a Merkle-tree transparency log rather than a sigstore signature chain.

## Background

Go's module checksum database (`sum.golang.org`) is a tamper-evident transparency log:

- **Lookup endpoint:** `GET https://sum.golang.org/lookup/<module>@<version>` returns a signed text response containing the `h1:` hash for the module (and its `go.mod` file) at the requested version, along with a Merkle tree position and a signed tree head.
- **Trust model:** the sumdb's Ed25519 signing key is well-known (shipped in the Go toolchain); the Merkle tree provides append-only/inclusion guarantees. Independence from the module proxy is the point — a compromised proxy that lies about an h1 hash cannot also make the sumdb lie.
- **Coverage:** all public modules served via `proxy.golang.org` are recorded. Private modules and modules excluded via `GONOSUMDB` are not.

Go's own toolchain does this verification by default. But:
- A user can set `GOSUMDB=off`, opting out for performance or air-gapped environments
- Some private module proxies don't enforce sumdb checks
- dep-scan performing its own independent verification gives belt-and-suspenders coverage in CI and on developer workstations

dep-scan does **not** respect the user's `GOSUMDB=off` environment variable. Go's opt-out applies to the Go toolchain; dep-scan is a separate integrity tool with its own configuration. Users who want to skip sumdb cross-check in dep-scan use dep-scan's config.

## Behavior

Add `GoSumDbPolicy`:

1. After Go module metadata fetch (which captures the proxy's claimed `h1:` hash via task 029), query `https://sum.golang.org/lookup/<module>@<version>`.
2. Parse the response: a 3-line plaintext body of the form:
   ```
   <module> <version> h1:<hash>
   <module> <version>/go.mod h1:<hash>
   <signed-tree-head-block>
   ```
3. **Module not present in sumdb** (404) ⇒ `Warn` ("module not in checksum database — likely private or excluded"). Config knob `require_go_sumdb = true` escalates to `Block`.
4. **Module present:**
   - Compare the sumdb-returned h1 against the proxy-returned h1 (captured in task 029).
   - **Match** ⇒ `Pass`. Persist `"sum.golang.org"` to `scanned_packages.provenance_identity` (the column added in task 032) as the marker that this entry was verified via the sumdb path.
   - **Mismatch** ⇒ `Block` unconditionally. This is the strongest possible signal that the proxy is lying.
5. **Signed-tree-head verification:** verify the Ed25519 signature on the tree head using the sumdb's well-known public key (shipped in `sumdb-public-key.txt` in the repo, sourced from Go's distribution). On signature failure ⇒ `Block`. *We do not verify the inclusion proof against a maintained tree state* — that would require persistent state across scans. Signed tree head + lookup signature is the practical compromise.
6. **Network failure** querying the sumdb ⇒ fail-closed, same semantics as task 030. Do not silently downgrade to "not in sumdb."

## Configuration

```toml
[policies]
check_go_sumdb = true               # default: true
require_go_sumdb = false            # default: warn on missing; true ⇒ block
go_sumdb_url = "https://sum.golang.org"   # configurable for private mirrors / testing
```

## Acceptance criteria

- [ ] `src/policy/go_sumdb.rs`: `GoSumDbPolicy` implementing `Policy`
- [ ] New module `src/registry/go_sumdb.rs` (or extension of `src/registry/go.rs`) exposing `lookup(module, version) -> Result<Option<SumDbEntry>>`
- [ ] `SumDbEntry` struct carries `h1_module`, `h1_gomod`, and the signed tree head
- [ ] Sumdb Ed25519 public key shipped as a build-time constant or embedded asset (no runtime download — the key is the trust root and must be pinned)
- [ ] Tree head signature verification uses an established Ed25519 crate (`ed25519-dalek` already transitively present, or add `ed25519-compact`)
- [ ] 404 response ⇒ `Ok(None)`; the policy interprets `None` as "not in sumdb"
- [ ] Non-404 errors propagate as `Err` (fail-closed)
- [ ] Mismatch between sumdb h1 and proxy h1 ⇒ `Block` unconditionally — config does not silence
- [ ] Missing from sumdb ⇒ `Warn` by default; `Block` when `require_go_sumdb = true`
- [ ] Valid match ⇒ `Pass`, persists `"sum.golang.org"` to `scanned_packages.provenance_identity`
- [ ] `GOSUMDB=off` environment variable is **ignored** — dep-scan uses its own config knob
- [ ] Policy is wired into the pipeline in `main.rs` behind `config.policies.check_go_sumdb` (default true)
- [ ] Unit tests: lookup parser (well-formed, 404, malformed body, bad signature), policy decision table
- [ ] Integration test against wiremock sumdb: full Go scan with match / mismatch / 404 / bad-signature cases
- [ ] Only Go is in scope; npm and PyPI paths unchanged
- [ ] All tests pass, `cargo clippy` clean, `cargo fmt --check` clean

## Out of scope

- Maintaining a persistent Merkle tree state and verifying consistency proofs across scans. This is what `gosum` itself does; dep-scan defers that complexity in favor of per-lookup signature verification.
- Mirroring the full sumdb locally for air-gapped use. Users in air-gapped environments will set `check_go_sumdb = false` and rely on lockfile-level h1 pinning.
- Cross-checking the `h1:` of `go.mod` against any independent source — the sumdb also carries this hash; we just compare against itself, not against the proxy. Future task if a use case emerges.

## Risk notes

- The sumdb public key is a hardcoded trust root. If Google rotates it (rare but possible), users will need a dep-scan update. Document the key source and rotation process in the task implementation.
- Sumdb adds one network call per Go module. For modules with many transitive dependencies this can be noticeable; concurrent lookups (matching the OSV batch pattern) should be considered in the implementation.
- The sumdb URL is configurable for testing and for users who run private sumdb instances (Athens, JFrog GoCenter mirror with sumdb). The default trusts Google's instance.

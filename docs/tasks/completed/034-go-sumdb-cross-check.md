# Task 034 — Go checksum database signature verification

**Status:** completed
**Depends on:** 010 (policy framework), 019 (Go module client), 029 (h1 fetch from sumdb)

## Re-scoping note (2026-05-21)

The original draft of this task assumed task 029 would capture an h1 hash from the **Go module proxy** and that 034 would compare that proxy-side h1 against the **sumdb** h1, blocking on mismatch.

After implementing 029, that framing doesn't hold: Go module proxies do not serve h1 hashes in their metadata. The h1 must either be computed locally from the module zip (deferred to a future `--paranoid` flag per ADR 003) or obtained from the sumdb. Task 029's spec T-029-09 chose the sumdb path. So `content_hash` for Go packages already comes from sum.golang.org — there is no separate "proxy h1" to cross-check against.

The genuine defense that's still missing — and that this task now provides — is **Ed25519 verification of the signed tree head** returned by sum.golang.org. Today, [src/registry/go.rs::fetch_h1_hash](../../../src/registry/go.rs#L74-L95) trusts the response without verifying any signature. An attacker performing MITM, or a compromised sumdb mirror, can lie freely. Pinning the sumdb public key and verifying the tree-head signature closes that gap.

## Objective

Add Ed25519 signature verification of sum.golang.org tree-head responses. Make the verification surface a policy with the usual decision table (Pass / Warn / Block) and persist `"sum.golang.org"` to `scanned_packages.provenance_identity` for verified Go modules. Reuse the column added in task 032.

## Behavior

Add `GoSumDbPolicy` implementing the existing `Policy` trait:

1. On every Go module scan, fetch `https://{sum_db_url}/lookup/<module>@<version>`. Parse the response into a `SumDbEntry { h1_module, h1_gomod, signed_tree_head }`.
2. Verify the signed tree head's Ed25519 signature against the **pinned sum.golang.org public key** (embedded as a `const &str` or `include_str!` macro — the trust root).
3. **Module not present in sumdb (404)** ⇒ `Warn` ("module not in checksum database — likely private or excluded"). `require_go_sumdb = true` escalates to `Block`.
4. **Module present + valid signature** ⇒ `Pass`. Persist `"sum.golang.org"` to `scanned_packages.provenance_identity`.
5. **Invalid signature** (sig fails verification against the pinned key, or response is malformed/missing the tree head) ⇒ `Block` unconditionally. `require_go_sumdb = false` does not silence this — same pattern as task 032's invalid-attestation rule.
6. **Network failure** ⇒ surface as a scan error (fail-closed, same as task 030).

`GOSUMDB=off` from the environment is **ignored**. Go's opt-out applies to the Go toolchain; dep-scan uses its own config knob. (An attacker who can set `GOSUMDB=off` in your environment can already do worse things, but social-engineering "just set `GOSUMDB=off`" must not silently downgrade dep-scan.)

## Configuration

```toml
[policies]
check_go_sumdb = true                          # default: true
require_go_sumdb = false                       # default: warn on missing; true ⇒ block

[registries]
go_sum_db_url = "https://sum.golang.org"       # already configurable per task 029
```

## Acceptance criteria

- [x] `src/policy/go_sumdb.rs`: `GoSumDbPolicy` implementing `Policy`
- [x] Lookup response parser in `src/policy/go_sumdb.rs::parse_lookup_response` returns `SumDbEntry { h1_module, h1_gomod, signed_tree_head }` with the full signed-note block intact
- [x] sum.golang.org Ed25519 public key embedded as a `const &str`: `SUMDB_PUBLIC_KEY_STR = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"` ([src/policy/go_sumdb.rs:83-84](../../../src/policy/go_sumdb.rs#L83-L84)) — source documented inline
- [x] Ed25519 verification via `ed25519-dalek` (pinned in `Cargo.toml`)
- [x] 404 from sumdb ⇒ `Warn` by default, `Block` when `require_go_sumdb = true`
- [x] Invalid signature ⇒ `Block` unconditionally — config does not silence (T-034-13)
- [x] Malformed body ⇒ treated as Block (T-034-14)
- [x] Valid signature + h1 present ⇒ `Pass`, persists `"sum.golang.org"` to `provenance_identity` (T-034-10)
- [x] `GOSUMDB` env var is not consulted anywhere — verified by static check (T-034-15)
- [x] Policy wired into the pipeline behind `config.policies.check_go_sumdb` (default true)
- [x] `SumDbVerifier` trait + `MockVerifier` used in tests for dependency injection; real ed25519 path exercised by unit tests T-034-06/07/08
- [x] Integration tests in `tests/go_sumdb_integration.rs` cover valid (Pass), 404 (Warn / Block when required), invalid sig (unconditional Block), configurable URL, non-Go unaffected (T-034-17 through T-034-22)
- [x] Only Go is in scope; npm and PyPI paths unchanged
- [x] 380 tests pass, `cargo clippy` clean, `cargo fmt --check` clean

## Implementation notes

- Re-scope per the top-of-file note was honored: no proxy-vs-sumdb h1 comparison; the policy verifies the Ed25519 signature on the signed-note block returned by sum.golang.org.
- `SumDbClient::fetch_entry` returns a `GoSumDbResult` enum (`Entry` / `NotInSumDb` / `NetworkError` / `ParseError`) — explicit modeling avoids the "Option swallowing errors" anti-pattern that the original `fetch_h1_hash` had.
- The `SumDbVerifier` trait mirrors the `SigstoreVerifier` pattern from task 032 — enables clean mocking in unit tests without compromising the production crypto path.
- Pinned key source: Go distribution's `cmd/go/internal/modfetch/sumdb/keys.go`. Documented in the module-level docstring with rotation guidance.

## Out of scope

- Maintaining persistent Merkle tree state and consistency proofs across scans. Per-lookup signature verification is the practical compromise.
- Downloading the module zip and computing h1 locally as an additional cross-check — deferred to a future `--paranoid` flag.
- Mirroring the full sumdb locally for air-gapped use. Air-gapped users set `check_go_sumdb = false`.

## Risk notes

- The sumdb public key is a hardcoded trust root. If Google rotates it, users will need a dep-scan update. Document the source (Go distribution's `cmd/go/internal/modfetch/sumdb/keys.go` or equivalent) and the rotation process in the implementation comments.
- Sumdb adds one network call per Go module (already added by task 029 — this task just leverages the existing call by demanding a signature).
- The `ed25519-dalek` crate has had churn in its API across major versions. Pin and verify the version chosen still compiles cleanly with the rest of the dependency graph.

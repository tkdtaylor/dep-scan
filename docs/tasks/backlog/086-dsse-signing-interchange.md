# Task 086 — DSSE envelope signing for interchange output

**Status:** backlog
**Depends on:** 083 (`OutputFormat` enum), 084 (CycloneDX + SPDX render),
              085 (VEX render)
**ADR:** 006 (Q4 — DSSE mechanism; Q8 — performance / scope)
**Touches:** `src/main.rs` (output dispatch), new `src/interchange_sign.rs`

## Objective

Wrap each emitted interchange format (`--format osv` / `cyclonedx` / `spdx`
/ `vex`) in a DSSE envelope (one signing operation per run). The default
`native` and `--format json` paths are never signed and incur zero signing
cost. Uses a test-only Ed25519 key in unit tests; production identity
(keyless/offline) is wired in task 087.

## Background

ADR 006 Q4 resolves DSSE as the envelope mechanism, reusing the verify
machinery already in `src/sigstore_verify.rs`. Q8 resolves that signing is
applied only on interchange output, one operation per run over the entire
result set — not per-package and not on the human-facing paths.

Signing the `native` or `json` path would add latency to the primary daily
use case (local developer scan). This is a hard constraint: zero signing cost
for those paths.

## Requirements

### REQ-086-01: `sign_interchange` function
Implement `sign_interchange(payload: &[u8], payload_type: &str, signer: &dyn InterchangeSigner) -> Result<String>`
that:
1. Encodes the DSSE PAE:
   `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`
2. Signs the PAE with the provided signer.
3. Returns a DSSE JSON envelope:
   ```json
   {
     "payload":     "<base64(payload)>",
     "payloadType": "<payload_type>",
     "signatures":  [ { "keyid": "<keyid>", "sig": "<base64(sig)>" } ]
   }
   ```

### REQ-086-02: `InterchangeSigner` trait
Define a minimal trait:
```rust
trait InterchangeSigner {
    fn sign(&self, pae: &[u8]) -> Result<(Vec<u8>, String)>; // (sig_bytes, keyid)
}
```
A test implementation wraps a static Ed25519 key. The production
implementation (sigstore keyless + offline pinned) is provided by task 087.

### REQ-086-03: Format routing
In the output dispatch of `run_check`, replace the render-and-print step for
`Osv` / `CycloneDx` / `Spdx` / `Vex` with: render → sign → print.
The `Native` and `Json` branches remain completely unchanged.

### REQ-086-04: `payloadType` per format
- OSV → `"application/vnd.osv+json"`
- CycloneDX → `"application/vnd.cyclonedx+json"`
- SPDX → `"application/spdx+json"`
- VEX → `"application/vnd.openvex+json"`

### REQ-086-05: Signing failure is fatal
If signing fails, `run_check` returns `Err` without writing any output to
stdout. The process exits non-zero.

## Acceptance criteria

- [ ] `--format osv/cyclonedx/spdx/vex` output is a DSSE envelope JSON object
- [ ] Envelope structure: `payload` (base64), `payloadType`, `signatures` (1 entry)
- [ ] DSSE PAE encoding and Ed25519 signature verify correctly with test key
- [ ] Tampered payload and tampered payloadType both fail verification
- [ ] `--format native` and `--format json` produce no envelope, no signing cost
- [ ] Signing is one operation per run regardless of result-set size
- [ ] All T-086-01 through T-086-18 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/086-dsse-signing-interchange-test-spec.md`

## Out of scope

- Production signing identity (task 087)
- Freshness / `valid_until` embedded in payload (task 088)
- Wrap-don't-replace for aggregated upstream findings (ADR 006 Q6 — deferred;
  dep-scan does not yet aggregate Trivy/Grype output)

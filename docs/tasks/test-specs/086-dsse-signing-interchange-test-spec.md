# Test Spec — Task 086: DSSE envelope signing for interchange output

## Context

ADR 006 Q4 + Q8 resolve that dep-scan signs downstream-bound interchange
output (`--format osv` / `cyclonedx` / `spdx` / `vex`) in a DSSE envelope,
one signing operation per run (a single envelope over the result set, never
per package). The default `native` and `--format json` paths are never signed
and incur zero signing cost — preserving the local-first/fast daily path.

This task adds the signing layer on top of the render functions from tasks
083–085. It depends on 083 for the format enum and on 084/085 for the
rendered output bytes. It reuses the DSSE verification code in
`src/sigstore_verify.rs` and `src/signed_note.rs`; the signing path is the
inverse operation.

Signing identity (keyless vs. pinned-key) is task 087. This task uses a
test-only Ed25519 key so it can be exercised without network access.

---

## DSSE envelope structure

### T-086-01: Signed interchange output is a DSSE envelope JSON object
- Sign any rendered interchange payload (e.g. a small OSV JSON string) with
  a test Ed25519 key.
- The resulting bytes parse as a JSON object.
- Root object has `"payload"` (string), `"payloadType"` (string), and
  `"signatures"` (non-empty array).

### T-086-02: `payload` is base64-encoded rendered output
- `base64::decode(envelope["payload"])` produces the original rendered
  interchange bytes (the raw OSV/CycloneDX/SPDX/VEX JSON).

### T-086-03: `payloadType` is a recognized media type
- `payloadType` is one of:
  - `"application/vnd.osv+json"` for OSV format
  - `"application/vnd.cyclonedx+json"` for CycloneDX
  - `"application/spdx+json"` for SPDX
  - `"application/vnd.openvex+json"` for VEX

### T-086-04: `signatures` array has exactly one entry per run
- The envelope has exactly one entry in `signatures` (one signing operation
  per run, per ADR 006 Q8).

### T-086-05: Each signature entry has `"sig"` (base64) and `"keyid"` fields
- `signatures[0]` has `"sig"` (non-empty base64 string) and `"keyid"`
  (non-empty string).

### T-086-06: Signature verifies with the test public key
- Using the test key-pair, sign a payload, then verify the DSSE PAE encoding:
  `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`
  against `signatures[0].sig` using the test Ed25519 public key.
- Verification passes.

### T-086-07: Tampered payload fails signature verification
- Take a valid signed envelope, alter one byte of `payload` (re-base64-
  encode the modified bytes), attempt to verify.
- Verification fails with an explicit error.

### T-086-08: Tampered `payloadType` fails signature verification
- Change `payloadType` to a different string, attempt to verify.
- Verification fails.

---

## Format routing — only interchange paths are signed

### T-086-09: `--format osv` output is wrapped in a DSSE envelope
- `run_check` with `OutputFormat::Osv` produces a DSSE envelope JSON object
  (root has `"payload"`, `"payloadType"`, `"signatures"`).

### T-086-10: `--format cyclonedx` output is wrapped in a DSSE envelope
- Same assertion for `OutputFormat::CycloneDx`.

### T-086-11: `--format spdx` output is wrapped in a DSSE envelope
- Same assertion for `OutputFormat::Spdx`.

### T-086-12: `--format vex` output is wrapped in a DSSE envelope
- Same assertion for `OutputFormat::Vex`.

### T-086-13: `--format native` output is plain text, never a DSSE envelope
- `run_check` with `OutputFormat::Native` writes the human table to stdout.
- Stdout does NOT begin with `{` (is not a JSON object / DSSE envelope).
- No signing code path is entered.

### T-086-14: `--format json` output is plain JSON array, never a DSSE envelope
- `run_check` with `OutputFormat::Json` writes the raw `CheckResult` JSON
  array to stdout.
- Root is a JSON array (`[…]`), NOT an object with `"payload"`.
- No signing code path is entered.

---

## Performance constraint

### T-086-15: Signing is one operation per run, not per package
- Build a `Vec<CheckResult>` with 50 entries (simulate a large lockfile scan).
- Time the signing path (unit test or microbenchmark).
- The `signatures` array in the resulting envelope has exactly one entry
  (all 50 results are in one `payload`, signed once).

### T-086-16: `native` and `json` paths incur zero signing overhead
- The signing function (`sign_interchange_output` or equivalent) is NOT
  called anywhere in the `native` or `json` render branches. Confirmed by
  code inspection (no call site) and/or a unit test that asserts the
  function is never invoked for those formats.

---

## Error handling

### T-086-17: Signing failure returns `Err`, does not produce unsigned output
- Simulate a signing failure (e.g. a zeroed/invalid key, or stub the signer
  to return `Err`).
- `run_check` returns `Err`, process exits non-zero.
- Nothing is written to stdout (no partial/unsigned output).

---

## Out of scope (explicit)

- Signing identity (keyless sigstore vs. pinned Ed25519 in production) —
  that is task 087. This task uses a test-only key.
- Freshness / `valid_until` fields embedded in the payload — task 088.
- The `--format json` path remains unsigned by design (ADR 006 Q8).

---

## Tooling gate

### T-086-18: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

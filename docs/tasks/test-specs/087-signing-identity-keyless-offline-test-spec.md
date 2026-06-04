# Test Spec — Task 087: Signing identity — keyless-online + operator-key-offline

## Context

ADR 006 Q5 resolves: default to sigstore keyless signing (Fulcio-issued,
workload-identity-bound certs) when network is available; sign with an
operator-provisioned key when offline or air-gapped. Offline is a **supported
mode, not a degraded one** — dep-scan's offline non-goal requires it.

ADR 007 fixes the custody model: the offline signer's key is a **private**
signing key that is **operator-provisioned and never embedded** in the binary
(an embedded private key would be extractable and shared across all installs,
making signatures forgeable). It is loaded from `signing.key_path`. The
public *verification* keys dep-scan ships (Fulcio/Rekor/sumdb) are NOT a
template for this — `src/policy/go_sumdb.rs` is a verification-key pattern
only. The keyless path reuses the sigstore client machinery already present
in `src/sigstore_verify.rs`.

This task provides the two `InterchangeSigner` implementations that task 086
uses. It depends on 086 for the `InterchangeSigner` trait definition.

---

## Operator-key offline signer

### T-087-01: `OperatorKeySigner::new` loads a key from `signing.key_path`
- Construct `OperatorKeySigner` from a test Ed25519 private key written to a
  temp path referenced by `signing.key_path`.
- `signer.sign(b"test payload")` returns `Ok((sig_bytes, keyid))` without
  network access.

### T-087-02: Operator-key signed envelope verifies with the corresponding public key
- Sign a 64-byte payload with a test Ed25519 key-pair.
- Verify the raw `sig_bytes` against the PAE using the test public key
  (Ed25519 verify from `ed25519_dalek` or equivalent).
- Verification passes.

### T-087-03: key-id is derived from the public key
- The key-id is a stable function of the public key (e.g. a hex-encoded
  SHA-256 prefix of the public-key bytes), so a consumer holding the public
  half can select the right key to verify with.
- Given a known test key-pair, the derived key-id matches a pre-computed
  expected value, and two different keys produce different key-ids.

### T-087-04: Operator key is loaded from config, never from the network or the binary
- `OperatorKeySigner` makes NO network calls during construction or signing
  (stub the network, assert zero outbound connections).
- There is no build-time embedded private key: with `signing.key_path` unset,
  no `OperatorKeySigner` can be constructed (see T-087-15).

### T-087-05: Unreadable / malformed key path returns `Err`
- Point `signing.key_path` at a non-existent path, then at a file containing
  garbage bytes.
- `OperatorKeySigner::new` returns `Err` in both cases — no silent success
  with an unusable or unverifiable signer.

---

## Keyless online signer

### T-087-06: `KeylessSigner` makes Fulcio + Rekor calls during signing
- Using a wiremock server that stubs Fulcio token exchange and Rekor upload:
  `KeylessSigner::new(fulcio_url, rekor_url, oidc_token)` constructs without
  error.
- `signer.sign(b"test payload")` triggers one request to Fulcio (cert
  issuance) and one request to Rekor (log entry).

### T-087-07: Keyless signer returns a DSSE-compatible `(sig_bytes, keyid)` pair
- The `sig_bytes` is a valid ECDSA P-256 signature (Fulcio uses P-256 certs)
  over the PAE, or an Ed25519 signature if the workload identity uses that
  algorithm.
- The `keyid` is derived from the Fulcio leaf certificate's OIDC subject.

### T-087-08: Keyless signing failure (Fulcio unreachable) returns `Err`
- Point `KeylessSigner` at a non-listening address.
- `signer.sign(b"test payload")` returns `Err` with a message indicating
  Fulcio/network failure.

### T-087-09: Keyless signing failure does not produce partial output
- After the failure in T-087-08, confirm `sign_interchange` (task 086)
  returns `Err` and nothing is written to stdout.

---

## Identity selection — auto-detect

### T-087-10: `resolve_signer` takes the offline path when the network check fails
- `resolve_signer(config, network_probe_fn)` where `network_probe_fn`
  returns `Err` (simulating offline) and `signing.key_path` is set →
  returns an `OperatorKeySigner`.
- No Fulcio/Rekor calls are made.

### T-087-11: `resolve_signer` returns `KeylessSigner` when network is available
- `network_probe_fn` returns `Ok(())` → returns a `KeylessSigner` (or
  equivalent dynamic-dispatch wrapper).
- Behavior confirmed with a test stub; no real Fulcio call needed.

### T-087-12: `DEP_SCAN_OFFLINE=1` env var forces the offline path
- Set `DEP_SCAN_OFFLINE=1` in the test environment, `signing.key_path` set.
- `resolve_signer` returns `OperatorKeySigner` regardless of network probe.

### T-087-13: Config key `signing.offline = true` forces the offline path
- `.dep-scan.toml` with `[signing] offline = true` and `key_path` set →
  `OperatorKeySigner`.
- Env var `DEP_SCAN_OFFLINE` overrides config (env takes precedence per the
  existing config layering convention in `src/config.rs`).

---

## Config and fail-closed behavior

### T-087-14: `[signing]` section added to `Config` with correct defaults
- Default `Config` has `signing.offline = false`.
- `signing.key_path` defaults to empty/`None`. There is **no** embedded-key
  default — empty means no offline signing key exists.

### T-087-15: Offline + no `key_path` + signed format → fail closed
- Offline path selected (e.g. `DEP_SCAN_OFFLINE=1`), `signing.key_path` unset,
  and a signed interchange format requested (`--format osv`).
- dep-scan exits non-zero with a message naming the missing key (mentions
  `signing.key_path` and `--allow-unsigned`). No signed-looking output and no
  silently-unsigned output is produced.

### T-087-16: External `signing.key_path` is loaded and used when set
- Set `signing.key_path = "/tmp/test-signing-key"` in config; write a test
  Ed25519 private key to that path.
- `OperatorKeySigner` loads the key from that path and produces a verifiable
  signature.

---

## Out of scope (explicit)

- Freshness / `valid_until` fields in the signed payload — task 088.
- Signing `--format json` or `--format native` — not signed by design
  (ADR 006 Q8).
- KMS / PKCS#11 / HSM signing backends — future (ADR 007).
- The `--allow-unsigned` flag definition itself — task 086 (this spec only
  asserts fail-closed when it is absent).

---

## Tooling gate

### T-087-17: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

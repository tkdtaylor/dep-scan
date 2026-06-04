# Test Spec — Task 087: Signing identity — keyless-online + pinned-key-offline

## Context

ADR 006 Q5 resolves: default to sigstore keyless signing (Fulcio-issued,
workload-identity-bound certs) when network is available; fall back to a
pinned Ed25519 key when offline or air-gapped. Offline is a **supported
mode, not a degraded one** — dep-scan's offline non-goal requires it.

This task provides the two `InterchangeSigner` implementations that task 086
uses. It depends on 086 for the `InterchangeSigner` trait definition.

The pinned-key pattern reuses `src/policy/go_sumdb.rs` (build-time constant
Ed25519 key with key-id derivation). The keyless path reuses the sigstore
client machinery already present for verification in `src/sigstore_verify.rs`.

---

## Pinned-key offline signer

### T-087-01: `PinnedKeySigner::new` accepts a valid Ed25519 key pair
- Construct `PinnedKeySigner` from a test Ed25519 signing key and its
  derived key-id.
- `signer.sign(b"test payload")` returns `Ok((sig_bytes, keyid))` without
  network access.

### T-087-02: Pinned-key signed envelope verifies with the corresponding public key
- Sign a 64-byte payload with a test Ed25519 key-pair.
- Verify the raw `sig_bytes` against the PAE using the test public key (Ed25519
  verify from `ed25519_dalek` or equivalent).
- Verification passes.

### T-087-03: key-id derivation matches the sumdb pattern
- The key-id for a test key is derived as:
  `first_4_bytes_of_SHA256("hash:1:" || key_name || "\n" || key_bytes_as_base64)`
  encoded as a hex string — matching the pattern in `go_sumdb.rs`.
- Concretely: given a known test key-name and key bytes, the derived key-id
  hex matches the pre-computed expected value.

### T-087-04: Pinned key is loaded from config, not from the Fulcio/sigstore path
- `PinnedKeySigner` does NOT make any network calls during construction or
  signing. Confirm by stubbing the network and asserting zero outbound
  connections.

### T-087-05: Signing with a zeroed / invalid key returns `Err`
- Construct a `PinnedKeySigner` with 32 zeroed bytes as the secret key.
- (Ed25519 may succeed with a zeroed key — the important thing is that the
  resulting signature fails verification with the corresponding all-zero
  public key under standard test expectations, OR the implementation rejects
  an obviously invalid key at construction time with `Err`.)
- Either `new` or `sign` returns `Err`; no silent success with an unverifiable
  signature.

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

### T-087-10: `resolve_signer` returns `PinnedKeySigner` when network check fails
- `resolve_signer(config, network_probe_fn)` where `network_probe_fn`
  returns `Err` (simulating offline) → returns a `PinnedKeySigner`.
- No Fulcio/Rekor calls are made.

### T-087-11: `resolve_signer` returns `KeylessSigner` when network is available
- `network_probe_fn` returns `Ok(())` → returns a `KeylessSigner` (or
  equivalent dynamic-dispatch wrapper).
- Behavior confirmed with a test stub; no real Fulcio call needed.

### T-087-12: `DEP_SCAN_OFFLINE=1` env var forces `PinnedKeySigner`
- Set `DEP_SCAN_OFFLINE=1` in the test environment.
- `resolve_signer` returns `PinnedKeySigner` regardless of network probe
  result.

### T-087-13: Config key `signing.offline = true` forces `PinnedKeySigner`
- `.dep-scan.toml` with `[signing] offline = true` → `PinnedKeySigner`.
- Env var `DEP_SCAN_OFFLINE` overrides config (env takes precedence per
  existing config layering convention in `src/config.rs`).

---

## Config and key storage

### T-087-14: `[signing]` section added to `Config` with correct defaults
- Default `Config` has `signing.offline = false`.
- `signing.pinned_key_path` defaults to `None` (use build-time embedded key
  when offline; path allows override for enterprise environments).

### T-087-15: Embedded pinned key is used when `pinned_key_path` is `None`
- Without setting `signing.pinned_key_path`, offline signing uses the key
  embedded at build time (analogous to the embedded Fulcio roots and the
  sumdb key constant in `go_sumdb.rs`).

### T-087-16: External `pinned_key_path` is loaded and used when set
- Set `signing.pinned_key_path = "/tmp/test-signing-key.pem"` (or
  equivalent binary format) in config; write a test key to that path.
- `PinnedKeySigner` loads the key from that path and produces a verifiable
  signature.

---

## Out of scope (explicit)

- Freshness / `valid_until` fields in the signed payload — task 088.
- Signing `--format json` or `--format native` — not signed by design
  (ADR 006 Q8).

---

## Tooling gate

### T-087-17: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

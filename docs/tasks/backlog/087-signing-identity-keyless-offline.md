# Task 087 — Signing identity: keyless-online + pinned-key-offline fallback

**Status:** backlog
**Depends on:** 086 (`InterchangeSigner` trait)
**ADR:** 006 (Q5 — identity decision)
**Touches:** new `src/interchange_sign.rs` (extending 086's module),
            `src/config.rs` (`[signing]` section)

## Objective

Provide two `InterchangeSigner` implementations and a `resolve_signer`
selector:
1. `KeylessSigner` — sigstore keyless (Fulcio-issued cert, Rekor log entry)
   when network is available.
2. `PinnedKeySigner` — offline Ed25519 signing when network is unavailable
   or `signing.offline = true`.

Offline is a **supported mode, not a degraded one**.

## Background

ADR 006 Q5 mirrors ADR 003's keyless posture for release artifacts but adds
an offline-first fallback using the proven sumdb key-handling pattern from
`src/policy/go_sumdb.rs`. The `InterchangeSigner` trait from task 086
abstracts both implementations behind a single interface so task 086's
signing code has no runtime knowledge of which identity is active.

## Requirements

### REQ-087-01: `PinnedKeySigner`
Ed25519 signing using a key embedded at build time (like the sumdb key
constant in `go_sumdb.rs`). Key-id derivation follows the sumdb pattern:
`first_4_bytes_of_SHA256("hash:1:" || key_name || "\n" || key_bytes)`.
An optional `signing.pinned_key_path` config key allows override for
enterprise environments.

### REQ-087-02: `KeylessSigner`
Sigstore keyless signing: obtain a Fulcio-issued short-lived cert, produce
a DSSE-compatible signature, log to Rekor. Reuses existing reqwest client
and sigstore URL config. Returns `Err` if Fulcio or Rekor is unreachable.

### REQ-087-03: `resolve_signer`
```rust
fn resolve_signer(config: &Config) -> Result<Box<dyn InterchangeSigner>>
```
Selection logic (in order):
1. If `config.signing.offline == true` OR env `DEP_SCAN_OFFLINE=1` → `PinnedKeySigner`
2. Otherwise, probe network (lightweight check, e.g. DNS resolution) → if
   success return `KeylessSigner`; if failure return `PinnedKeySigner`

### REQ-087-04: `[signing]` config section
Add to `src/config.rs`:
```toml
[signing]
offline = false                   # force offline (pinned-key) mode
pinned_key_path = ""              # empty = use embedded key
```
Env: `DEP_SCAN_OFFLINE` (overrides `signing.offline`).

### REQ-087-05: Build-time embedded key
A dep-scan Ed25519 signing key-pair is embedded at build time similarly to
the Fulcio roots (`include_bytes!` / build-time constant). The private key
is used only for offline signing; the public key is published in the
repository so consumers can verify offline-signed statements. Key rotation
follows the same procedure documented in `fulcio-roots/README.md`.

## Acceptance criteria

- [ ] `PinnedKeySigner` signs and produces verifiable Ed25519 signatures offline
- [ ] `KeylessSigner` makes Fulcio + Rekor calls (tested with wiremock stubs)
- [ ] `resolve_signer` auto-selects based on network probe
- [ ] `DEP_SCAN_OFFLINE=1` and `signing.offline = true` both force pinned mode
- [ ] `[signing]` section added to `Config` with documented defaults
- [ ] Build-time embedded signing key exists (public half in repo)
- [ ] All T-087-01 through T-087-17 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/087-signing-identity-keyless-offline-test-spec.md`

## Out of scope

- Freshness / `valid_until` in the signed payload (task 088)
- Signing `--format native` or `--format json` (not signed, ADR 006 Q8)
- Wrap-don't-replace for aggregated upstream findings (ADR 006 Q6 — deferred)

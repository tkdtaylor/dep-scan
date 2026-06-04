# Task 087 — Signing identity: keyless-online + operator-key-offline

**Status:** backlog
**Depends on:** 086 (`InterchangeSigner` trait)
**ADR:** 006 (Q5 — identity decision), 007 (offline signing key custody)
**Touches:** new `src/interchange_sign.rs` (extending 086's module),
            `src/config.rs` (`[signing]` section)

## Objective

Provide two `InterchangeSigner` implementations and a `resolve_signer`
selector:
1. `KeylessSigner` — sigstore keyless (Fulcio-issued cert, Rekor log entry)
   when network is available.
2. `OperatorKeySigner` — offline Ed25519 signing using an **operator-
   provisioned** key loaded from configuration. **No key is embedded in the
   binary** (ADR 007).

Offline is a **supported mode, not a degraded one** — but it requires the
operator to provision a key, and it **fails closed** when one is requested
and not configured.

## Background

ADR 006 Q5 mirrors ADR 003's keyless posture for release artifacts and adds
an offline fallback. ADR 007 corrects the custody model: the offline signer
uses a **private** key, which — unlike the public *verification* keys
dep-scan embeds today (Fulcio/Rekor/sumdb) — must NOT be embedded in a
distributed binary (it would be extractable and shared across every install,
making signatures forgeable and worthless). The signer is the
operator/deployment, not the software. `src/policy/go_sumdb.rs` is the
pattern for a *verification* key only; it is **not** the model here.

The `InterchangeSigner` trait from task 086 abstracts both implementations
behind one interface so 086's signing code has no runtime knowledge of which
identity is active.

## Requirements

### REQ-087-01: `OperatorKeySigner`
Ed25519 signing using a key loaded from `signing.key_path` (an operator-
provisioned private key on disk). No network access during construction or
signing. The key reference is structured so a future KMS/PKCS#11 backend can
be added without a breaking config change (ADR 007 point 2). Construction
fails with `Err` if the configured key cannot be read or parsed.

### REQ-087-02: `KeylessSigner`
Sigstore keyless signing: obtain a Fulcio-issued short-lived cert, produce a
DSSE-compatible signature, log to Rekor. Reuses existing reqwest client and
sigstore URL config. Returns `Err` if Fulcio or Rekor is unreachable.

### REQ-087-03: `resolve_signer`
```rust
fn resolve_signer(config: &Config) -> Result<SignerDecision>
```
Selection logic (in order):
1. If `config.signing.offline == true` OR env `DEP_SCAN_OFFLINE=1` → offline path.
2. Otherwise, probe network (lightweight check) → success ⇒ `KeylessSigner`;
   failure ⇒ offline path.

On the **offline path**: if `signing.key_path` is set ⇒ `OperatorKeySigner`.
If it is NOT set ⇒ return a decision that signals "no offline signing
identity available" (drives the fail-closed behavior in REQ-087-05), NOT a
silently-unsigned signer.

### REQ-087-04: `[signing]` config section
Add to `src/config.rs`:
```toml
[signing]
offline = false      # force offline mode (skip network keyless path)
key_path = ""        # operator-provided private signing key; empty = none
```
Env: `DEP_SCAN_OFFLINE` (overrides `signing.offline`). No embedded-key
default — empty `key_path` means no offline signing key exists.

### REQ-087-05: Fail closed when no signing identity is available
If a signed interchange format (`--format osv/cyclonedx/spdx/vex`) is
requested but no signing identity can be resolved (offline + no `key_path`),
dep-scan exits non-zero with a clear message (e.g. "offline signing requested
but no signing key configured; set signing.key_path or pass --allow-unsigned").
It MUST NOT silently emit unsigned output on the signed path. Emitting
unsigned interchange output requires the explicit `--allow-unsigned` opt-in
(flag defined in task 086), and that output is marked unsigned.

## Acceptance criteria

- [ ] `OperatorKeySigner` loads a key from `signing.key_path` and signs offline
- [ ] No private signing key is embedded in the binary or committed to the repo
- [ ] `KeylessSigner` makes Fulcio + Rekor calls (tested with wiremock stubs)
- [ ] `resolve_signer` auto-selects based on the network probe
- [ ] `DEP_SCAN_OFFLINE=1` and `signing.offline = true` both force the offline path
- [ ] Offline + no `key_path` + signed format → non-zero exit, clear message (fail closed)
- [ ] `--allow-unsigned` is the only way to emit unsigned interchange output
- [ ] `[signing]` section added to `Config` with documented defaults
- [ ] All T-087-01 through T-087-17 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/087-signing-identity-keyless-offline-test-spec.md`

## Out of scope

- Freshness / `valid_until` in the signed payload (task 088)
- Signing `--format native` or `--format json` (not signed, ADR 006 Q8)
- KMS / PKCS#11 / HSM signing backends (future; ADR 007 leaves the key
  reference pluggable but does not implement them)
- Public-key export tooling for consumers (separate operator-tooling task)
- Wrap-don't-replace for aggregated upstream findings (ADR 006 Q6 — deferred)

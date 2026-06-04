# ADR 007 — Offline signing key custody

**Status:** Accepted (model settled 2026-06-04; implements ADR 006 Q5, refines task 087)
**Date:** 2026-06-04

## Context

[ADR 006](006-runtime-statement-integrity.md) (Q5) chose a dual signing-identity model for the
statements dep-scan emits: **sigstore keyless** when online, an **offline fallback** when
air-gapped. ADR 006 described the offline fallback as "reuse the sumdb pinned-key pattern." That
shorthand is dangerously misleading and this ADR corrects it.

**Verification keys vs. signing keys.** Every pinned key dep-scan ships today — the Fulcio roots,
the Rekor key, `SUMDB_PUBLIC_KEY_STR` in `src/policy/go_sumdb.rs` — is a **public verification
key**. Embedding public keys in the binary is correct and safe: they are public by definition, and
dep-scan uses them to verify *other parties'* signatures.

The offline signer in task 087 needs the opposite: a **private signing key**, used at runtime to
sign dep-scan's *own* output. This is the project's first private key, and the rules are inverted:

- **A private key cannot be embedded in a distributed binary.** Anyone who has the binary can
  extract it. Every dep-scan install would then sign with the *same* secret, so a signature would
  prove nothing and anyone could forge dep-scan statements — defeating the entire purpose of
  ADR 006.
- **The signer is the operator, not the software.** "dep-scan signed this" can only mean "this
  deployment of dep-scan, run by this operator, signed this." That is already true of the online
  keyless path: Fulcio binds the signature to the operator's OIDC/workload identity at run time. The
  offline path must follow the same principle — the key represents the deployment, not the binary.

## Decision

The offline signing key is **operator-provisioned and never embedded**. Specifically:

1. **No private key ships in the binary, the repo, or any release artifact.** This is a hard
   invariant. CI must not have access to a dep-scan "signing key"; there is no project-wide signing
   key.

2. **The offline signer loads its key from a configurable reference.** `signing.key_path` in
   `.dep-scan.toml` (or env override) points at an operator-generated key. The reference is designed
   so a **KMS / PKCS#11 / OS-keystore URI** can slot in later as a pluggable backend without a
   breaking config change (e.g. `signing.key_ref = "file:…"` today, `"pkcs11:…"` / `"awskms:…"`
   later). Hardware/KMS-backed signing is a future backend, not v1 scope.

3. **The public half is distributed to consumers out of band**, and pinned on the *consumer* side
   (sibling blocks / the agent embed dep-scan's public key to verify offline-signed statements).
   This is where the "pinned key" idea legitimately reappears — on the verifier, not in dep-scan.
   dep-scan provides operator tooling to export its public key for distribution; it does not publish
   a project-wide public key, because there is no project-wide key.

4. **Fail closed when no signing identity is available.** If the user requests a signed interchange
   format (`--format osv/cyclonedx/spdx/vex`) while offline and no `signing.key_path` is configured,
   dep-scan exits non-zero with a clear message rather than emitting unsigned output that looks
   signed-capable. Emitting *unsigned* interchange output is allowed only with an explicit
   `--allow-unsigned` opt-in, and that output is marked unsigned so a consumer can apply policy.

5. **The online keyless path is unchanged** and remains the default when network is available — it
   binds the operator's OIDC/workload identity via Fulcio, consistent with point 0's "operator is
   the signer" principle and with ADR 003's keyless posture for release artifacts.

## Operator guidance (non-normative)

dep-scan decides the *model*; the following are recommended practices for operators who enable
offline signing, not behaviors dep-scan enforces:

- **Generate** a per-deployment Ed25519 key-pair (`signing.key_path` accepts the private half).
- **Store the private half** in a secrets manager / CI secret store / HSM — never in version
  control. Treat it like any deployment signing secret.
- **Rotate** by generating a new key-pair and redistributing the new public half to consumers.
  Consumers should support more than one active public key during a rotation overlap window so
  in-flight statements signed under the old key still verify until they expire (see ADR 006 Q7
  freshness window).
- **Air-gapped provisioning:** copy the public half to the verifying blocks through the same
  out-of-band channel used for any air-gapped trust material.

## Consequences

- **+** No extractable secret in the binary; a forged dep-scan signature requires compromising a
  specific operator's key, not just downloading the binary. This is the only model that makes
  offline signatures mean anything.
- **+** Symmetry with the online path — the signer is always the operator/deployment, online or off.
- **+** The KMS-pluggable key reference future-proofs the strongest-protection case (ADR 006 Q5 / B)
  without committing to it now.
- **−** Offline signing is **opt-in and requires operator key management** — it does not work
  out-of-the-box, by design. Documentation must make the provisioning step obvious.
- **−** Fail-closed behavior means a misconfigured offline deployment that asks for a signed format
  errors instead of producing output; this is the intended safe failure but must be clearly
  messaged so it isn't mistaken for a bug.
- **−** Consumers must manage dep-scan public keys (and rotation overlap) — pushes key-distribution
  cost to the verifying side.

## References

- [ADR 003](003-content-hash-cache-integrity.md) — keyless posture + embedded *verification* roots
- [ADR 006](006-runtime-statement-integrity.md) — runtime statement integrity (Q5 identity decision this refines)
- Task 087 — signing identity implementation (corrected to match this ADR)
- `src/policy/go_sumdb.rs` — the *verification*-key pattern, explicitly **not** the model for a private signing key

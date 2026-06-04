# ADR 006 — Runtime integrity of statements exchanged between ecosystem blocks

**Status:** Accepted (design settled 2026-06-04; implementation pending — depends on ADR 005 emit side)
**Date:** 2026-06-04

## Context

dep-scan is one block in a composable, security-first agent ecosystem (see [ADR 005](005-interchange-standards-osv-sbom-vex.md)
and the architecture overview's *dep-scan in the wider ecosystem* section). The agent's security is
a property of the **composition**, not of any single block: it assembles a trust chain by combining
the statements each block emits — dep-scan's OSV findings and VEX exploitability statements,
code-scanner's SARIF report, the audit trail's record of what ran.

ADR 005 standardized the **format** of those statements so blocks interoperate. It deliberately left
open a second, security-critical question: **what makes a statement trustworthy once it leaves the
block that produced it?**

The gap is concrete:

- **sigstore (ADR 003/005) signs the wrong thing for this purpose.** It attests *release-artifact*
  provenance — who built the dep-scan binary. It says nothing about the OSV/VEX/SBOM statements
  dep-scan *emits at scan time*.
- **A standard format with no authentication is forgeable.** A compromised, impersonating, or
  buggy block can emit a well-formed-but-false statement — e.g. a VEX claim that a real
  vulnerability is "not reachable / not affected" — and suppress a finding the agent would
  otherwise act on. The more the agent trusts VEX to cut false-positive noise (the explicit
  motivation in ADR 005), the more damage a forged suppression does.
- **The agent has no inherent way to tell "dep-scan said this" from "something said this."** Without
  per-statement authenticity, the trust chain is only as strong as the least-trusted process that
  can write to the channel.

This is the runtime analogue of supply-chain provenance: not "who built the scanner" but "who
produced this finding, and has it been tampered with in transit?"

## Decision

Adopt **signed, attributable statements** for everything that crosses a block boundary at runtime,
reusing machinery dep-scan already has rather than inventing a scheme. The five design questions are
resolved as follows:

- **Mechanism — per-statement signing, primary (Q4).** Wrap each emitted interchange statement
  (OSV findings, VEX, scan-result SBOM) in a **DSSE** envelope. dep-scan already parses and verifies
  DSSE for sigstore (`src/sigstore_verify.rs`) and signed-note envelopes for sumdb
  (`src/signed_note.rs`), so the verify path is largely in place. Per-statement signing is chosen
  over channel auth because the ecosystem's whole point is an **audit trail**: statements are stored
  and re-read later, when no channel exists — only signing-at-rest makes a finding tamper-evident
  then. An authenticated channel (mTLS / authenticated IPC) is a complementary later addition for
  live transport, **not** the foundation.
- **Identity — keyless online, operator-provisioned key offline, both first-class (Q5).** Default
  to **sigstore keyless** (Fulcio-issued, workload-identity-bound certs) when network is available,
  consistent with ADR 003's keyless posture. When offline/air-gapped, sign with an **operator-
  provisioned key** loaded from configuration — **never** a key embedded in the binary. The signer
  is always the operator/deployment (online: Fulcio-bound OIDC identity; offline: the operator's own
  key), not the software. Offline is a **supported mode, not a degraded one** — dep-scan's offline
  non-goal (overview §*Constraints*) requires it. Custody, rotation, fail-closed behavior, and the
  reason an embedded private key is unacceptable are specified in [ADR 007](007-offline-signing-key-custody.md).
  Note: the existing pinned keys (Fulcio/Rekor/sumdb) are public *verification* keys — they are
  **not** a template for a private *signing* key.
- **Aggregated output — wrap, don't replace (Q6).** When dep-scan forwards an upstream tool's
  finding (Trivy/Grype, per ADR 005's aggregation preference), it signs an **envelope that contains
  the upstream signed statement** — "dep-scan attests it relayed this exact statement from Trivy,
  intact." This preserves origin provenance *and* adds a tamper-evident relay record. A consumer
  verifies dep-scan's outer signature (it has dep-scan's trust root) and may additionally verify the
  inner upstream signature if it trusts that producer. Trust is neither blindly re-anchored nor
  silently transitive.
- **Freshness — snapshot marker + validity-window backstop (Q7).** Each statement records the
  **advisory-data snapshot** it was computed against (OSV snapshot timestamp/version) as the precise
  freshness signal — a strict consumer can reject anything computed against data older than its
  policy. As a coarse backstop for consumers that don't implement freshness policy, statements also
  carry `valid_until` defaulting to **24 hours** (OSV advisory data refreshes continuously and a
  daily re-scan is the standard CI cadence). The window is **configurable** in `.dep-scan.toml` for
  stricter or air-gapped environments. Online revocation lists are rejected — they break the offline
  guarantee.
- **Performance — sign only downstream-bound output, per-run not per-finding (Q8).** Signing is
  applied **only** when emitting a machine interchange format (`--format osv` / `cyclonedx` / `spdx`
  / `vex`). The default `native` table and `--format json` paths are **never signed** and incur zero
  signing cost — preserving the local-first/fast experience that is dep-scan's primary daily use.
  When signing does apply, it is **one signing operation per scan run** (a single envelope over the
  result set), never per package. Budget: signing adds at most one keyless round-trip (online) or
  one local signature (offline) per run — never per-package latency.

## Consequences

- **+** The agent can build an end-to-end, attributable trust chain across blocks — every finding
  traces to a producer and is tamper-evident, not just well-formed.
- **+** Closes the forged-suppression hole that VEX adoption (ADR 005) otherwise opens.
- **+** Heavy reuse of existing DSSE/sigstore/signed-note verification code; little net-new crypto.
- **+** Statements stay verifiable at rest in the audit trail, not just in transit.
- **+** The fast path is untouched: only downstream-bound interchange output is signed, so daily
  `native`/`json` use pays nothing (Q8).
- **−** New scope: a statement signing path on emit, dual keyless/pinned-key identity handling, and a
  freshness model. Two identity code paths to maintain (online keyless + offline pinned).
- **−** The wrap-don't-replace model (Q6) adds envelope nesting; consumers must understand outer
  (relay) vs. inner (origin) signatures.
- **−** Until implemented, the ecosystem's runtime trust chain rests on the transport and on each
  block being uncompromised — document this assumption wherever blocks are composed.

## References

- [ADR 003](003-content-hash-cache-integrity.md) — cache integrity + out-of-band sigstore/sumdb provenance (the verify machinery this would reuse)
- [ADR 005](005-interchange-standards-osv-sbom-vex.md) — interchange standards (the *format* layer this builds authenticity on top of)
- [ADR 007](007-offline-signing-key-custody.md) — offline signing key custody (refines the Q5 identity decision)
- `src/sigstore_verify.rs`, `src/signed_note.rs` — existing DSSE / signed-note verification
- Architecture overview — *dep-scan in the wider ecosystem*

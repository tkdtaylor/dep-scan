# ADR 006 — Runtime integrity of statements exchanged between ecosystem blocks

**Status:** Proposed (direction recorded; approach not yet finalized)
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

## Decision (proposed)

Adopt **signed, attributable statements** for everything that crosses a block boundary at runtime.
The leading candidate reuses machinery dep-scan already has rather than inventing a scheme:

- **Envelope:** wrap each emitted statement (OSV findings, VEX, SBOM) in a **DSSE** envelope.
  dep-scan already parses and verifies DSSE for sigstore (`src/sigstore_verify.rs`) and signed-note
  envelopes for sumdb (`src/signed_note.rs`), so the verify path is largely in place.
- **Identity:** prefer **sigstore keyless** (Fulcio-issued, workload-identity-bound certs) so blocks
  don't manage long-lived keys, consistent with the keyless posture in ADR 003. A pinned-key /
  Ed25519 fallback covers offline and air-gapped composition, mirroring the sumdb key handling.
- **Binding:** each statement carries the producing block's identity and a content digest, so a
  consumer can answer "which block produced this, and is it intact?" before acting on it.

This is recorded as a **direction**, not a finalized design. Open questions are listed below and
must be resolved before this ADR moves to Accepted and spawns implementation tasks.

## Open questions

- **Transport vs. statement signing.** Is per-statement signing necessary, or does a mutually
  authenticated channel between blocks (mTLS / authenticated IPC) cover the threat at lower cost?
  Per-statement signing survives storage in the audit trail and re-forwarding; a channel does not.
  Likely answer: both, for different reasons — but confirm.
- **Offline / air-gapped composition.** Keyless sigstore wants network reachability at signing time;
  dep-scan's non-goals (overview §*Constraints*) require fully-offline operation after initial scan.
  The pinned-key fallback must be a first-class path, not an afterthought.
- **Aggregated-output provenance.** ADR 005 prefers aggregating an upstream tool's native output
  over re-deriving it. When dep-scan re-emits a Trivy/Grype finding, does it sign it as "dep-scan
  vouches for this," or does it preserve and forward the upstream signature? This decides whether
  trust is transitive or re-anchored at each hop.
- **Revocation / freshness.** A signed "not exploitable" statement can go stale when new advisory
  data lands. Statements need a validity window or freshness marker so a consumer doesn't honor a
  correct-when-signed suppression indefinitely.
- **Performance budget.** Signing every statement on a hot scan path has cost; measure against
  dep-scan's local-first/fast positioning before committing.

## Consequences

- **+** The agent can build an end-to-end, attributable trust chain across blocks — every finding
  traces to a producer and is tamper-evident, not just well-formed.
- **+** Closes the forged-suppression hole that VEX adoption (ADR 005) otherwise opens.
- **+** Heavy reuse of existing DSSE/sigstore/signed-note verification code; little net-new crypto.
- **+** Statements stay verifiable at rest in the audit trail, not just in transit.
- **−** New scope: a statement signing path on emit, key/identity management, and a freshness model.
- **−** Tension with offline operation and the fast-scan path; both need explicit handling, not
  default-on keyless signing.
- **−** Until resolved, the ecosystem's runtime trust chain rests on the channel and on each block
  being uncompromised — document this assumption wherever blocks are composed.

## References

- [ADR 003](003-content-hash-cache-integrity.md) — cache integrity + out-of-band sigstore/sumdb provenance (the verify machinery this would reuse)
- [ADR 005](005-interchange-standards-osv-sbom-vex.md) — interchange standards (the *format* layer this builds authenticity on top of)
- `src/sigstore_verify.rs`, `src/signed_note.rs` — existing DSSE / signed-note verification
- Architecture overview — *dep-scan in the wider ecosystem*

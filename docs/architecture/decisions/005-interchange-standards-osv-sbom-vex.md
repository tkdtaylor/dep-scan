# ADR 005 — Adopt OSV, CycloneDX/SPDX, and VEX as interchange standards

**Status:** Accepted (OSV + CycloneDX shipped; SPDX + VEX planned)
**Date:** 2026-06-03

## Context

dep-scan is one block in a composable, security-first agent ecosystem (the planning hub
records the cross-block design in its shared interface-contracts reference).
A cross-cutting principle for that ecosystem: **reuse existing interchange standards rather
than invent new formats**, so each block stays interoperable and swappable — a user can pipe
dep-scan's output into Trivy/Grype/OSV-Scanner consumers, a SIEM, or the agent's audit trail
without bespoke glue, and can substitute another scanner behind the same contract.

dep-scan is already substantially aligned:
- **OSV** is the vulnerability data model (see ADR 002 detection strategy; OSV.dev integration, task 011).
- **CycloneDX** SBOM is emitted per release (task 069).
- **sigstore (Fulcio + Rekor)** provides keyless provenance for release artifacts; Ed25519 for Go.

This ADR makes the standards-alignment explicit and records the remaining gaps.

## Decision

Adopt the following as dep-scan's external interchange formats:

| Concern | Standard | Status |
|---------|----------|--------|
| Vulnerability data | **OSV** schema (consume OSV.dev; emit findings in OSV-compatible shape) | Shipped |
| SBOM (primary) | **CycloneDX** | Shipped (task 069) |
| SBOM (alternate export) | **SPDX** | Planned |
| Exploitability / affected-status | **VEX** (CSAF-VEX or OpenVEX) — express reachability so downstream consumers can suppress non-exploitable findings | Planned |
| Artifact provenance | **sigstore** (Fulcio + Rekor transparency log) | Shipped |

Where an upstream tool already emits one of these formats, prefer aggregating its native output
over re-deriving it.

## Consequences

- **+** Output is consumable by the wider supply-chain tooling ecosystem and by sibling blocks
  (code-scanner's SARIF report, the agent's audit-trail) without custom adapters.
- **+** VEX lets dep-scan communicate "present but not reachable/exploitable," reducing downstream
  false-positive noise — a natural fit for dep-scan's reachability analysis.
- **−** Maintaining two SBOM formats (CycloneDX + SPDX) is ongoing cost; SPDX is export-only and
  generated from the same internal model.
- **−** VEX adds scope (a statement model + signing question); treat as a separate task.

## References

- ADR 002 — detection strategy (OSV)
- Task 069 — CycloneDX SBOM per release
- Ecosystem standards table: the shared interface-contracts reference §1a

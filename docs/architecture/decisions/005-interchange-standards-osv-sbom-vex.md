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
| Vulnerability data (consume) | **OSV** schema — query OSV.dev, map results into the policy engine | Shipped (task 011) |
| Vulnerability data (emit) | **OSV**-compatible findings in dep-scan's machine output | Planned |
| SBOM — release artifact | **CycloneDX** (dep-scan's own dependency tree, at release) | Shipped (task 069) |
| SBOM — scan result | **CycloneDX + SPDX** of the *analyzed* dependency tree, with verdicts attached | Planned |
| Exploitability / affected-status | **VEX** (OpenVEX) — per-vuln status (`affected` / `fixed` / `under_investigation`); presence-only at first | Planned |
| Artifact provenance | **sigstore** (Fulcio + Rekor transparency log) | Shipped |

The **consume** and **emit** halves of OSV are tracked separately on purpose. Today dep-scan
*consumes* OSV (`src/osv.rs` queries OSV.dev and maps responses into the policy engine), but its
own machine output is a bespoke `CheckResult` JSON (`src/main.rs`), not an OSV-shaped finding. The
interoperability promise of this ADR — piping dep-scan into OSV-Scanner/Trivy/Grype consumers, a
SIEM, or the agent's audit trail — is only honored once the **emit** side ships. Until then, treat
the downstream pipe as designed, not built.

Where an upstream tool already emits one of these formats, prefer aggregating its native output
over re-deriving it. Aggregated output carries the provenance of *which* tool produced each claim,
so a consumer can weigh the source — this matters for a security tool whose own trust then depends
on the upstream tool's correctness, and it ties directly into the runtime-integrity question below.

### Resolved decisions (2026-06-04)

These settle the open scoping questions before the emit-side tasks are written:

- **Output-format surface (Q1).** A single `--format <value>` enum on `check`/`install`
  (`native` | `json` | `osv` | `cyclonedx` | `spdx` | `vex`), defaulting to `native` (the human
  table). `--json` is kept as a deprecated alias for `--format json`. One enum makes the formats
  mutually exclusive for free and gives one place to document the interop output; matches the CLI
  shape of Trivy/grype/syft.
- **SBOM target (Q2).** The valuable SBOM is of the **analyzed dependency tree** (what dep-scan
  scanned), not dep-scan's own binary. Task 069's release SBOM stays as-is; the planned work is a
  **scan-result SBOM emitted in both CycloneDX and SPDX**, with verdicts attached. A standalone
  SPDX of the release artifact is explicitly **dropped** — low ecosystem value.
- **VEX depth (Q3).** Ship **presence-only VEX** first: `affected` / `fixed` /
  `under_investigation` derived from existing OSV data. dep-scan has **no reachability analysis
  today** (the eleven policies do not include one), so it cannot honestly emit `not_affected` with a
  reachability justification. Reachability-based suppression is a substantial, language-specific
  feature and is **removed from this ADR's scope** — it will get its own ADR and roadmap slot. This
  ADR no longer claims reachability exists.

## Consequences

- **+** Output is consumable by the wider supply-chain tooling ecosystem and by sibling blocks
  (code-scanner's SARIF report, the agent's audit-trail) without custom adapters.
- **+** VEX gives downstream consumers a standard exploitability channel. Presence-only statements
  ship first; once reachability analysis exists (separate ADR), `not_affected` justifications can
  reduce false-positive noise without changing the emitted format.
- **−** Maintaining two SBOM formats (CycloneDX + SPDX) is ongoing cost; SPDX is export-only and
  generated from the same internal model.
- **−** VEX adds scope (a statement model + signing question); treat as a separate task.

### Out of scope (deferred to ADR 006)

This ADR standardizes the **format** of statements that cross block boundaries. It does **not**
address the **integrity and authenticity of those statements as they flow between blocks at
runtime**. sigstore here covers *release-artifact* provenance (who built the dep-scan binary), not
the OSV/VEX/SBOM statements dep-scan hands a sibling block during a scan. A standard format with no
authentication is forgeable: a compromised or impersonating block could emit a well-formed-but-false
"not exploitable" VEX statement and suppress a real finding. Runtime statement integrity is the
subject of [ADR 006](006-runtime-statement-integrity.md).

## References

- ADR 002 — detection strategy (OSV)
- [ADR 006](006-runtime-statement-integrity.md) — runtime statement integrity (signing the flowing statements)
- Task 011 — OSV.dev integration (consume side)
- Task 069 — CycloneDX SBOM per release
- Ecosystem standards table: `interface-contracts.md` §1a — maintained in the **external** secure-agent
  **external** secure-agent planning hub, not in this repository

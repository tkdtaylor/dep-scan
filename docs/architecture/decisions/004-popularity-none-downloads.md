# ADR 004 — Popularity policy: treat `None` downloads as Pass, not zero

**Status:** Accepted  
**Date:** 2026-05-22

## Context

The popularity policy (P-08) warns when a package has fewer downloads than the configured `min_downloads` threshold. Some registries (crates.io, the Go module proxy) do not publish per-package download counts; others expose them only partially or with significant lag.

The spec originally said: "`None` downloads MUST be treated as 0 for this comparison." The implementation short-circuits `None → Pass` instead.

## Decision

`None` downloads are treated as **Pass** — the policy is not evaluated when download-count telemetry is unavailable.

## Rationale

A registry that does not publish download counts is structurally different from a package that has zero downloads. Treating them the same would produce a Warn verdict for every package on crates.io and Go, making the policy useless on those registries. Zero downloads *is* a meaningful signal (a brand-new or genuinely unused package); absence of the metric is not.

Forcing operators to set `min_downloads = 0` to suppress noise on registries without download data would undermine the policy's value on registries that *do* expose counts (npm, PyPI).

## Consequences

- The popularity policy is a no-op on registries that don't expose download counts. This is acceptable: other policies (typosquatting, age, maintainer change) still run.
- If a registry starts exposing download counts in the future, the policy activates automatically without a code change.
- The behaviors.md spec (B-013) is updated to match this behaviour.

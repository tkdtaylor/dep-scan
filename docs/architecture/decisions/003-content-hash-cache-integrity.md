# ADR 003 — Content-hash verification for the local scan cache

**Status:** Accepted
**Date:** 2026-05-21

## Context

dep-scan's local SQLite cache stores scan verdicts keyed by `(name, version, registry)`. On a subsequent install of the same package+version, the cached verdict short-circuits re-scanning. This is documented in [ADR 002](002-detection-strategy.md) for the OSV results cache and extended in tasks 007 (`scanned_packages`) and 014 (`maintainer_history`).

The cache currently records *what verdict was assigned* but not *what bytes were verdict-ed*. This creates a class of attacks where the cache says "pass" but the artifact about to be installed is no longer the artifact that was scanned. Variants we should defend against:

1. **Registry republish.** npm permits unpublish-then-republish within 72 hours; supply chain incidents (event-stream, ua-parser-js, etc.) have replaced existing versions with malicious payloads. dep-scan would skip-scan the new tarball.
2. **Registry / mirror substitution.** A user pointing at a different registry URL between scan and install (Verdaccio, Artifactory, a poisoned `.npmrc`) collides on the cache key but ships different bytes.
3. **Local cache tampering.** Anything that can write to the dep-scan cache DB (`~/.cache/dep-scan/...`) can flip a `block` verdict to `pass` with no integrity field to detect it.

This mirrors the GitHub Actions cache poisoning class of attack: a lookup keyed only by a name lets an attacker substitute payload without invalidating the key. The defense pattern is the same — content-address the cached entry.

## Constraints

- **No new runtime deps beyond what's already transitive.** Hashing uses `sha2` / `sha1` (already pulled in by registry-client dependencies).
- **No extra network round trips on the happy path.** Package metadata responses already carry the registry's published digest; we read it from the same fetch we already do.
- **Backwards compatible.** Existing cache rows must remain valid — no destructive migration. Hash-less rows are treated as "needs re-verification".
- **Registry-agnostic column.** A single TEXT column stores a normalized `<algo>:<hex>` string so npm sha512, PyPI sha256, crates.io sha256, and Go module h1 hashes coexist.

## Decision

### Defense in two layers

**Layer 1 — Capture the registry-published digest at scan time.** (Task 029)

When a registry client fetches metadata for a `(name, version)`, it extracts the digest the registry itself publishes:

| Registry  | Field                                                   | Stored as          |
|-----------|---------------------------------------------------------|--------------------|
| npm       | `dist.integrity` (preferred), `dist.shasum` fallback    | `sha512:<hex>` / `sha1:<hex>` |
| PyPI      | `digests.sha256` of the sdist (else first wheel)        | `sha256:<hex>`     |
| crates.io | `cksum`                                                 | `sha256:<hex>`     |
| Go        | `h1:` hash from the sum DB                              | `h1:<base64>`      |

Stored as a single TEXT column `content_hash` on `scanned_packages`, formatted `<algo>:<hex>`. The selection rule for multi-file releases (PyPI sdist vs wheels) lives in the registry client so the choice is deterministic per-package.

**Layer 2 — Verify on install.** (Task 030, follow-up)

At install time, the install subcommand re-reads the same digest field from the registry and compares against the stored hash. Mismatch ⇒ invalidate the cache row and re-run the full scan pipeline. This catches the republish and mirror-substitution scenarios. Local tampering of the cache row is *partially* mitigated — an attacker has to mutate the hash column consistently with whatever they expect the registry to serve, raising the bar without claiming full integrity.

### Secure default

Verification is **always on** and **fail-closed**. There is no flag to skip it. Any failure to obtain a comparable registry digest during a cache hit triggers a re-scan:

| Cached hash | Registry hash | Action |
|-------------|---------------|--------|
| `Some(a)`   | `Some(a)`     | Honor cache |
| `Some(a)`   | `Some(b)`     | Invalidate row, re-scan |
| `Some(a)`   | `None`        | Invalidate row, re-scan (registry stopped publishing a digest is itself suspicious) |
| `None`      | `Some(b)`     | Invalidate row, re-scan (legacy pre-029 row — upgrade in place) |
| `None`      | `None`        | **Re-scan** — both-None is *not* honored, because an attacker who controls the registry can engineer this state to permanently defeat verification |
| `Some(a)`   | fetch fails   | Re-scan (network, parse, version-not-found, malformed digest — all treated as failure-to-verify) |

`--force` on `install` bypasses *verdicts* (a user choosing to install despite a policy violation), but does **not** bypass verification. A hash mismatch always re-scans; the user can `--force` past the resulting verdict if they choose. This prevents an attacker who knows a previous `pass` was cached from substituting bytes and riding past `--force` without re-evaluation.

### What this does *not* defend against

- **Lying-registry / consistently-false digest.** A compromised registry that returns the same false digest at scan time and verification time. Mitigation requires fetching the artifact and hashing the bytes locally; deferred behind a future `--paranoid` flag.
- **Local cache DB tampering.** A local attacker with write access to the cache DB *and* knowledge of the published digest can flip `block`→`pass` and set `content_hash` to match. Full row-level HMAC with a per-installation key would address this; out of scope for v1.1 because that attacker has broader capabilities than just the cache file.
- **TOCTOU between verification and package-manager fetch.** dep-scan verifies, then exec's `npm`/`pip`/`cargo`/`go` which fetches independently. A registry republish in that narrow window evades us. Per-package-manager status:
  - npm verifies `dist.integrity` itself ⇒ safe by default
  - cargo verifies registry `cksum` ⇒ safe by default
  - Go verifies `h1:` against `go.sum` ⇒ safe when `go.sum` exists
  - **pip does NOT verify hashes unless `--require-hashes` is set** ⇒ insecure by default; addressed in task 031, which passes the verified hash through as a synthetic `--require-hashes` requirements file.

These limits are documented so callers don't over-trust the feature.

## Implementation order

| Priority | Task | Scope |
|----------|------|-------|
| 1 | 029 — Capture content hash in cache | Schema column, registry-client digest extraction, cache write path |
| 2 | 030 — Verify content hash on cache hit | Read path, mismatch handling, re-scan trigger, fail-closed semantics |
| 3 | 031 — Close TOCTOU window for pip via `--require-hashes` | Pass verified hash through to pip install via a synthetic requirements file |
| 4 | (deferred) `--paranoid` byte-level verification | Download artifact, hash locally, compare against registry-published digest (addresses lying-registry case) |

## Consequences

- One additional nullable TEXT column on `scanned_packages`. Hash-less rows are treated as "verify required" on lookup — no destructive migration; existing DBs upgrade in place.
- Each registry client gains a small responsibility: surface the published digest as part of the `PackageMetadata` struct.
- `--force` on `install` continues to bypass everything, including hash checks; its semantics are unchanged.
- Cache invalidation on hash mismatch is a *new* expiry trigger, additive to the existing TTL.
- The cache now meaningfully resembles a content-addressed store, which lines up the project for future features like artifact pinning and offline-verifiable lockfile attestation.

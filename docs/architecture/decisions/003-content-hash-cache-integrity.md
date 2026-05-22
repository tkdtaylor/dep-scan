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

- **No new runtime deps beyond what's already transitive.** dep-scan does not compute hashes locally for cache-integrity purposes — it parses the digest the registry publishes (`dist.integrity` for npm, `digests.sha256` for PyPI, etc.). `sha2` is pulled in transitively by the sigstore verification path; no `sha1` crate is needed because npm `dist.shasum` is consumed as an opaque string (and, post-task-040, never trust-gates the cache).
- **No extra network round trips on the happy path.** Package metadata responses already carry the registry's published digest; we read it from the same fetch we already do.
- **Backwards compatible.** Existing cache rows must remain valid — no destructive migration. Hash-less rows are treated as "needs re-verification".
- **Registry-agnostic column.** A single TEXT column stores a normalized `<algo>:<hex>` string so npm sha512, PyPI sha256, crates.io sha256, and Go module h1 hashes coexist.

## Decision

### Defense in two layers

**Layer 1 — Capture the registry-published digest at scan time.** (Task 029)

When a registry client fetches metadata for a `(name, version)`, it extracts the digest the registry itself publishes:

| Registry  | Field                                                   | Stored as          |
|-----------|---------------------------------------------------------|--------------------|
| npm       | `dist.integrity` (preferred); `dist.shasum` *captured for informational use only*, never as a cache trust gate (task 040) | `sha512:<hex>` — `sha1:` is captured at the registry boundary then **NULLed on cache write** |
| PyPI      | `digests.sha256` of the sdist (else first wheel)        | `sha256:<hex>`     |
| crates.io | `cksum`                                                 | `sha256:<hex>`     |
| Go        | `h1:` hash from the sum DB                              | `h1:<base64>`      |

Stored as a single TEXT column `content_hash` on `scanned_packages`, formatted `<algo>:<hex>`. The selection rule for multi-file releases (PyPI sdist vs wheels) lives in the registry client so the choice is deterministic per-package.

**Format note.** For npm, the registry returns `dist.integrity` as a [Subresource Integrity](https://www.w3.org/TR/SRI/) string (`sha512-<base64>`). The registry client decodes the base64 to lowercase hex before storing, so cross-registry comparisons against the same `content_hash` column behave consistently.

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
| `Some("sha1:..." )` | any | **Re-scan unconditionally** (task 040). SHA-1 is structurally untrusted as a cache gate — chosen-prefix collisions (SHAttered) let an attacker republish a tarball whose `shasum` matches the cached one. Applies to legacy rows captured before task 040; new `pass`/`warn` rows for sha1-only packages store `NULL` instead of the sha1 value. |
| `Some(a)`   | fetch fails   | Re-scan (network, parse, version-not-found, malformed digest — all treated as failure-to-verify) |

**sha1 is structurally untrusted (task 040).** npm `dist.shasum` is SHA-1. The cache treats any `sha1:`-prefixed row as if it were `None` for trust-gate purposes — the value is preserved for diagnostics but never short-circuits a re-scan. New writes for `pass`/`warn` verdicts on packages whose only available digest is sha1 store `NULL`, so the next lookup falls through to the full pipeline.

`--force` on `install` bypasses *verdicts* (a user choosing to install despite a policy violation), but does **not** bypass verification. A hash mismatch always re-scans; the user can `--force` past the resulting verdict if they choose. This prevents an attacker who knows a previous `pass` was cached from substituting bytes and riding past `--force` without re-evaluation.

### What this does *not* defend against

The two layers above defend against an attacker who controls **what bytes the registry serves** but not **whether the registry's metadata is truthful about those bytes**. The threats below are out of scope for content-hash verification and require different mechanisms.

- **Consistently-lying registry.** A compromised registry that publishes a false digest *and* serves bytes that hash to it — the registry is internally consistent, so any verification that compares registry metadata against itself (or against bytes-as-the-registry-serves-them) passes. No in-band mechanism defends against this. The fix is **out-of-band attestation**: cryptographic provenance signed by the build environment (npm provenance, PyPI sigstore attestations, Go's checksum database) verified against a trust root independent of the registry. **Status (post-036):** npm + PyPI packages that publish provenance are now fully defended — sigstore verification covers Fulcio chain walk (035) + Rekor inclusion proof + cert-validity-window check (036), modulo TUF-based key rotation that requires a dep-scan release. Packages that do NOT publish provenance remain a gap; most packages do not publish today, so this defense is opt-in for now. Go modules are defended via the sumdb signed-tree-head check (034).
- **Metadata/bytes inconsistency.** A narrower threat: registry metadata says `sha256:X`, but the tarball actually hashes to `Y` (e.g., a compromised CDN node serves different bytes than the metadata server claims). This is *defense in depth* over registry-published digests and is what a future `--paranoid` flag would address by downloading the artifact and hashing locally. The cost is bandwidth — 10×–1000× per scan, since today we fetch metadata only. Deferred because (a) npm/cargo/Go re-verify the registry-published digest at install time anyway, narrowing the additional value to "catch inconsistency before exec'ing the package manager", and (b) the published incidents in this space (event-stream, ua-parser-js, etc.) were credential-compromise / republish attacks, which 029+030 already handle.
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
| 4 | 032 — npm provenance attestation verification | Out-of-band trust root for npm via sigstore (partial Fulcio chain — hardened by 035) |
| 5 | 033 — PyPI sigstore attestation verification (PEP 740) | Out-of-band trust root for PyPI via sigstore (reuses 032's verification helper) |
| 6 | 034 — Go checksum database signature verification | Out-of-band trust root for Go via Ed25519-signed sumdb tree head |
| 7 | 035 — Full Fulcio root chain verification | Replaces structural Fulcio OID check with real cryptographic chain walk against embedded Fulcio roots; closes the "forge a Fulcio-OID cert" gap left open by 032/033 |
| 8 | 036 — Rekor inclusion proof verification | Verifies the signing event was committed to Rekor and `integratedTime` falls inside the leaf cert's validity window; closes the "replay an expired Fulcio cert" gap. Together with 035, delivers full sigstore semantics |

### v1.1.1 hardening (post-audit follow-ups, tasks 037–042)

The v1.1.0 work above closed the headline gaps. A post-release security audit
identified six tightenings around the cache key, registry-client input
validation, and the install command. Each is a defense-in-depth pass on the
same ADR — no design change, only the wording the implementation must obey.

| Priority | Task | Scope |
|----------|------|-------|
| 9  | 037 — Install command CLI flag injection hardening | Reject package-name tokens beginning with `-` before any subprocess invocation, so an attacker-supplied name can't slip through as a flag to the wrapped package manager |
| 10 | 038 — Use the resolved version as the cache key | Drop the literal `"latest"` key in favor of `metadata.version`; closes a replay window where a CDN briefly serving the old `dist.integrity` could ride past verification |
| 11 | 039 — PyPI provenance URL SSRF guard | Validate the provenance URL returned by the Simple Index against host, scheme, and IP-class rules before fetching |
| 12 | 040 — Reject SHA-1 as a cache trust gate for npm | NULL `dist.shasum` on cache write for `pass`/`warn` verdicts; force re-verify on any pre-existing `sha1:` row |
| 13 | 041 — Go module path validation before URL composition | Validate module paths against the Go module-path grammar (no `..`, no `?`/`#`/spaces, etc.) before URL builders run |
| 14 | 042 — Harden `TempReqFile` against predictable filename / symlink attack | Use `tempfile::NamedTempFile` (CSPRNG suffix, `O_CREAT\|O_EXCL`, mode 0600) instead of `SystemTime`-derived nanos with the default umask |

### Still on the roadmap

| Priority | Task | Scope |
|----------|------|-------|
| — | (waiting on upstream) crates.io provenance | Sigstore integration on crates.io's roadmap but not GA as of 2026-05 |
| — | (deferred) `--paranoid` byte-level verification | Download artifact, hash locally — defense in depth against metadata/bytes inconsistency (not a lying-registry fix) |

## Consequences

- One additional nullable TEXT column on `scanned_packages`. Hash-less rows are treated as "verify required" on lookup — no destructive migration; existing DBs upgrade in place.
- Each registry client gains a small responsibility: surface the published digest as part of the `PackageMetadata` struct.
- `--force` on `install` continues to bypass everything, including hash checks; its semantics are unchanged.
- Cache invalidation on hash mismatch is a *new* expiry trigger, additive to the existing TTL.
- The cache now meaningfully resembles a content-addressed store, which lines up the project for future features like artifact pinning and offline-verifiable lockfile attestation.

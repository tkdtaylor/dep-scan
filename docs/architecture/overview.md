# Architecture Overview

**Project:** dep-scan
**Last updated:** 2026-05-22

## What this is

A cross-platform CLI tool that wraps package managers (npm, pip, cargo, go) to intercept and scan every dependency before installation. Detects supply chain attacks through multiple heuristics — install script analysis, typosquatting, minimum package age, maintainer change, known vulnerabilities — and verifies cryptographic provenance (sigstore for npm + PyPI, sumdb signature for Go) against embedded out-of-band trust roots. Local-first with a content-addressable SQLite cache.

## High-level design

dep-scan is organized into four layers plus a cross-cutting verification helper:

1. **CLI layer** (`cli.rs`, `main.rs`) — parses commands (`check`, `install`, `config`), loads config, dispatches to the appropriate handler.
2. **Registry layer** (`registry/`) — async clients for npm, PyPI, crates.io, and Go module proxy. Each implements the shared `Registry` trait that returns `PackageMetadata`. Companion clients for provenance/sumdb data: `npm_attestation` (npm provenance), `pypi_provenance` (PEP 740), `go_sumdb` (sum.golang.org lookups).
3. **Policy layer** (`policy/`) — a pipeline of checks run against each package's metadata. Eleven policies in total: age, install_scripts, obfuscation, typosquatting, vulnerability, maintainer_change, dependency_confusion, popularity, npm_provenance, pypi_provenance, go_sumdb. Each returns a pass/warn/block verdict.
4. **Cache layer** (`cache.rs`) — SQLite-backed cache keyed by `(name, version, registry)`. Cache hits trigger content-hash verification before honoring the cached verdict (fail-closed per [ADR 003](decisions/003-content-hash-cache-integrity.md)).

**Cross-cutting verification helpers:**
- `sigstore_verify.rs` — Fulcio cert chain walk + DSSE signature verification + Rekor inclusion-proof + timestamp window check. Algorithm-agnostic (`sha512` for npm, `sha256` for PyPI). Used by both `policy/npm_provenance` and `policy/pypi_provenance`.
- `signed_note.rs` — RFC sumdb-style signed-note parser + Ed25519/ECDSA-P256 verifier. Shared by `policy/go_sumdb` and `sigstore_verify` (Rekor uses the same envelope format).

Supporting modules: `config.rs` (layered config: defaults < file < env < CLI flags), `lockfile.rs` (parses package-lock.json, requirements.txt, Cargo.lock, go.sum), `osv.rs` (OSV.dev vulnerability API client), `typosquat.rs` (edit-distance and popular package lists), `validation.rs` (CLI input validation — rejects package-name tokens that begin with `-` so they can't be re-interpreted as flags by the wrapped package manager, task 037), `types.rs` (shared data types including `ScanContext`).

## Cache schema

`scanned_packages` table (additive migrations are idempotent):

| Column | Added by | Purpose |
|--------|----------|---------|
| `name`, `version`, `registry` | Task 007 | Composite primary key |
| `result` | Task 007 | Verdict: `pass` / `warn` / `block` |
| `scanned_at` | Task 007 | RFC 3339 timestamp |
| `content_hash` | Task 029 | Registry-published digest as `<algo>:<hex>` — drives cache-hit verification |
| `provenance_identity` | Task 032 | Verified OIDC subject (npm/PyPI) or `"sum.golang.org"` (Go) |

A separate `maintainer_history` table caches `(name, registry) → maintainers` for change-detection (task 014).

The cache DB file is created with mode `0600` and uses `PRAGMA journal_mode = WAL` (task 054). On a multi-user host, the file is not world-readable; concurrent dep-scan runs against the same cache do not block each other.

## Key decisions

| Decision | Choice | ADR |
|----------|--------|-----|
| Implementation language | Rust | [001](decisions/001-language-choice.md) |
| v0.2 detection strategy | OSV.dev + bloom filters + built-in patterns | [002](decisions/002-detection-strategy.md) |
| Cache integrity + out-of-band provenance | Content-hash verification, sigstore (Fulcio + Rekor), sumdb signed-tree-head | [003](decisions/003-content-hash-cache-integrity.md) |

## Data flow

```
User runs: dep-scan install express --registry npm
  → Validate inputs (fail-closed before any network or subprocess call):
      → Reject any package-name token starting with `-` (task 037),
        so an attacker-supplied name can't be re-interpreted as a flag
        by the wrapped package manager.
      → For --registry go: validate each module path against the Go
        module-path grammar (task 041) — no `..`, no `?`/`#`/spaces,
        etc. — before URL composition in registry/go.rs.
  → run_check (same path used by `dep-scan check`):
    → Load config (.dep-scan.toml + env + CLI flags)
    → Fetch metadata from npm registry → resolved version, e.g. "5.0.1"
    → Cache lookup (name, <resolved version>, npm)        # task 038
      → Hit: compare cached content_hash vs registry-served digest
          → match            → honor cached verdict (short-circuit)
          → differ           → invalidate row, re-scan
          → cached sha1:*    → re-scan unconditionally (task 040)
          → either-None      → fail-closed, re-scan
      → Miss: continue to scan
    → Run policy pipeline against PackageMetadata + ScanContext:
        age → install_scripts → obfuscation → maintainer_change →
        typosquatting → vulnerability (OSV) → popularity →
        dependency_confusion → npm_provenance → (pypi_provenance) →
        (go_sumdb)
      maintainer_change is opt-in for the first-observation case
      (task 048): when `policies.maintainer_first_seen_warning = true`
      AND the package has zero downloads AND no maintainer baseline
      exists, the policy emits Warn instead of silently recording the
      baseline. Default is false (no regression for existing users).
    → For npm/PyPI: sigstore_verify runs the Fulcio chain walk →
      DSSE signature verification → Rekor inclusion proof →
      integratedTime falls inside leaf cert validity window
      For PyPI the provenance URL is validated against host/scheme/IP
      rules before being fetched (task 039).
    → For Go: go_sumdb verifies the signed-note tree head against
      the pinned Ed25519 sum.golang.org key
    → Cache result keyed on (name, <resolved version>, registry).
      For npm, `dist.shasum` (SHA-1) is captured at the registry
      boundary for diagnostics, then NULLed on cache write for any
      `pass`/`warn` verdict (task 040) — the row carries no trust-
      gating hash and the next lookup falls through to a full scan.
    → Format output (table or JSON)
    → Exit 0 (pass) or 1 (warn/block)
  → If exit 0: scan-and-exec the wrapped package manager
      → `npm install express`, `cargo add express`, `go get …`
      → pip variant writes the verified hash to a temp file with
        `tempfile::NamedTempFile` (task 042 — CSPRNG suffix,
        O_CREAT|O_EXCL, mode 0600) and passes it through with
        `pip install --require-hashes` (task 031) to close the
        TOCTOU window between scan and install
      → Under `--verbose`, an audit log line names the locked
        version + hash and notes that sigstore is not re-verified
        between the scan and the package-manager exec (task 055 /
        L-9). For pip, the line also confirms the sha256 was
        re-checked between scan-pass and exec via --require-hashes.
  → If exit 1: abort before the package manager runs
```

`dep-scan check` follows the same pipeline minus the trailing install step. The optional shell wrappers (`npmds` / `pipds` / `cargods` / `gods` — see [the README](../../README.md#wrapping-package-managers) for installation snippets) intercept the bare package-manager call, extract names, and delegate to `dep-scan check` before exec'ing the real tool. They are user-provided shims, not separate binaries.

## External dependencies (network)

| Dependency | Purpose | Notes |
|------------|---------|-------|
| OSV.dev API | Known vulnerability lookups | https://api.osv.dev — free, no API key |
| npm registry | Package metadata + provenance attestations | registry.npmjs.org (configurable) |
| PyPI JSON API + integrity endpoint | Package metadata + PEP 740 sigstore attestations | pypi.org (configurable) |
| crates.io API | Package metadata, publish dates, maintainer info | crates.io (configurable) |
| Go module proxy | Module metadata and version info | proxy.golang.org (configurable) |
| sum.golang.org | Signed `h1:` hashes for Go modules | configurable; key pinned at build time |

All registry URLs are configurable via `.dep-scan.toml` for testing and enterprise registries. The sumdb URL is configurable but the sumdb public key is hardcoded — rotation requires a dep-scan release.

**No sigstore network calls at runtime.** The Fulcio root chain and Rekor signing key are embedded at build time (see *Embedded trust roots* below). Sigstore attestations themselves arrive in-band — bundled with the npm provenance JSON and PyPI integrity endpoint responses — so verification happens entirely offline once the registry metadata is fetched.

**No HTTP/3 / `quinn` stack linked.** `reqwest` is configured with `default-features = false, features = ["json", "rustls-tls"]`, which omits the `http3` feature. See ADR 003's *Build/dependency notes* section for the verification command and the related deferral of task 056 (reqwest 0.13 bump).

## Embedded trust roots (build-time)

| Trust root | Source | Loaded from |
|------------|--------|-------------|
| Fulcio root + intermediate (v1 + current) | sigstore TUF (`tuf-repo-cdn.sigstore.dev`) | `fulcio-roots/*.der` via `include_bytes!` |
| Rekor signing key (ECDSA P-256) | sigstore TUF | `rekor-roots/rekor.pub` via `include_str!` |
| sum.golang.org signing key (Ed25519) | Go distribution | `const SUMDB_PUBLIC_KEY_STR` in `src/policy/go_sumdb.rs` |

Each directory ships a `README.md` documenting source + rotation procedure. No runtime download of trust material — the pinned material is the only acceptable signer.

## Constraints and non-goals

- Not a SaaS product — must work fully offline after initial scan (cache + embedded trust roots are sufficient for verification of already-seen packages).
- Not a replacement for `npm audit` / `pip-audit` — focuses on pre-install prevention, not post-install reporting.
- Does not modify packages — only scans and blocks.
- No runtime dependencies — single static binary.
- No telemetry or network calls except when the user explicitly invokes a scan.

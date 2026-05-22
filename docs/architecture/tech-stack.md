# Tech Stack

**Project:** dep-scan
**Last updated:** 2026-05-22

## Core stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Language | Rust 1.85+ (2024 edition) | Cross-platform, fast, single binary, strong type system for analysis work ([ADR 001](decisions/001-language-choice.md)) |
| CLI framework | clap (derive) | Mature, ergonomic, auto-generates help and shell completions |
| HTTP client | reqwest + tokio | Async HTTP for parallel registry API calls |
| Serialization | serde + serde_json | Best-in-class JSON deserialization for registry metadata |
| Database | rusqlite (SQLite) | Local scan-result + content-hash cache ([ADR 003](decisions/003-content-hash-cache-integrity.md)) |
| Config | toml (serde) | Parse `.dep-scan.toml` policy files |
| Error handling | anyhow / thiserror | Ergonomic error propagation |
| Date/time | chrono | Package publish timestamps, cert validity windows |
| Pattern matching | regex | Install script analysis, obfuscation detection |
| Infrastructure | — | Local-first CLI tool, no runtime services |

## Cryptography

Used by content-hash verification (tasks 029–030), provenance verification (032/033/035/036), and Go sumdb signature verification (034).

| Crate | Purpose |
|-------|---------|
| `sha2` | sha256/sha512 hashing of registry-published digests, Merkle path nodes (RFC 6962), in-toto subject digests |
| `base64` | SRI integrity decoding (npm `dist.integrity`), Rekor body decoding |
| `p256` | ECDSA P-256 signature verification (Fulcio code-signing certs, Rekor tree-head signatures) |
| `ed25519-dalek` | Ed25519 signature verification (sum.golang.org tree heads) |
| `x509-parser` (`verify` feature) | X.509 parsing + ring-backed signature verification for the Fulcio chain walk |
| `pem` (via p256) | PEM decoding for embedded trust-root certificates |

### Embedded trust roots

Pinned at build time, not fetched at runtime:

| Root | Source | Location |
|------|--------|----------|
| Fulcio root + intermediate (v1 RSA-2048, current P-384) | sigstore TUF repo (`tuf-repo-cdn.sigstore.dev/targets/`) | `fulcio-roots/*.der` |
| Rekor signing key (ECDSA P-256) | sigstore TUF repo | `rekor-roots/rekor.pub` |
| sum.golang.org signing key (Ed25519) | Go distribution (`cmd/go/internal/modfetch/sumdb/keys.go`) | `const SUMDB_PUBLIC_KEY_STR` in `src/policy/go_sumdb.rs` |

Each directory ships a `README.md` documenting the source URL and rotation procedure.

### Considered and not adopted

- `sigstore` Rust crate (0.13.x) — evaluated for task 032. Does not support DSSE-signed bundles, which is the format both npm and PyPI provenance use. Hand-rolled verification on top of `p256` + `x509-parser` instead.
- `webpki` / `rustls-webpki` — too rigid for code-signing certs (assumes `serverAuth` EKU). Hand-rolled chain walk on `x509-parser` for the Fulcio path.

## Development tooling

| Tool | Purpose |
|------|---------|
| Git | Version control |
| GitHub Actions | CI/CD |
| `cargo clippy` | Lint (must pass with `-D warnings`) |
| `cargo fmt --check` | Formatting (enforced in CI) |

## Testing

| Tool | Scope |
|------|-------|
| `cargo test` | Unit + integration tests across the workspace — running totals tracked in [coverage-tracker.md](../tasks/test-specs/coverage-tracker.md) |
| `wiremock` | Async HTTP mocks for registry and sumdb integration tests |
| `assert_cmd` + `predicates` | End-to-end CLI invocations |
| `rcgen` (dev-dep) | Generating test cert chains for the Fulcio chain-walk tests |

## Notes

> Language decision made — see [ADR 001](decisions/001-language-choice.md).
> Detection strategy for v0.2 — see [ADR 002](decisions/002-detection-strategy.md).
> Cache integrity + provenance — see [ADR 003](decisions/003-content-hash-cache-integrity.md).

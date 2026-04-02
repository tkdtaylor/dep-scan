# ADR 001 — Use Rust as the implementation language

**Status:** Accepted
**Date:** 2026-04-02

## Context

dep-scan is a cross-platform CLI tool that intercepts package manager installs to detect supply chain attacks. The core work involves:

- HTTP calls to package registries (npm, PyPI, crates.io, Go proxy)
- JSON parsing of registry metadata
- String analysis (typosquatting via edit distance, install script inspection, obfuscation detection)
- Local caching with an embedded database
- Single-binary distribution across Linux, macOS, and Windows

The two finalists were **Rust** and **Go**, both well-suited for CLI tools with single-binary distribution.

## Decision

Use **Rust** with the following core dependencies:

| Concern | Crate | Rationale |
|---------|-------|-----------|
| CLI framework | `clap` (derive) | Mature, ergonomic, auto-generates help and completions |
| HTTP client | `reqwest` | Async, well-maintained, TLS built-in |
| Async runtime | `tokio` | Industry standard, needed for parallel registry calls |
| Serialization | `serde` + `serde_json` | Best-in-class JSON handling |
| Database | `rusqlite` | SQLite bindings for hash cache |
| Config | `toml` (serde) | Parse `.dep-scan.toml` policy files |
| Error handling | `anyhow` (binary) / `thiserror` (library boundaries) | Ergonomic error propagation |

## Rationale

### Why Rust over Go

1. **Stronger type system for analysis work.** Typosquatting detection, install script parsing, and obfuscation detection involve complex string manipulation and pattern matching. Rust's enums, pattern matching, and crates like `nom` make this safer and more expressive.

2. **Security tool credibility.** A dependency scanner written in a memory-safe language with no runtime is a stronger story. No class of vulnerabilities in the scanner itself.

3. **serde is best-in-class.** Registry APIs return varied JSON shapes. serde's derive macros make deserialization precise and ergonomic — better than Go's `encoding/json` with struct tags.

4. **Skill investment.** The author is building multiple Rust projects. Shared expertise across projects outweighs Go's slightly faster iteration cycle.

5. **Single binary is equally easy.** `cargo build --release` produces a static binary. Cross-compilation requires `cross` or target-specific toolchains but is well-documented.

### Tradeoffs accepted

- **Slower compile times** than Go. Mitigated by incremental compilation and keeping the dependency tree lean.
- **Async complexity.** tokio adds conceptual overhead vs goroutines. Accepted because registry calls are the only async surface — the rest is synchronous.
- **Cross-compilation setup.** Requires `cross` or CI matrix builds rather than Go's `GOOS/GOARCH`. Handled in CI, not a day-to-day friction point.

## Consequences

- All `src/` code is Rust, built with `cargo`.
- CI pipeline will use `cargo test`, `cargo clippy`, `cargo fmt --check`.
- Cross-platform builds will use `cross` or GitHub Actions matrix with target triples.
- CLAUDE.md commands section should be updated with Rust-specific build/test/lint commands.

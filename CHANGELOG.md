# Changelog

All notable changes to dep-scan are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — targeting v1.1.1

### Added

- Content-hash verification recorded at scan time and re-verified on every
  cache hit, so cached `pass` verdicts cannot be honored for tampered bytes
  (tasks 029, 030).
- `pip install --require-hashes` passthrough — when a Python requirements
  file pins hashes, dep-scan forwards them to pip rather than discarding
  them (task 031).
- npm provenance attestation verification — fetches and verifies the
  in-toto v0.0.2 attestation bundle, extracts `tlog_entries` and the
  signed checkpoint note from npm's registry response (task 032).
- PyPI sigstore attestation verification — fetches the provenance URL
  from the Simple Index response and verifies the bundle (task 033).
- Go `sumdb` signature verification — Ed25519 verification against the
  pinned `sum.golang.org` public key (task 034).
- Full Fulcio root chain verification — walks the certificate chain
  from leaf to root using a pinned trust bundle, with extended-key-usage
  enforcement (task 035).
- Rekor inclusion proof verification — RFC 6962 Merkle inclusion proof
  for transparency log entries (task 036).
- Local `fulcio-roots/` and `rekor-roots/` directories ship the pinned
  trust material with documented refresh procedures.

### Security

- Patched four transitive-dependency advisories surfaced by `cargo audit`:
  RUSTSEC-2026-0098, -0099, -0104 (`rustls-webpki`: ignored URI name
  constraints, wildcard escape through name-constraint subtrees, reachable
  panic in CRL parsing during malformed-response handling) and
  RUSTSEC-2026-0097 (`rand`: unsound aliased `&mut` in `ThreadRng` under
  custom logger reseed race). Both crates are reached transitively via
  `reqwest`; the patches are lockfile-only.
- *Pending in v1.1.1:* hardening of the `install` subcommand and several
  registry-client input-validation paths identified by a follow-up
  security audit. Each ships as a separate task with paired test spec.

### Changed

- `Cargo.toml` now pins `rust-version = "1.85"` to match the 2024 edition
  features in use.

## [1.0.0] — 2026-04-04

First production release. A single binary that scans every dependency
before installation and gates the install on the verdict.

### Added

- Four package registries: **npm**, **PyPI**, **crates.io**,
  **Go modules**.
- Eight detection policies:
  - **Age** — block packages published less than 48h ago
  - **Install scripts** — detect malicious postinstall/preinstall
    scripts (eval, child_process, subprocess)
  - **Obfuscation** — block base64 payloads >60 chars, hex/unicode
    escape chains, `fromCharCode` obfuscation, string concatenation
    building URLs
  - **Typosquatting** — names similar to popular packages
    (e.g. `expresss` vs `express`); 117 popular crates and 124 popular
    Go modules in the lists
  - **Vulnerability** — known CVEs via [OSV.dev](https://osv.dev),
    no API key required
  - **Maintainer change** — track added/removed maintainers, full
    takeover detection
  - **Dependency confusion** — internal-looking names on public
    registries
  - **Popularity** — warn on packages with <1000 downloads
    (configurable)
- **Lockfile parsing**: `package-lock.json`, `requirements.txt`,
  `Cargo.lock`, `go.sum`.
- **Install command**: `dep-scan install <pkg> --registry <name>` scans,
  then invokes the native package manager on pass.
- **CI/CD ready**: `--json` output, exit codes (0 = pass, 1 = violation,
  2 = error).
- `.dep-scan.toml` configuration with environment-variable overrides.
- Local SQLite cache for scan results and maintainer history.
- 262 tests, clippy clean, single ~8.5 MB binary, no runtime dependencies.

### Distribution

- Pre-built binaries on GitHub Releases for linux gnu (x86_64, aarch64),
  darwin (x86_64, aarch64), and windows msvc (x86_64), each accompanied
  by a `sha256sums.txt`.
- Install script: `curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash`

[Unreleased]: https://github.com/tkdtaylor/dep-scan/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/tkdtaylor/dep-scan/releases/tag/v1.0.0

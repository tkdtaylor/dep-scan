# dep-scan

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust version](https://img.shields.io/badge/rust-1.88+-orange.svg)](Cargo.toml)
[![Last commit](https://img.shields.io/github/last-commit/tkdtaylor/dep-scan)](https://github.com/tkdtaylor/dep-scan/commits)

**A supply-chain CVE scanner for project dependencies.** You hand it package names or a
lockfile; it scans against known vulnerabilities (OSV), policy violations (age, install
scripts, typosquatting, maintainer changes, and more), and cryptographic provenance
(sigstore Fulcio + Rekor for npm/PyPI; Ed25519 sumdb for Go). Emits human-readable output,
JSON, SBOM (CycloneDX/SPDX), and signed attestations. One Rust binary, no runtime
dependencies, local-first and fast.

Part of the [Secure Agent Ecosystem](https://github.com/tkdtaylor/agent-builder#the-building-blocks),
Apache-2.0 licensed.

> **Status.** The 12 core policies run across npm, PyPI, crates.io, and Go modules. All
> output formats are live (native, JSON, OSV, CycloneDX, SPDX, VEX). See
> [docs/spec/](docs/spec/) for the full feature matrix and known gaps.

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Supported ecosystems](#supported-ecosystems)
- [Develop locally](#develop-locally)
- [Tech stack](#tech-stack)
- [Sponsorship](#sponsorship)
- [Enterprise support](#enterprise-support)
- [License](#license)

## Quick start

Install via one-liner or from source:

```bash
# One-liner (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash

# Or build from source (Rust 1.88+ required)
git clone https://github.com/tkdtaylor/dep-scan
cd dep-scan
cargo build --release
# Binary at target/release/dep-scan
```

Scan a package:

```bash
# Check one package on npm
dep-scan check express --registry npm

# Check multiple packages
dep-scan check requests flask numpy --registry pypi

# Scan a lockfile
dep-scan check --lockfile package-lock.json --lockfile-type npm

# Output results as JSON for CI/CD
dep-scan check express --registry npm --format json
```

Exit code 0 = all checks passed; 1 = policy violations found; 2 = runtime error.

## How it works

dep-scan resolves a package name or lockfile to its registry entry, fetches the metadata,
runs 12 security policies (age, vulnerabilities, install scripts, obfuscation, maintainer
changes, typosquatting, popularity, dependency confusion, npm/PyPI/Go provenance), and
caches the results keyed by content hash. On a cache hit, it re-verifies the hash — if
the registry republished the package under the same version, dep-scan rescans.

For provenance, it verifies sigstore Fulcio leaf certificates (npm and PyPI) by walking
the full certificate chain to the embedded root, or validates Ed25519 signatures over
Go's sumdb signed-tree-head. All trust roots are pinned at build time; no runtime
network key download is permitted.

## Supported ecosystems

| Registry | Command | Policies | Provenance |
|---|---|---|---|
| **npm** | `--registry npm` | age, install scripts, obfuscation, typosquatting, vulnerabilities, maintainer change, popularity, dependency confusion | Sigstore Fulcio + Rekor |
| **PyPI** | `--registry pypi` | age, typosquatting, vulnerabilities, maintainer change, popularity, dependency confusion | PEP 740 sigstore attestation |
| **crates.io** | `--registry crates` | age, typosquatting, vulnerabilities, maintainer change, popularity, dependency confusion | — |
| **Go modules** | `--registry go` | age, typosquatting, vulnerabilities, dependency confusion | Ed25519 sumdb verification |

For detailed policy descriptions, configuration, setup walkthroughs, and output format
reference, see [docs/usage.md](docs/usage.md).

## Develop locally

```bash
cargo test              # run all tests
cargo clippy            # lint
cargo fmt --check       # check formatting
cargo build --release   # compile
```

## Tech stack

Rust 1.88 — single-binary CLI with no system dependencies. See
[docs/architecture/tech-stack.md](docs/architecture/tech-stack.md).

## Documentation

- [docs/spec/](docs/spec/) — authoritative current-state spec (behaviors, policies,
  data model, interfaces, configuration, security invariants)
- [docs/usage.md](docs/usage.md) — setup walkthrough, installing packages with dep-scan,
  wrapping package managers, configuration reference
- [docs/architecture/overview.md](docs/architecture/overview.md) — system design
- Architecture decisions: [docs/architecture/decisions/](docs/architecture/decisions/)

## Security

Report security issues via [SECURITY.md](SECURITY.md).

## Sponsorship

dep-scan is independent, open-source security tooling. If it saves you time or risk, [sponsoring its development](https://github.com/sponsors/tkdtaylor) is the most direct way to keep it maintained.

## Enterprise support

Commercial support, integration help, and SLAs are available. Apache-2.0 means you can build on dep-scan freely; paid support is a partner if you want one, never a requirement. Contact [tools@taylorguard.me](mailto:tools@taylorguard.me).

## License

[Apache License 2.0](LICENSE) — free to use, modify, and distribute. See [NOTICE](NOTICE)
for attribution and disclaimers, and [CONTRIBUTING.md](CONTRIBUTING.md) for DCO
contribution terms (no CLA required).

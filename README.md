# dep-scan

A cross-platform CLI tool that intercepts and scans every dependency before installation. Detects supply chain attacks — typosquatting, malicious install scripts, suspicious maintainer changes, known vulnerabilities — and enforces configurable policies like minimum package age.

Local-first, fast, open source. Single Rust binary with no runtime dependencies.

## Quick start

```bash
# Build from source
cargo build --release

# Check a package on npm
dep-scan check lodash --registry npm

# Check multiple packages on PyPI
dep-scan check requests flask numpy --registry pypi

# JSON output for CI/CD pipelines
dep-scan check express --registry npm --json
```

## What it detects

dep-scan runs **6 security policies** against every package:

| Policy | What it catches | Default |
|--------|----------------|---------|
| **Age** | Packages published less than 48 hours ago | Block |
| **Install scripts** | Malicious `postinstall`/`preinstall` scripts (eval, child_process, subprocess) | Block |
| **Typosquatting** | Names suspiciously similar to popular packages (e.g. `expresss` vs `express`) | Warn/Block |
| **Vulnerability** | Known CVEs via [OSV.dev](https://osv.dev) (free, no API key) | Block |
| **Maintainer change** | Added/removed maintainers since last scan; full takeover detection | Warn/Block |
| **Dependency confusion** | Internal-looking package names on public registries | Warn |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | One or more policy violations (warn or block) |
| 2 | Runtime error (network failure, invalid config) |

## Configuration

Initialize a config file:

```bash
dep-scan config init    # creates .dep-scan.toml in current directory
dep-scan config show    # prints effective configuration
```

Example `.dep-scan.toml`:

```toml
min_package_age_hours = 48

[registries]
npm_url = "https://registry.npmjs.org"
pypi_url = "https://pypi.org"

[policies]
check_min_age = true
check_install_scripts = true
check_maintainer_changes = true
check_typosquatting = true
check_vulnerabilities = true

[osv]
osv_url = "https://api.osv.dev"

[dependency_confusion]
internal_prefixes = ["internal-", "private-", "corp-"]
```

All settings can be overridden via environment variables:

| Variable | Overrides |
|----------|-----------|
| `DEP_SCAN_MIN_AGE` | `min_package_age_hours` |
| `DEP_SCAN_NPM_URL` | `registries.npm_url` |
| `DEP_SCAN_PYPI_URL` | `registries.pypi_url` |
| `DEP_SCAN_OSV_URL` | `osv.osv_url` |
| `DEP_SCAN_CACHE_PATH` | `cache_path` |

## Supported registries

- **npm** (`--registry npm`) — full support including install script extraction
- **PyPI** (`--registry pypi`) — metadata and vulnerability scanning (install script analysis limited by PyPI API)

Cargo and Go module support planned for v0.3.

## Example output

```
$ dep-scan check expresss internal-utils --registry npm

Package              Version      Age        Result
expresss             0.0.0        84401h     WARN: Package 'expresss' is similar to popular package 'express' (distance: 0.12)
  age: pass
  install_scripts: pass
  maintainer_change: pass
  typosquatting: WARN — Package 'expresss' is similar to popular package 'express' (distance: 0.12)
  vulnerability: pass
  dependency_confusion: pass
internal-utils       0.1.0        891h       WARN: Package 'internal-utils' matches internal namespace pattern 'internal-' — possible dependency confusion
  age: pass
  install_scripts: pass
  maintainer_change: pass
  typosquatting: pass
  vulnerability: pass
  dependency_confusion: WARN — Package 'internal-utils' matches internal namespace pattern 'internal-' — possible dependency confusion
```

## Building from source

Requires Rust 1.75+ (uses native async traits).

```bash
git clone https://github.com/tkdtaylor/dep-scan.git
cd dep-scan
cargo build --release
# Binary at target/release/dep-scan
```

## Development

```bash
cargo test              # run all tests (161 tests)
cargo clippy            # lint
cargo fmt --check       # check formatting
```

## Architecture

See [docs/architecture/overview.md](docs/architecture/overview.md) for system design and [docs/architecture/decisions/](docs/architecture/decisions/) for ADRs:

- [ADR 001](docs/architecture/decisions/001-language-choice.md) — Rust as implementation language
- [ADR 002](docs/architecture/decisions/002-detection-strategy.md) — v0.2 detection strategy and external data sources

## License

MIT

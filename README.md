# dep-scan

A cross-platform CLI tool that intercepts and scans every dependency before installation. Detects supply chain attacks — typosquatting, malicious install scripts, suspicious maintainer changes, known vulnerabilities — and enforces configurable policies like minimum package age.

Local-first, fast, open source. Single Rust binary with no runtime dependencies.

[![CI](https://github.com/tkdtaylor/dep-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/tkdtaylor/dep-scan/actions/workflows/ci.yml)

## Install

```bash
# One-liner install (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash

# Or build from source
cargo install --git https://github.com/tkdtaylor/dep-scan.git
```

## Quick start

```bash
# Build from source (alternative)
cargo build --release

# Check a package on npm
dep-scan check lodash --registry npm

# Check multiple packages on PyPI
dep-scan check requests flask numpy --registry pypi

# Check crates
dep-scan check serde tokio --registry crates

# Check Go modules
dep-scan check github.com/gin-gonic/gin --registry go

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

| Registry | Flag | Status | Attack vectors scanned |
|----------|------|--------|----------------------|
| **npm** | `--registry npm` | Full support | install scripts (`postinstall`, `preinstall`), typosquatting, age, CVEs, maintainer changes |
| **PyPI** | `--registry pypi` | Full support | `setup.py` hooks, typosquatting, age, CVEs, maintainer changes |
| **crates.io** | `--registry crates` | Full support | typosquatting, age, CVEs, maintainer changes, popularity |
| **Go modules** | `--registry go` | Full support | typosquatting, age, CVEs |

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

## Setting up with a new project

The easiest way to use dep-scan is to add it at the start of a project, before any dependencies are installed.

### 1. Install dep-scan

```bash
# Build from source (Rust 1.75+ required)
git clone https://github.com/tkdtaylor/dep-scan.git
cd dep-scan
cargo build --release

# Copy the binary somewhere on your PATH
sudo cp target/release/dep-scan /usr/local/bin/
# or for user-local install:
cp target/release/dep-scan ~/.local/bin/
```

### 2. Initialize config in your project

```bash
cd your-project
dep-scan config init    # creates .dep-scan.toml with sensible defaults
```

This gives you a `.dep-scan.toml` you can check into your repo so the whole team shares the same security policies.

### 3. Scan before adding dependencies

```bash
# Before running your package manager, check what you're about to add
dep-scan check express body-parser cors --registry npm
dep-scan check requests flask sqlalchemy --registry pypi
dep-scan check serde tokio clap --registry crates
dep-scan check github.com/gorilla/mux --registry go
# Or just use the wrappers — they scan automatically
npmds install express body-parser cors
pipds install requests flask sqlalchemy

# In CI/CD — fail the build on any policy violation
dep-scan check $(cat requirements.txt | grep -v '^#') --registry pypi --json
```

### 4. Ongoing use

Run `dep-scan check` any time you add a new dependency. The local SQLite cache means repeat checks are instant — only new or changed packages hit the registry.

---

## Wrapping package managers

dep-scan provides drop-in wrapper commands that scan every package before installing. Same arguments, same behavior as the real commands, but every install goes through dep-scan first.

| Wrapper | Wraps | Status |
|---------|-------|--------|
| **`npmds`** | `npm` | Available now |
| **`pipds`** | `pip` | Available now |
| **`cargods`** | `cargo` | Available now |
| **`gods`** | `go` | Available now |

```bash
# These work exactly like the real commands, but scan before installing
npmds install express body-parser cors
pipds install requests flask sqlalchemy
cargods add serde tokio
gods get github.com/some/module
# All other subcommands pass through unchanged
npmds test
pipds list
cargods build
gods test ./...
```

### Installing the wrappers (Linux / macOS)

```bash
# Install to /usr/local/bin (system-wide)
sudo tee /usr/local/bin/npmds << 'WRAPPER' > /dev/null
#!/usr/bin/env bash
set -euo pipefail
if [[ "${DEP_SCAN_SKIP:-}" == "1" ]]; then exec npm "$@"; fi
if [[ "${1:-}" =~ ^(install|i|add)$ ]]; then
  cmd="$1"; shift
  pkgs=(); flags=()
  for arg in "$@"; do
    if [[ "$arg" == -* ]]; then flags+=("$arg"); else pkgs+=("$arg"); fi
  done
  if [ ${#pkgs[@]} -gt 0 ]; then
    echo "dep-scan: scanning ${pkgs[*]}..."
    dep-scan check "${pkgs[@]}" --registry npm || {
      echo "dep-scan: blocked — resolve policy violations before installing" >&2
      exit 1
    }
  fi
  exec npm "$cmd" "${flags[@]}" "${pkgs[@]}"
else
  exec npm "$@"
fi
WRAPPER
sudo chmod +x /usr/local/bin/npmds

sudo tee /usr/local/bin/pipds << 'WRAPPER' > /dev/null
#!/usr/bin/env bash
set -euo pipefail
if [[ "${DEP_SCAN_SKIP:-}" == "1" ]]; then exec pip "$@"; fi
if [[ "${1:-}" == "install" ]]; then
  shift
  pkgs=(); flags=()
  for arg in "$@"; do
    if [[ "$arg" == -* ]]; then flags+=("$arg"); else pkgs+=("$arg"); fi
  done
  if [ ${#pkgs[@]} -gt 0 ]; then
    echo "dep-scan: scanning ${pkgs[*]}..."
    dep-scan check "${pkgs[@]}" --registry pypi || {
      echo "dep-scan: blocked — resolve policy violations before installing" >&2
      exit 1
    }
  fi
  exec pip install "${flags[@]}" "${pkgs[@]}"
else
  exec pip "$@"
fi
WRAPPER
sudo chmod +x /usr/local/bin/pipds

# cargo wrapper
sudo tee /usr/local/bin/cargods << 'WRAPPER' > /dev/null
#!/usr/bin/env bash
set -euo pipefail
if [[ "${DEP_SCAN_SKIP:-}" == "1" ]]; then exec cargo "$@"; fi
if [[ "${1:-}" =~ ^(add|install)$ ]]; then
  cmd="$1"; shift
  pkgs=(); flags=()
  for arg in "$@"; do
    if [[ "$arg" == -* ]]; then flags+=("$arg"); else pkgs+=("$arg"); fi
  done
  if [ ${#pkgs[@]} -gt 0 ]; then
    echo "dep-scan: scanning ${pkgs[*]}..."
    dep-scan check "${pkgs[@]}" --registry crates || {
      echo "dep-scan: blocked — resolve policy violations before installing" >&2
      exit 1
    }
  fi
  exec cargo "$cmd" "${flags[@]}" "${pkgs[@]}"
else
  exec cargo "$@"
fi
WRAPPER
sudo chmod +x /usr/local/bin/cargods

# go wrapper
sudo tee /usr/local/bin/gods << 'WRAPPER' > /dev/null
#!/usr/bin/env bash
set -euo pipefail
if [[ "${DEP_SCAN_SKIP:-}" == "1" ]]; then exec go "$@"; fi
if [[ "${1:-}" =~ ^(get|install)$ ]]; then
  cmd="$1"; shift
  pkgs=(); flags=()
  for arg in "$@"; do
    if [[ "$arg" == -* ]]; then flags+=("$arg"); else pkgs+=("$arg"); fi
  done
  if [ ${#pkgs[@]} -gt 0 ]; then
    echo "dep-scan: scanning ${pkgs[*]}..."
    dep-scan check "${pkgs[@]}" --registry go || {
      echo "dep-scan: blocked — resolve policy violations before installing" >&2
      exit 1
    }
  fi
  exec go "$cmd" "${flags[@]}" "${pkgs[@]}"
else
  exec go "$@"
fi
WRAPPER
sudo chmod +x /usr/local/bin/gods
```

For user-local install (no sudo), put them in `~/.local/bin/` instead.

### Windows (PowerShell)

Add to your PowerShell profile (`$PROFILE`):

```powershell
function npmds {
  if ($env:DEP_SCAN_SKIP -eq '1') { & npm @args; return }
  if ($args[0] -in 'install', 'i', 'add') {
    $pkgs = $args[1..($args.Length-1)] | Where-Object { $_ -notlike '-*' }
    if ($pkgs) {
      Write-Host "dep-scan: scanning $($pkgs -join ', ')..."
      & dep-scan check @pkgs --registry npm
      if ($LASTEXITCODE -ne 0) { return }
    }
    & npm @args
  } else {
    & npm @args
  }
}

function pipds {
  if ($env:DEP_SCAN_SKIP -eq '1') { & pip @args; return }
  if ($args[0] -eq 'install') {
    $pkgs = $args[1..($args.Length-1)] | Where-Object { $_ -notlike '-*' }
    if ($pkgs) {
      Write-Host "dep-scan: scanning $($pkgs -join ', ')..."
      & dep-scan check @pkgs --registry pypi
      if ($LASTEXITCODE -ne 0) { return }
    }
    & pip @args
  } else {
    & pip @args
  }
}

# cargo and go wrappers
function cargods {
  if ($env:DEP_SCAN_SKIP -eq '1') { & cargo @args; return }
  if ($args[0] -in 'add', 'install') {
    $pkgs = $args[1..($args.Length-1)] | Where-Object { $_ -notlike '-*' }
    if ($pkgs) {
      Write-Host "dep-scan: scanning $($pkgs -join ', ')..."
      & dep-scan check @pkgs --registry crates
      if ($LASTEXITCODE -ne 0) { return }
    }
    & cargo @args
  } else {
    & cargo @args
  }
}

function gods {
  if ($env:DEP_SCAN_SKIP -eq '1') { & go @args; return }
  if ($args[0] -in 'get', 'install') {
    $pkgs = $args[1..($args.Length-1)] | Where-Object { $_ -notlike '-*' }
    if ($pkgs) {
      Write-Host "dep-scan: scanning $($pkgs -join ', ')..."
      & dep-scan check @pkgs --registry go
      if ($LASTEXITCODE -ne 0) { return }
    }
    & go @args
  } else {
    & go @args
  }
}
```

### Enforcing dep-scan (optional)

If you want to make `npmds`/`pipds` the **only** way to install packages on a system or for a team, you can redirect the bare commands:

**Per-user (shell aliases)** — add to `~/.bashrc` or `~/.zshrc`:

```bash
# Redirect all package managers to their dep-scan wrappers
alias npm='npmds'
alias pip='pipds'
alias cargo='cargods'
alias go='gods'         
# To bypass: use the full path or unset the alias
#   /usr/bin/npm install something
#   unalias npm && npm install something
```

**System-wide (PATH override)** — install shim scripts that replace `npm`/`pip` for all users:

```bash
# Create a directory that sits before the real binaries in PATH
sudo mkdir -p /usr/local/lib/dep-scan/bin

# Create shims for each package manager
for pair in "npm:npmds" "pip:pipds" "cargo:cargods" "go:gods"; do
  cmd="${pair%%:*}"; wrapper="${pair##*:}"
  sudo tee "/usr/local/lib/dep-scan/bin/$cmd" << SHIM > /dev/null
#!/usr/bin/env bash
exec $wrapper "\$@"
SHIM
  sudo chmod +x "/usr/local/lib/dep-scan/bin/$cmd"
done

# Add to system PATH (before /usr/bin)
echo 'export PATH="/usr/local/lib/dep-scan/bin:$PATH"' | sudo tee /etc/profile.d/dep-scan.sh
```

Now `npm install` and `pip install` go through dep-scan automatically. To bypass when needed:

```bash
# Use the real binary directly
/usr/bin/npm install something
/usr/bin/pip install something

# Or skip scanning for one command
DEP_SCAN_SKIP=1 npm install something
```

**Per-project (direnv)** — if your team uses [direnv](https://direnv.net/), add to `.envrc`:

```bash
# .envrc — enforces dep-scan for this project only
alias npm='npmds'
alias pip='pipds'
alias cargo='cargods'
alias go='gods'
```

### CI/CD integration

```yaml
# GitHub Actions example
- name: Install dep-scan
  run: cargo install --path .  # or download pre-built binary

- name: Scan dependencies before install
  run: |
    dep-scan check $(jq -r '.dependencies | keys[]' package.json) --registry npm --json
    # Exit code 1 = policy violation, fails the workflow

- name: Install dependencies
  run: npm install
```

### Skipping the scan

When you need to bypass scanning (e.g., trusted CI environment or installing dep-scan's own build deps):

```bash
# The wrappers are separate commands — the real tools always work directly
npm install something
pip install something
cargo add something
go get something

# Or skip scanning within a wrapper
DEP_SCAN_SKIP=1 npmds install something
DEP_SCAN_SKIP=1 pipds install something
DEP_SCAN_SKIP=1 cargods add something
DEP_SCAN_SKIP=1 gods get something
```

---

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
cargo test              # run all tests (262 tests)
cargo clippy            # lint
cargo fmt --check       # check formatting
```

## Architecture

See [docs/architecture/overview.md](docs/architecture/overview.md) for system design and [docs/architecture/decisions/](docs/architecture/decisions/) for ADRs:

- [ADR 001](docs/architecture/decisions/001-language-choice.md) — Rust as implementation language
- [ADR 002](docs/architecture/decisions/002-detection-strategy.md) — v0.2 detection strategy and external data sources

## License

MIT

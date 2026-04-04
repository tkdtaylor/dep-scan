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
# Before running npm install / pip install, check what you're about to add
dep-scan check express body-parser cors --registry npm
dep-scan check requests flask sqlalchemy --registry pypi

# In CI/CD — fail the build on any policy violation
dep-scan check $(cat requirements.txt | grep -v '^#') --registry pypi --json
```

### 4. Ongoing use

Run `dep-scan check` any time you add a new dependency. The local SQLite cache means repeat checks are instant — only new or changed packages hit the registry.

---

## Wrapping package managers — `npmds` and `pipds`

dep-scan provides **`npmds`** and **`pipds`** — drop-in wrappers that scan every package before installing. Use them anywhere you'd use `npm` or `pip`. Same arguments, same behavior, but every install goes through dep-scan first.

```bash
# These work exactly like npm/pip, but scan before installing
npmds install express body-parser cors
pipds install requests flask sqlalchemy

# All other commands pass through unchanged
npmds test
npmds run build
pipds list
pipds freeze
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
```

### Enforcing dep-scan (optional)

If you want to make `npmds`/`pipds` the **only** way to install packages on a system or for a team, you can redirect the bare commands:

**Per-user (shell aliases)** — add to `~/.bashrc` or `~/.zshrc`:

```bash
# Redirect npm/pip to their dep-scan wrappers
alias npm='npmds'
alias pip='pipds'

# To bypass: use the full path or unset the alias
#   /usr/bin/npm install something
#   unalias npm && npm install something
```

**System-wide (PATH override)** — install shim scripts that replace `npm`/`pip` for all users:

```bash
# Create a directory that sits before the real binaries in PATH
sudo mkdir -p /usr/local/lib/dep-scan/bin

# npm shim — redirects to npmds
sudo tee /usr/local/lib/dep-scan/bin/npm << 'SHIM' > /dev/null
#!/usr/bin/env bash
exec npmds "$@"
SHIM
sudo chmod +x /usr/local/lib/dep-scan/bin/npm

# pip shim — redirects to pipds
sudo tee /usr/local/lib/dep-scan/bin/pip << 'SHIM' > /dev/null
#!/usr/bin/env bash
exec pipds "$@"
SHIM
sudo chmod +x /usr/local/lib/dep-scan/bin/pip

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
# npmds/pipds are separate commands — npm/pip always work directly
npm install something
pip install something

# Or skip scanning within the wrapper
DEP_SCAN_SKIP=1 npmds install something
DEP_SCAN_SKIP=1 pipds install something
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

# dep-scan

A cross-platform CLI tool that intercepts and scans every dependency before installation. Detects supply chain attacks — typosquatting, malicious install scripts, suspicious maintainer changes, known vulnerabilities — verifies cryptographic provenance (sigstore-issued Fulcio + Rekor proofs for npm and PyPI; Ed25519-signed checksum database for Go), and enforces configurable policies like minimum package age. Cache entries are content-addressed and fail-closed on hash mismatch — a republished tarball under the same version triggers a re-scan. For pip, the verified hash is passed through with `--require-hashes` to close the TOCTOU window between scan and install.

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

dep-scan runs **11 security policies** against every package:

| Policy | What it catches | Default |
|--------|----------------|---------|
| **Age** | Packages published less than 48 hours ago | Block |
| **Install scripts** | Malicious `postinstall`/`preinstall` scripts (eval, child_process, subprocess) | Block |
| **Obfuscation** | Heavily encoded or unreadable install scripts (base64 blobs, hex strings, eval-of-string) | Block |
| **Typosquatting** | Names suspiciously similar to popular packages (e.g. `expresss` vs `express`) | Warn/Block |
| **Vulnerability** | Known CVEs via [OSV.dev](https://osv.dev) (free, no API key) | Block |
| **Maintainer change** | Added/removed maintainers since last scan; full takeover detection | Warn/Block |
| **Popularity** | Packages with very low download counts (configurable threshold) | Warn |
| **Dependency confusion** | Internal-looking package names on public registries | Warn |
| **npm provenance** | Sigstore-verified SLSA attestation (Fulcio chain walk + Rekor inclusion + cert-validity window). Defends against a lying npm registry. | Warn (missing) / Block (invalid) |
| **PyPI provenance** | PEP 740 sigstore attestation, same verification as npm with sha256 subject digests. Defends against a lying PyPI registry. | Warn (missing) / Block (invalid) |
| **Go sumdb** | Ed25519 signature verification of `sum.golang.org` signed-tree-head responses. Defends against a lying Go module proxy. | Warn (missing) / Block (invalid) |

### Cache integrity (always on)

Every cached verdict is content-addressed. On a cache hit, dep-scan re-fetches the registry's published digest (`dist.integrity` / `digests.sha256` / `cksum` / `h1:`) and compares it to the stored hash. Mismatch ⇒ invalidate the cache row and re-scan from scratch. There is no flag to skip this check. The both-`None` case (registry stopped publishing a digest, and the cache row was a pre-029 row) is fail-closed — re-scan, never honor.

npm's legacy `dist.shasum` is SHA-1 and is **never trust-gated**. Any cache row whose digest starts with `sha1:` re-scans unconditionally, and new `pass`/`warn` rows for sha1-only packages store `NULL` for the digest — closes the SHAttered chosen-prefix-collision window.

The cache is keyed by `(name, resolved_version, registry)` — never by the literal string `"latest"` — so a republished `pkg@latest` cannot ride past verification on a prior version's cached verdict.

See [ADR 003](docs/architecture/decisions/003-content-hash-cache-integrity.md) for the threat model.

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

Example `.dep-scan.toml` (matches `dep-scan config init` output):

```toml
min_package_age_hours = 48

[registries]
npm_url = "https://registry.npmjs.org"
pypi_url = "https://pypi.org"
crates_url = "https://crates.io"
go_proxy_url = "https://proxy.golang.org"
go_sum_db_url = "https://sum.golang.org"

[policies]
check_typosquatting = true
check_install_scripts = true
check_min_age = true
check_maintainer_changes = true
check_vulnerabilities = true
check_obfuscation = true
check_npm_provenance = true
require_npm_provenance = false
check_pypi_provenance = true
require_pypi_provenance = false
check_go_sumdb = true
require_go_sumdb = false

[osv]
osv_url = "https://api.osv.dev"

[dependency_confusion]
internal_prefixes = ["internal-", "private-", "corp-"]

[popularity]
min_downloads = 1000
```

The `require_*` knobs escalate a missing-attestation `Warn` into a `Block`. Most packages don't publish provenance yet, so the defaults are `Warn` to avoid a false-positive flood. Invalid attestations always `Block` regardless of these flags.

All settings can be overridden via environment variables:

| Variable | Overrides |
|----------|-----------|
| `DEP_SCAN_MIN_AGE` | `min_package_age_hours` |
| `DEP_SCAN_NPM_URL` | `registries.npm_url` |
| `DEP_SCAN_PYPI_URL` | `registries.pypi_url` |
| `DEP_SCAN_CRATES_URL` | `registries.crates_url` |
| `DEP_SCAN_GO_PROXY_URL` | `registries.go_proxy_url` |
| `DEP_SCAN_GO_SUM_DB_URL` | `registries.go_sum_db_url` |
| `DEP_SCAN_OSV_URL` | `osv.osv_url` |
| `DEP_SCAN_CACHE_PATH` | `cache_path` |

## Supported registries

| Registry | Flag | Status | Policies that apply |
|----------|------|--------|---------------------|
| **npm** | `--registry npm` | Full support | age, install scripts, obfuscation, typosquatting, vulnerability (OSV), maintainer change, popularity, dependency confusion, **npm provenance** (sigstore Fulcio chain walk + Rekor inclusion proof + cert-validity window) |
| **PyPI** | `--registry pypi` | Full support | age, typosquatting, vulnerability (OSV), maintainer change, popularity, dependency confusion, **PyPI provenance** (PEP 740 sigstore attestation; same sigstore verification as npm with sha256 subject digests). Provenance URL is host/scheme/IP-validated before fetch. `pip install` receives the verified hash via `--require-hashes`. |
| **crates.io** | `--registry crates` | Full support | age, typosquatting, vulnerability (OSV), maintainer change, popularity, dependency confusion |
| **Go modules** | `--registry go` | Full support | age, typosquatting, vulnerability (OSV), dependency confusion, **Go sumdb** (Ed25519 signed-tree-head verification against `sum.golang.org`). Module paths are validated against the Go module-path grammar before any URL composition. |

## Example output

```
$ dep-scan check expresss internal-utils --registry npm

Package              Version      Age        Result
expresss             0.0.0        85259h     WARN: Package 'expresss' is similar to popular package 'express' (distance: 0.12)
  age: pass
  install_scripts: pass
  obfuscation: pass
  maintainer_change: pass
  typosquatting: WARN — Package 'expresss' is similar to popular package 'express' (distance: 0.12)
  vulnerability: pass
  popularity: pass
  dependency_confusion: pass
internal-utils       0.1.0        1749h      WARN: Package 'internal-utils' matches internal namespace pattern 'internal-' — possible dependency confusion
  age: pass
  install_scripts: pass
  obfuscation: pass
  maintainer_change: pass
  typosquatting: pass
  vulnerability: pass
  popularity: pass
  dependency_confusion: WARN — Package 'internal-utils' matches internal namespace pattern 'internal-' — possible dependency confusion
```

## Setting up with a new project

The easiest way to use dep-scan is to add it at the start of a project, before any dependencies are installed.

### 1. Install dep-scan

```bash
# Build from source (Rust 1.85+ required — uses 2024 edition)
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

# Or use dep-scan install — scan and exec the package manager in one step
dep-scan install express body-parser cors --registry npm
dep-scan install requests flask sqlalchemy --registry pypi

# Or set up the optional shell wrappers (see "Wrapping package managers"
# below for the install snippet) so your normal npm/pip/cargo/go calls
# scan automatically:
#   npmds install express body-parser cors
#   pipds install requests flask sqlalchemy
#   cargods add serde tokio
#   gods get github.com/gorilla/mux

# Scan everything in a lockfile in one go
dep-scan check --lockfile package-lock.json --lockfile-type npm
dep-scan check --lockfile requirements.txt --lockfile-type pypi
dep-scan check --lockfile Cargo.lock --lockfile-type crates
dep-scan check --lockfile go.sum --lockfile-type go

# In CI/CD — fail the build on any policy violation
dep-scan check --lockfile package-lock.json --lockfile-type npm --json
```

### 4. Ongoing use

Run `dep-scan check` any time you add a new dependency. The local SQLite cache means repeat checks are instant — only new or changed packages hit the registry.

---

## Installing packages with dep-scan

For one-off installs, the built-in `dep-scan install` subcommand scans first and then invokes the underlying package manager only if every policy passes:

```bash
# Scan, then install if clean
dep-scan install express body-parser cors --registry npm
dep-scan install requests flask sqlalchemy --registry pypi
dep-scan install serde tokio clap --registry crates
dep-scan install github.com/gorilla/mux --registry go

# Override a block (e.g. for an internal package you've vetted)
dep-scan install internal-utils --registry npm --force
```

`--registry` accepts `npm`, `pypi`, `crates`, or `go`. `--force` proceeds with the install even when policies block — use it sparingly. Without `--force`, a policy violation aborts before the package manager runs.

For ongoing use across an existing workflow, the wrappers below are better — they intercept your normal `npm install` / `pip install` / `cargo add` / `go get` calls without changing your habits.

---

## Wrapping package managers

dep-scan provides drop-in wrapper commands that scan every package before installing. Same arguments, same behavior as the real commands, but every install goes through dep-scan first.

| Wrapper | Wraps | Distributed as |
|---------|-------|----------------|
| **`npmds`** | `npm` | Shell snippet below |
| **`pipds`** | `pip` | Shell snippet below |
| **`cargods`** | `cargo` | Shell snippet below |
| **`gods`** | `go` | Shell snippet below |

> The wrappers are **shell shims that call `dep-scan check`** — they are not separate binaries built by `cargo build`. Install them from the snippet in [*Installing the wrappers*](#installing-the-wrappers-linux--macos) below before using them.

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
- uses: actions/checkout@v4

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

Requires Rust 1.85+ (the crate uses the 2024 edition).

```bash
git clone https://github.com/tkdtaylor/dep-scan.git
cd dep-scan
cargo build --release
# Binary at target/release/dep-scan
```

## Development

```bash
cargo test              # run all tests
cargo clippy            # lint
cargo fmt --check       # check formatting
```

## Architecture

See [docs/architecture/overview.md](docs/architecture/overview.md) for system design and [docs/architecture/decisions/](docs/architecture/decisions/) for ADRs:

- [ADR 001](docs/architecture/decisions/001-language-choice.md) — Rust as implementation language
- [ADR 002](docs/architecture/decisions/002-detection-strategy.md) — v0.2 detection strategy and external data sources
- [ADR 003](docs/architecture/decisions/003-content-hash-cache-integrity.md) — content-hash cache integrity, sigstore + sumdb provenance verification

## License

MIT

# dep-scan Usage Guide

This guide covers setup, configuration, installing packages with dep-scan, and wrapping
your package managers. For the spec (policies, data model, configuration keys,
security invariants), see [docs/spec/](spec/).

## Install

### One-liner (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash
```

### Build from source

Requires Rust 1.88+:

```bash
git clone https://github.com/tkdtaylor/dep-scan
cd dep-scan
cargo build --release
# Binary at target/release/dep-scan
```

Copy the binary to your PATH:

```bash
sudo cp target/release/dep-scan /usr/local/bin/
# Or for user-local install:
cp target/release/dep-scan ~/.local/bin/
```

### Verify the download (optional)

If you have [cosign](https://github.com/sigstore/cosign) installed, verify the
release artifacts with sigstore keyless OIDC signing:

```bash
VERSION=v1.3.1
ARTIFACT=dep-scan-${VERSION}-x86_64-unknown-linux-gnu.tar.gz

cosign verify-blob \
  --certificate "${ARTIFACT}.crt" \
  --signature "${ARTIFACT}.sig" \
  --certificate-identity-regexp 'https://github.com/tkdtaylor/dep-scan/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${ARTIFACT}"
```

The `.sig` and `.crt` files are published alongside each release. Verification is
optional — the existing `sha256sums.txt` check is unaffected.

## Configuration

Initialize a config file in your project:

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
maintainer_first_seen_warning = false

[osv]
osv_url = "https://api.osv.dev"

[dependency_confusion]
internal_prefixes = ["internal-", "private-", "corp-"]

[popularity]
min_downloads = 1000

[signing]
offline    = false
key_path   = ""
fulcio_url = ""
rekor_url  = ""
oidc_token = ""

[vcs]
allowed_hosts      = []
denied_hosts       = []
fetch_timeout_secs = 30
max_blob_bytes     = 52428800

[transitive]
enabled           = false
max_depth         = 5
on_depth_limit    = "warn"
fetch_concurrency = 4
max_total_nodes   = 5000
```

### Environment variable overrides

Every setting can be overridden via environment variables:

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

## Setting up with a new project

1. Install dep-scan (see above)
2. Initialize config in your project: `dep-scan config init`
3. Scan before adding dependencies:

```bash
# Before running your package manager, check what you're about to add
dep-scan check express body-parser cors --registry npm
dep-scan check requests flask sqlalchemy --registry pypi
dep-scan check serde tokio clap --registry crates
dep-scan check github.com/gorilla/mux --registry go

# Or use dep-scan install to scan and execute the package manager in one step
dep-scan install express body-parser cors --registry npm
dep-scan install requests flask sqlalchemy --registry pypi

# Or scan a lockfile
dep-scan check --lockfile package-lock.json --lockfile-type npm
dep-scan check --lockfile requirements.txt --lockfile-type pypi
dep-scan check --lockfile Cargo.lock --lockfile-type crates
dep-scan check --lockfile go.sum --lockfile-type go

# In CI/CD, fail the build on policy violations
dep-scan check --lockfile package-lock.json --lockfile-type npm --format json
```

4. Ongoing use: Run `dep-scan check` any time you add a new dependency. The local
   SQLite cache means repeat checks are instant.

## Installing packages with dep-scan

The `dep-scan install` subcommand scans first, then invokes the underlying package
manager only if every policy passes:

```bash
# Scan, then install if clean
dep-scan install express body-parser cors --registry npm
dep-scan install requests flask sqlalchemy --registry pypi
dep-scan install serde tokio clap --registry crates
dep-scan install github.com/gorilla/mux --registry go

# Override a block (for an internal package you've vetted)
dep-scan install internal-utils --registry npm --force

# Print an audit line before exec (v1.2.0+)
dep-scan install express --registry npm --verbose
# → [audit] express@5.0.1 hash=sha512:… verdict=pass …
```

Without `--force`, a policy violation aborts before the package manager runs.

## Wrapping package managers

For ongoing use, use the drop-in wrapper commands `npmds`, `pipds`, `cargods`, and
`gods` — they intercept your normal install/add calls and scan automatically.

### Quick install (Linux/macOS)

The wrapper scripts live in [`shims/`](../shims/). Copy them to a directory on your PATH:

```bash
cp shims/* ~/.local/bin/
```

Now you can use them:

```bash
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

### Installing the wrappers (Linux/macOS)

If you prefer to install them manually:

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

To make `npmds`/`pipds` the only way to install packages:

**Per-user (shell aliases)** — add to `~/.bashrc` or `~/.zshrc`:

```bash
alias npm='npmds'
alias pip='pipds'
alias cargo='cargods'
alias go='gods'
```

**System-wide (PATH override)**:

```bash
sudo mkdir -p /usr/local/lib/dep-scan/bin
for pair in "npm:npmds" "pip:pipds" "cargo:cargods" "go:gods"; do
  cmd="${pair%%:*}"; wrapper="${pair##*:}"
  sudo tee "/usr/local/lib/dep-scan/bin/$cmd" << SHIM > /dev/null
#!/usr/bin/env bash
exec $wrapper "\$@"
SHIM
  sudo chmod +x "/usr/local/lib/dep-scan/bin/$cmd"
done
echo 'export PATH="/usr/local/lib/dep-scan/bin:$PATH"' | sudo tee /etc/profile.d/dep-scan.sh
```

**Per-project (direnv)** — add to `.envrc`:

```bash
alias npm='npmds'
alias pip='pipds'
alias cargo='cargods'
alias go='gods'
```

To bypass when needed:

```bash
# Use the real binary directly
/usr/bin/npm install something
DEP_SCAN_SKIP=1 npm install something
```

## CI/CD integration

GitHub Actions example:

```yaml
- uses: actions/checkout@v4

- uses: dtolnay/rust-toolchain@stable
  with:
    toolchain: "1.88"

- name: Install dep-scan
  run: cargo install --locked --path .

- name: Scan dependencies before install
  run: dep-scan check $(jq -r '.dependencies | keys[]' package.json) --registry npm --format json
```

## Output formats and policies

For detailed information on:
- The 12 security policies (age, install scripts, obfuscation, typosquatting,
  vulnerabilities, maintainer changes, popularity, dependency confusion, npm/PyPI/Go
  provenance)
- Output formats (native, JSON, OSV, CycloneDX, SPDX, VEX)
- Exit codes
- Cache integrity and hash verification
- Dogfood allowlist

See [docs/spec/](spec/) — specifically [behaviors.md](spec/behaviors.md) for policies
and [interfaces.md](spec/interfaces.md) for CLI/output details.

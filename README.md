# dep-scan

A cross-platform CLI tool that intercepts and scans every dependency before installation. Detects supply chain attacks — typosquatting, malicious install scripts, suspicious maintainer changes, known vulnerabilities — verifies cryptographic provenance (sigstore-issued Fulcio + Rekor proofs for npm and PyPI; Ed25519-signed checksum database for Go), and enforces configurable policies like minimum package age. Cache entries are content-addressed and fail-closed on hash mismatch — a republished tarball under the same version triggers a re-scan. For pip, the verified hash is passed through with `--require-hashes` to close the TOCTOU window between scan and install.

Local-first, fast, open source. Single Rust binary with no runtime dependencies.

[![CI](https://github.com/tkdtaylor/dep-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/tkdtaylor/dep-scan/actions/workflows/ci.yml)

## Install

```bash
# One-liner install (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash

# Or build from source (requires Rust 1.88+)
cargo install --locked --git https://github.com/tkdtaylor/dep-scan.git
```

### Optional: verify the download with cosign

Every release artifact is signed with [sigstore](https://sigstore.dev) keyless OIDC signing.
If you have [cosign](https://github.com/sigstore/cosign) installed you can verify before running:

```bash
VERSION=v1.3.0
ARTIFACT=dep-scan-${VERSION}-x86_64-unknown-linux-gnu.tar.gz

cosign verify-blob \
  --certificate "${ARTIFACT}.crt" \
  --signature "${ARTIFACT}.sig" \
  --certificate-identity-regexp 'https://github.com/tkdtaylor/dep-scan/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${ARTIFACT}"
```

The `.sig` and `.crt` companion files are published alongside each binary in the
[GitHub Release](https://github.com/tkdtaylor/dep-scan/releases). Verification is optional —
the existing `sha256sums.txt` check is unaffected.

### SBOM

Each release also ships a [CycloneDX](https://cyclonedx.org/) SBOM
(`dep-scan.cdx.json`) listing every direct and transitive Rust dependency.
Download it from the release assets to audit dep-scan's own supply chain with
Trivy, Grype, or Dependency-Track.

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
dep-scan check express --registry npm --format json

# Scan the full transitive dependency tree, not just direct deps
dep-scan check express --registry npm --transitive

# Emit a signed CycloneDX SBOM / OpenVEX document of what was scanned
dep-scan check express --registry npm --format cyclonedx --allow-unsigned
```

## What it detects

dep-scan eats its own dog food: every CI run scans dep-scan's own `Cargo.lock` with the same heuristics it applies to user projects, so any new transitive dependency that fails dep-scan's policies is caught before merge.

dep-scan runs **12 security policies** against every package:

| Policy | What it catches | Default |
|--------|----------------|---------|
| **Age** | Packages published less than 48 hours ago | Block |
| **Install scripts** | Malicious `postinstall`/`preinstall` scripts (eval, child_process, subprocess). v1.2.0 tightened the heuristics — line/block comments are stripped before pattern matching and pure-hex sequences (SHA-256 digests, git SHAs) no longer false-positive as base64 blobs. | Block |
| **Obfuscation** | Heavily encoded or unreadable install scripts (base64 blobs, hex strings, eval-of-string) | Block |
| **Typosquatting** | Names suspiciously similar to popular packages (e.g. `expresss` vs `express`) | Warn/Block |
| **Vulnerability** | Known CVEs via [OSV.dev](https://osv.dev) (free, no API key) | Block |
| **Maintainer change** | Added/removed maintainers since last scan; full takeover detection. Opt-in `policies.maintainer_first_seen_warning = true` extends this to warn on first-observation of a package with zero downloads (defends against typosquat-from-day-one). Default: false (legacy behavior). | Warn/Block |
| **Popularity** | Packages with very low download counts (configurable threshold) | Warn |
| **Dependency confusion** | Internal-looking package names on public registries | Warn |
| **npm provenance** | Sigstore-verified SLSA attestation (Fulcio chain walk + Rekor inclusion + cert-validity window). Defends against a lying npm registry. | Warn (missing) / Block (invalid) |
| **PyPI provenance** | PEP 740 sigstore attestation, same verification as npm with sha256 subject digests. Defends against a lying PyPI registry. | Warn (missing) / Block (invalid) |
| **Go sumdb** | Ed25519 signature verification of `sum.golang.org` signed-tree-head responses. Defends against a lying Go module proxy. | Warn (missing) / Block (invalid) |
| **Mutable ref** | Git-sourced dependencies pinned to a mutable ref (branch/tag) instead of an immutable commit SHA — the upstream can be silently rewritten after you vet it. Applies only to VCS deps. | Warn (configurable to Block via `[vcs] mutable_git_ref = "block"`) |

> The `vcs_host` host-allowlist check (configured under `[vcs] allowed_hosts` / `denied_hosts`) gates which hosts a git dependency may be fetched from. It's a fail-closed network-egress gate rather than a per-package `Policy`, so it isn't counted among the twelve policies above.

### Dogfood policy

dep-scan's CI scans its own `Cargo.lock` on every push. When dep-scan reports a
block verdict on one of its own transitive dependencies, the maintainer has
three options:

1. **Fix the root cause in code** — correct response for false positives (e.g. the
   `version_check` typosquat false-positive, fixed by adjusting heuristics).
2. **Wait for the signal to resolve naturally** — age blocks expire once the
   package has been published for 48 hours.
3. **Acknowledge the block** — for investigated-and-benign findings (e.g. an
   audited maintainer rotation), record the justification in
   `.dep-scan-dogfood-allowlist.toml`.

The file `.dep-scan-dogfood-allowlist.toml` at the repo root is CI metadata,
not a dep-scan feature. dep-scan itself still reports every block; the
`scripts/dogfood-gate.py` gate reads the allowlist and downgrades matched
blocks from `::error::` (build failure) to `::warning::` (logged but not
failing). Unmatched blocks still fail the build.

**Allowlist entry fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `package` | yes | Crate name; must match the `package` field in dep-scan JSON |
| `policy` | yes | Policy name: `age`, `maintainer_change`, `typosquatting`, etc. |
| `justification` | yes | Free text; reference a task, issue, or investigation writeup |
| `opened_at` | yes | ISO date (`YYYY-MM-DD`) the entry was added |
| `version` | no | Exact-match version string; omit to match any version |
| `expires` | no | ISO date after which the entry is inert; use for transient blocks |

**When to use `expires`:** Always set it for age-policy blocks — those resolve
naturally once the package is >48h old. Set it ~48-72h after the block was
first observed. For investigated maintainer changes, `expires` is optional but
recommended to ensure entries get periodically reviewed.

**Rule: never allowlist a verdict you haven't actually investigated.** An
unexplained allowlist entry is indistinguishable from negligence.

### Cache integrity (always on)

Every cached verdict is content-addressed. On a cache hit, dep-scan re-fetches the registry's published digest (`dist.integrity` / `digests.sha256` / `cksum` / `h1:`) and compares it to the stored hash. Mismatch ⇒ invalidate the cache row and re-scan from scratch. There is no flag to skip this check. The both-`None` case (registry stopped publishing a digest, and the cache row was a pre-029 row) is fail-closed — re-scan, never honor.

npm's legacy `dist.shasum` is SHA-1 and is **never trust-gated**. Any cache row whose digest starts with `sha1:` re-scans unconditionally, and new `pass`/`warn` rows for sha1-only packages store `NULL` for the digest — closes the SHAttered chosen-prefix-collision window.

The cache is keyed by `(name, resolved_version, registry)` — never by the literal string `"latest"` — so a republished `pkg@latest` cannot ride past verification on a prior version's cached verdict.

The cache DB file is created with mode `0600` and uses WAL journaling (v1.2.0) — not world-readable on shared hosts, and concurrent dep-scan runs do not block or corrupt each other. On Unix the DB file is created atomically with `O_CREAT|O_EXCL` and mode `0600` in a single syscall — there is no window where the file briefly exists as `0644` between `Connection::open` and the follow-up `chmod`.

See [ADR 003](docs/architecture/decisions/003-content-hash-cache-integrity.md) for the threat model.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | One or more policy violations (warn or block) |
| 2 | Runtime error (network failure, invalid config) |

## Output formats

`dep-scan check` and `dep-scan install` accept `--format <value>`:

| Format | Output |
|--------|--------|
| `native` | Human-readable table (default) |
| `json` | dep-scan's JSON array of per-package verdicts |
| `osv` | OSV-schema JSON, consumable by OSV-Scanner / Trivy / Grype |
| `cyclonedx` | CycloneDX 1.4+ JSON SBOM of the scanned dependency set, verdicts attached |
| `spdx` | SPDX 2.3+ JSON SBOM of the scanned dependency set, verdicts attached |
| `vex` | OpenVEX document (presence-only: `affected` / `fixed` / `under_investigation`) |

> The bare `--json` flag is a **deprecated alias** for `--format json` — it still works but `--format json` is preferred. `--format` and `--json` are mutually exclusive.

### Signed interchange output

The machine-readable interchange formats (`osv`, `cyclonedx`, `spdx`, `vex`) are
**DSSE-signed by default**, once per run over the whole result set. dep-scan signs
either with a sigstore keyless identity (when `[signing] fulcio_url`/`rekor_url`/`oidc_token`
are configured and the network is reachable) or with an offline operator key
(`[signing] key_path`, a PEM PKCS#8 Ed25519 key). With no signing key configured on
the offline path, a signed-format request **fails closed** — nothing is written to
stdout. Pass `--allow-unsigned` to emit the raw payload with an explicit
`"_dep_scan_unsigned": true` marker instead. The `native` and `json` paths are never
signed.

Consumers verify against the operator's public key, which you export with:

```bash
dep-scan signing export-pubkey > pubkey.pem   # reads [signing] key_path; PEM SPKI + key-id
```

## Configuration

Initialize a config file:

```bash
dep-scan config init    # creates .dep-scan.toml in current directory
dep-scan config show    # prints effective configuration
```

Example `.dep-scan.toml`. The annotated comments below are explanatory
only — `dep-scan config init` writes the same keys with the same default
values, but without the comments (and with the multi-line array layout
`toml::to_string_pretty` produces).

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
# Opt-in (v1.2.0): warn on first-observation of a zero-download package.
maintainer_first_seen_warning = false

[osv]
osv_url = "https://api.osv.dev"

[dependency_confusion]
internal_prefixes = ["internal-", "private-", "corp-"]

[popularity]
min_downloads = 1000

[signing]                  # interchange-output signing identity (see "Interchange output" below)
offline    = false         # force the offline signing path, skip the network keyless path
key_path   = ""            # operator-provisioned PEM PKCS#8 Ed25519 private key; empty = none
fulcio_url = ""            # keyless Fulcio base URL (empty = keyless not provisioned)
rekor_url  = ""            # keyless Rekor base URL (empty = keyless not provisioned)
oidc_token = ""            # OIDC identity token presented to Fulcio (secret; redacted in `config show`)

[vcs]                      # git/VCS dependency handling
allowed_hosts      = []    # if non-empty, ONLY these hosts may be fetched
denied_hosts       = []    # always rejected; deny wins over allow
fetch_timeout_secs = 30    # hard wall-clock budget for a single VCS fetch
max_blob_bytes     = 52428800   # 50 MiB; larger blobs are skipped, not read into memory

[transitive]               # transitive dependency walker (opt-in)
enabled           = false  # false = flat scan only (non-regressive default); --transitive overrides
max_depth         = 5      # deepest level walked; 0 = root only
on_depth_limit    = "warn" # verdict floor for cut nodes: "warn" (default) | "block"
fetch_concurrency = 4      # parallel fetches during the walk; must be >= 1
max_total_nodes   = 5000   # maximum distinct nodes scanned; must be >= 1
```

The `require_*` knobs escalate a missing-attestation `Warn` into a `Block`. Most packages don't publish provenance yet, so the defaults are `Warn` to avoid a false-positive flood. Invalid attestations always `Block` regardless of these flags.

> **Note:** The `popularity` and `dependency_confusion` policies are always enabled and are configured via their own `[popularity]` and `[dependency_confusion]` sections, not by `check_*` booleans in `[policies]`.

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
| **Go modules** | `--registry go` | Full support | age, typosquatting, vulnerability (OSV), dependency confusion, **Go sumdb** (Ed25519 signed-tree-head verification against `sum.golang.org`). Module paths **and version strings** are validated against the Go module-path and semver/pseudo-version grammar before any URL composition. |

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
  npm_provenance: pass
internal-utils       0.1.0        1749h      WARN: Package 'internal-utils' matches internal namespace pattern 'internal-' — possible dependency confusion
  age: pass
  install_scripts: pass
  obfuscation: pass
  maintainer_change: pass
  typosquatting: pass
  vulnerability: pass
  popularity: pass
  dependency_confusion: WARN — Package 'internal-utils' matches internal namespace pattern 'internal-' — possible dependency confusion
  npm_provenance: pass
```

## Examples

Ready-to-use configs, a GitHub Actions snippet, and sample JSON output live in
[`examples/`](examples/). Each file has an inline comment explaining what it's for.

## Setting up with a new project

The easiest way to use dep-scan is to add it at the start of a project, before any dependencies are installed.

### 1. Install dep-scan

```bash
# Build from source (Rust 1.88+ required — uses 2024 edition)
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
dep-scan config init    # creates .dep-scan.toml with sensible defaults (aborts if file already exists)
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
dep-scan check --lockfile package-lock.json --lockfile-type npm --format json
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

# Print an audit line naming the locked version + hash before exec
dep-scan install express --registry npm --verbose
# → [audit] express@5.0.1 hash=sha512:… verdict=pass sigstore_reverified=false (L-9)  # npm example
```

The `--verbose` audit line (v1.2.0) records exactly what version + content
hash the wrapped package manager is about to fetch, and explicitly notes
that sigstore provenance is verified only at scan time — not re-run between
scan-pass and `npm/cargo/go install` (the documented TOCTOU gap in
[ADR 003](docs/architecture/decisions/003-content-hash-cache-integrity.md)).
For pip the audit line also confirms the sha256 was re-checked between
scan-pass and `pip install --require-hashes`.

`--registry` accepts `npm`, `pypi`, `crates`, or `go`. `--force` proceeds with the install even when policies block — use it sparingly. Without `--force`, a policy violation aborts before the package manager runs.

For ongoing use across an existing workflow, the wrappers below are better — they intercept your normal `npm install` / `pip install` / `cargo add` / `go get` calls without changing your habits.

---

## Wrapping package managers

dep-scan provides drop-in wrapper commands that scan every package before installing. Same arguments, same behavior as the real commands, but every install goes through dep-scan first.

### Quick install (Linux / macOS)

The wrapper scripts live in [`shims/`](shims/). Copy them to a directory on your `PATH`:

```sh
cp shims/* ~/.local/bin/
```

That's it — `npmds`, `pipds`, `cargods`, and `gods` are now available. See [`shims/README.md`](shims/README.md) for customisation notes.

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

- uses: dtolnay/rust-toolchain@stable
  with:
    toolchain: "1.88"  # dep-scan's MSRV

- name: Install dep-scan
  run: cargo install --locked --path .  # or download pre-built binary

- name: Scan dependencies before install
  run: |
    dep-scan check $(jq -r '.dependencies | keys[]' package.json) --registry npm --format json
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

Requires Rust 1.88+ (the crate uses the 2024 edition; MSRV bumped from 1.85 in v1.2.0 to accommodate a patched `time` dep).

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
- [ADR 004](docs/architecture/decisions/004-popularity-none-downloads.md) — popularity policy: treat `None` downloads as Pass, not zero
- [ADR 005](docs/architecture/decisions/005-interchange-standards-osv-sbom-vex.md) — adopt OSV, CycloneDX/SPDX, and VEX as interchange output standards
- [ADR 006](docs/architecture/decisions/006-runtime-statement-integrity.md) — runtime integrity of statements exchanged between ecosystem blocks
- [ADR 007](docs/architecture/decisions/007-offline-signing-key-custody.md) — offline signing key custody
- [ADR 008](docs/architecture/decisions/008-git-vcs-dependency-handling.md) — git/VCS dependency handling and transitive scanning
- [ADR 009](docs/architecture/decisions/009-transitive-resolution.md) — transitive dependency resolution (the DFS walker)
- [ADR 010](docs/architecture/decisions/010-synchronous-signer-over-async-network.md) — driving the async sigstore network from the synchronous signer trait
- [ADR 011](docs/architecture/decisions/011-manifest-edge-resolution-granularity.md) — manifest edge resolution granularity for git dependencies

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy and
how to report security issues in dep-scan itself.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the build/test workflow, commit
conventions, and how to propose new features.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT

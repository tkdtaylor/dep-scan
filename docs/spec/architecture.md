# Architecture — C4 Element Catalog

**Project:** dep-scan
**Last updated:** 2026-05-22 (v1.2.0)

The structured catalog of architectural elements that the diagrams in [`../architecture/diagrams.md`](../architecture/diagrams.md) render. Tables here are the **machine-readable spec** for the system's structure — they survive a Mermaid rewrite and are what a drift audit checks the code against.

## How this file relates to the diagrams

| File | Form | Use when |
|------|------|----------|
| [`../architecture/diagrams.md`](../architecture/diagrams.md) | Visual (Mermaid C4 + sequence) | You want to *see* the structure |
| `architecture.md` (this file) | Tabular (rows + columns) | You want to *check, query, or regenerate* the structure |

When the structure changes, both files update in the same commit. The tables here are the source of truth for *what exists*; the diagrams are the source of truth for *how it's drawn*.

---

## 1. Persons (actors)

| Name | Description | Goals |
|------|-------------|-------|
| **CLI user** | A developer or CI job invoking `dep-scan` directly or through wrapper shims | Block malicious dependencies before they're installed; produce a machine-readable signal for CI gates |
| **Maintainer of a wrapped project** | Owner of a Node / Python / Rust / Go project who installs dep-scan as a gate around their package manager | Same as above; reduce supply-chain risk for their consumers |

> No automated-system actors. dep-scan does not expose an inbound API.

---

## 2. Systems

| Name | Type | Description | Owner |
|------|------|-------------|-------|
| **dep-scan** | In-scope | Single-binary CLI: scans dependencies before install, verifies provenance, gates the wrapped package manager | This team |
| **npm registry** | External | Package metadata + provenance attestations (`registry.npmjs.org`) | npm Inc. |
| **PyPI** | External | Python package metadata + PEP 740 provenance (`pypi.org`) | PSF |
| **crates.io** | External | Rust crate metadata + cksum (`crates.io`) | Rust Foundation |
| **Go module proxy** | External | Module metadata + version info (`proxy.golang.org`) | Google |
| **sum.golang.org** | External | Signed-tree-head verification for Go modules | Google |
| **OSV.dev** | External | Aggregated vulnerability database (`api.osv.dev`) | Google + community |
| **Sigstore Fulcio** | External (build-time only) | Root + intermediate CAs for code-signing identity certs. **Never called at runtime** — roots embedded via `include_bytes!` | OpenSSF |
| **Sigstore Rekor** | External (build-time only) | Transparency log. Runtime: inclusion proofs arrive in-band; the verifier key is embedded at build time | OpenSSF |
| **Wrapped package manager** | External (subprocess) | `npm`, `pip`, `cargo`, or `go` — exec'd after a passing scan | Respective ecosystems |

---

## 3. Containers

dep-scan is a **single statically-linked Rust binary**. No service decomposition.

| Name | Technology | Description |
|------|-----------|-------------|
| `dep-scan` | Rust 1.88, edition 2024, single binary | The whole product. Runs as a one-shot CLI; exits when work is done. |
| `~/.dep-scan/cache.db` | SQLite (rusqlite 0.39, WAL mode, mode 0600) | Local content-addressed cache for scan verdicts + maintainer history. Owned by `dep-scan`; not shared with any other process. |

> SQLite is a library, not a service container, but it's listed because it's the only persistent state in the system.

---

## 4. Components (inside `dep-scan`)

| Component | Source | Responsibility |
|-----------|--------|----------------|
| **CLI layer** | [`src/cli.rs`](../../src/cli.rs), [`src/main.rs`](../../src/main.rs) | clap-based subcommand parsing; dispatches to handlers; emits table / JSON output; assembles the verbose audit log line |
| **Config layer** | [`src/config.rs`](../../src/config.rs) | Layered config (defaults < `.dep-scan.toml` < env < flags); see [configuration.md](configuration.md) |
| **Validation layer** | [`src/validation.rs`](../../src/validation.rs) | Rejects `-`-prefixed package-name tokens before any subprocess (F-001); Go module-path and version-string validation lives in [`src/registry/go.rs`](../../src/registry/go.rs) |
| **Registry layer** | [`src/registry/`](../../src/registry/) | Async HTTP clients for npm, PyPI, crates.io, Go proxy; companion clients for provenance + sumdb endpoints. Each implements the `Registry` trait. |
| **Lockfile parser** | [`src/lockfile.rs`](../../src/lockfile.rs) | Parses `package-lock.json`, `requirements.txt`, `Cargo.lock`, `go.sum` |
| **OSV client** | [`src/osv.rs`](../../src/osv.rs) | Vulnerability lookups against OSV.dev |
| **Typosquat detector** | [`src/typosquat.rs`](../../src/typosquat.rs) | Edit-distance + popular-package lists; 256-char length bound (F-020) |
| **Policy layer** | [`src/policy/`](../../src/policy/) | 11 policies implementing `Policy::evaluate(&ScanContext) -> PolicyResult` |
| **VCS fetch client** | [`src/vcs/fetch.rs`](../../src/vcs/fetch.rs) | Sandboxed, read-only git fetch (ADR 008, task 096). Pure-Rust gitoxide fetch-to-objects + materialise-ourselves; no `git` CLI, no checkout, no hooks/submodules/symlink-follow. First fetch of untrusted third-party source — highest-risk trust boundary. Host policy lives in [`src/policy/vcs_host.rs`](../../src/policy/vcs_host.rs) (task 095). |
| **Cache layer** | [`src/cache.rs`](../../src/cache.rs) | SQLite-backed cache with content-hash decision matrix (F-002, F-007, F-008) |
| **Sigstore verifier** | [`src/sigstore_verify.rs`](../../src/sigstore_verify.rs) | Fulcio chain walk + DSSE + Rekor inclusion proof + timestamp window; used by P-09, P-10 |
| **Signed-note parser/verifier** | [`src/signed_note.rs`](../../src/signed_note.rs) | RFC sumdb-style envelope; shared by P-11 (sumdb) and the Rekor checkpoint |
| **Types** | [`src/types.rs`](../../src/types.rs) | `PackageMetadata`, `ScanContext`, `VulnerabilityInfo`, `InstallScript` |

### Component dependencies (direction of arrows = "depends on")

```
main → cli → { validation, config }
main → { registry, lockfile, osv, cache, policy }
policy.* → { types, sigstore_verify (for P-09/P-10), signed_note (for P-11) }
sigstore_verify → signed_note
registry.* → types
cache → types
types → { registry::npm_attestation, policy::go_sumdb }   ← enrichment-payload types only (see note)
```

Direction rules:
- **`types` does not perform behavior** — it carries data. The only cross-module references in [`src/types.rs`](../../src/types.rs) are to *concrete enrichment-payload types* (`AttestationBundle`, `GoSumDbResult`) referenced via fully-qualified paths so the `ScanContext` can carry those payloads from the enrichment phase into the policy phase. `types` MUST NOT call any function or method on those modules — it names them as types only.
- **`policy.*` MUST NOT depend on `registry.*` for behavior** — policies receive pre-fetched data via `ScanContext` and never call registry clients directly. The exception above (`types` referencing `npm_attestation::AttestationBundle`) is a *type* reference, not a behavioral one.
- **`cache` MUST NOT depend on `policy`** — the cache is a passive store.

---

## 5. Cross-cutting decisions

| Concern | Decision | Where |
|---------|----------|-------|
| **Async runtime** | tokio (single-threaded for the registry/HTTP fan-out) | Cargo.toml; `main` uses `#[tokio::main]` |
| **HTTP client** | reqwest 0.12, `default-features = false, features = ["json", "rustls-tls"]`. HTTP/3 (`quinn`) is NOT linked. | Cargo.toml; verified during v1.2.0 audit |
| **Crypto provider** | `ring` (via `rustls-tls`). aws-lc-rs is intentionally excluded — the aarch64 cross runner does not ship `cmake`. See [ADR 003 § Build/dependency notes](../architecture/decisions/003-content-hash-cache-integrity.md#builddependency-notes-post-v12) |
| **TLS truststore** | Webpki + rustls-native-certs |
| **Trust roots for provenance** | Pinned at build time: `fulcio-roots/*.der`, `rekor-roots/rekor.pub`, `SUMDB_PUBLIC_KEY_STR`. **No runtime download** (F-013) |
| **Database** | SQLite via rusqlite 0.39 (bundled, WAL mode, mode 0600) |
| **Cross-platform** | linux-gnu (x86_64, aarch64), darwin (x86_64, aarch64), windows-msvc (x86_64). Aarch64-linux build uses `cross-rs/cross` |
| **Error handling** | `anyhow` for application errors; `thiserror` for library boundaries (e.g. `RegistryError`) |
| **Concurrency model** | One-shot CLI; no daemon, no IPC, no shared mutable state except the local SQLite cache |
| **Local-first** | No telemetry, no network calls except for explicit user-invoked scans |

---

## 6. Deployment

dep-scan ships as a single statically-linked binary. There is no deployment topology.

| Target triple | Built by | Built where |
|---------------|----------|-------------|
| `x86_64-unknown-linux-gnu` | `cargo build --release` | GitHub Actions ubuntu-latest |
| `aarch64-unknown-linux-gnu` | `cross build --release --target aarch64-unknown-linux-gnu` | GitHub Actions ubuntu-latest with `cross-rs/cross` |
| `x86_64-apple-darwin` | `cargo build --release` | GitHub Actions macos-13 |
| `aarch64-apple-darwin` | `cargo build --release` | GitHub Actions macos-14 |
| `x86_64-pc-windows-msvc` | `cargo build --release` | GitHub Actions windows-latest |

Each release publishes a binary + `sha256sums.txt` to GitHub Releases. The `install.sh` script downloads the appropriate binary based on `uname -m`/`uname -s`.

---

## 7. Element naming conventions

- **Persons:** noun phrases, one-line description, role-focused.
- **Systems:** match the canonical name where one exists (e.g. "PyPI", not "Python Package Index").
- **Containers:** lowercase command / file name.
- **Components:** the module name in source (e.g. `policy.age`, `registry.npm`). When the module is one of many in a subdirectory, prefix with the parent (`policy.age`, not just `age`).

When this catalog changes, [`../architecture/diagrams.md`](../architecture/diagrams.md) MUST be updated in the same commit. A row added here without a diagram update is a drift.

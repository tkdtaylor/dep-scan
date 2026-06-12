# Interfaces

**Project:** dep-scan
**Last updated:** 2026-06-12 (task 108: transitive scan path wiring — native `Transitive scan:` section + combined `{results, transitive}` JSON shape when transitive is enabled)

The system's contact surface — everything that calls into the system, everything the system calls out to, and the public traits within the system. Each interface is a stable contract: changes here are breaking changes.

Not in this file:
- What the interfaces *do* (that's in [behaviors.md](behaviors.md))
- What data flows through them (that's in [data-model.md](data-model.md))
- How they're configured (that's in [configuration.md](configuration.md))

---

## Inbound interface: CLI

### Invocation

```
dep-scan [GLOBAL OPTIONS] <SUBCOMMAND> [SUBCOMMAND OPTIONS]
```

### Global flags

| Flag | Type | Default | Effect |
|------|------|---------|--------|
| `--config <PATH>` | path | `.dep-scan.toml` in cwd | Override the config file path |
| `-v`, `--verbose` | bool | `false` | Enable verbose output (anyhow chain, audit log, tlog field diagnostics) |
| `-q`, `--quiet` | bool | `false` | Reserved — parsed by clap but no command currently gates output on it. Present for forward compatibility |

### Subcommand: `check`

```
dep-scan check <PACKAGE>... [--registry <NAME>] [--format <FORMAT>]
                            [--lockfile <PATH>] [--lockfile-type <TYPE>]
                            [--allow-unsigned]
```

| Argument / flag | Type | Required | Effect |
|-----------------|------|----------|--------|
| `<PACKAGE>...` | string list | yes (unless `--lockfile`) | Package-name tokens. MUST reject any starting with `-` (B-001, F-001). |
| `--registry <NAME>` | string | for bare names | `npm` \| `pypi` \| `crates` \| `crates.io` \| `go` \| `gomod` — case-insensitive |
| `--format <FORMAT>` | enum | no (default `native`) | Output format: `native` \| `json` \| `osv` \| `cyclonedx` \| `spdx` \| `vex`. The interchange formats (`osv`/`cyclonedx`/`spdx`/`vex`) are wrapped in a signed DSSE envelope by default (B-029); `native`/`json` are never signed. Mutually exclusive with `--json`. |
| `--json` | bool | no | **Deprecated alias** for `--format json`. Kept for backward compatibility; use `--format json` instead. Mutually exclusive with `--format`. |
| `--lockfile <PATH>` | path | no | Scan every entry in the lockfile |
| `--lockfile-type <TYPE>` | string | no | Override format detection: `npm` \| `pypi` \| `crates` \| `go` |
| `--allow-unsigned` | bool | no | Emit interchange output (`osv`/`cyclonedx`/`spdx`/`vex`) **unsigned** — the raw payload with an explicit `"_dep_scan_unsigned": true` marker instead of a DSSE envelope. Never affects `native`/`json` (B-029). |
| `--transitive` | bool | no | Enable transitive dependency scanning for this invocation, regardless of `[transitive] enabled` in the config file. Mutually exclusive with `--no-transitive` (last flag wins). CLI value takes precedence over config. |
| `--no-transitive` | bool | no | Disable transitive dependency scanning for this invocation, regardless of `[transitive] enabled` in the config file. Mutually exclusive with `--transitive` (last flag wins). CLI value takes precedence over config. |

### Subcommand: `install`

```
dep-scan install <PACKAGE>... --registry <NAME> [--format <FORMAT>] [--force]
                              [--allow-unsigned]
```

| Argument / flag | Type | Required | Effect |
|-----------------|------|----------|--------|
| `<PACKAGE>...` | string list | yes | Same `-`-prefix rejection as `check` (B-001) |
| `--registry <NAME>` | string | **yes** | Same vocabulary as `check`. Unlike `check`, required |
| `--format <FORMAT>` | enum | no (default `native`) | Same format vocabulary as `check`. Interchange formats are DSSE-signed by default (B-029). |
| `--json` | bool | no | **Deprecated alias** for `--format json`. Mutually exclusive with `--format`. |
| `--force` | bool | no | Proceed despite `warn`/`block`. **MUST NOT** bypass content-hash verification (F-002) |
| `--allow-unsigned` | bool | no | Same effect as on `check`: emit interchange output unsigned with the `"_dep_scan_unsigned"` marker. Never affects `native`/`json` (B-029). |

### Subcommand: `config`

```
dep-scan config show   # print effective configuration as TOML
dep-scan config init   # write defaults to .dep-scan.toml in cwd
```

`config init` MUST NOT overwrite an existing `.dep-scan.toml`. It aborts with a non-zero exit code instead.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All packages' aggregated verdicts are `pass`, OR install succeeded (or warned + `--force`) and the wrapped manager exited 0 |
| `1` | One or more packages produced `warn`/`block` verdicts (scan-only); or check failed and `--force` was not given (install) |
| `2` | Runtime error: invalid config, validation reject (`-foo`, bad Go path, bad version), network failure, unknown registry, lockfile parse error |
| _wrapped_ | If the wrapped package manager exits non-zero during `install`, that exit code is forwarded |

The 1 / 2 split is the contract CI gates rely on. Validation failures MUST exit `2`, not `1`.

### Example output (table mode)

```
$ dep-scan check expresss --registry npm

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
```

Header columns: exactly `Package`, `Version`, `Age`, `Result` in that order. Per-policy indented lines follow `  <name>: <pass|WARN|BLOCK>[ — <reason>]`.

### JSON output schema

```json
{
  "scanned_at": "2026-05-22T12:00:00Z",
  "packages": [
    {
      "name": "expresss",
      "version": "0.0.0",
      "registry": "npm",
      "published_at": "...",
      "downloads": null,
      "result": "warn",
      "reason": "Package 'expresss' is similar to popular package 'express' (distance: 0.12)",
      "policies": [
        { "policy_name": "age", "result": "pass", "reason": null },
        { "policy_name": "typosquatting", "result": "warn", "reason": "..." }
      ]
    }
  ]
}
```

Per-policy and aggregate `result` values are exactly one of `"pass"`, `"warn"`, `"block"`. The aggregate `reason` mirrors the worst-case policy's reason (any `block` first, then any `warn`, else `null`).

#### Transitive JSON shape (B-108)

When transitive scanning is **enabled** (`[transitive] enabled = true` or `--transitive`), the `--format json` payload is a two-key object carrying both the flat results and the transitive outcome; the bare results array is preserved unchanged when transitive is disabled (byte-for-byte non-regression, REQ-108-01):

```json
{
  "results": [ /* the flat per-package results above */ ],
  "transitive": {
    "worst_verdict": "block",
    "diagnostics": [
      { "kind": "DepthLimitReached", "node": "registry:npm/deep@1.0.0", "depth": 6 },
      { "kind": "CycleDetected", "from": "registry:npm/a@1.0", "to": "registry:npm/b@1.0" },
      { "kind": "NodeBudgetExceeded", "count": 5001, "limit": 5000 },
      { "kind": "UnresolvedRange", "from": "git:dep@<sha>", "name": "express", "range": "^4.18.0" }
    ],
    "nodes": [
      { "node": "git:malicious-subtree@<sha>", "depth": 0, "verdict": "block" }
    ]
  }
}
```

Native (`--format native`) appends a `Transitive scan:` section after the flat table with one row per scanned transitive node (`<node-id> depth <n> <verdict>`) followed by one line per diagnostic. The transitive worst verdict raises the exit code exactly like a flat failure (Warn/Block ⇒ exit ≥ 1).

### Verbose audit log

Under `--verbose`, `dep-scan install` emits one line per package, immediately before exec'ing the wrapped manager:

```
[audit] <name>@<resolved_version> hash=<content_hash> verdict=<pass|warn|block> sigstore_reverified=<true|false> (L-9)
```

- `sigstore_reverified=true` for pip (hash re-checked via `--require-hashes` between scan-pass and exec).
- `sigstore_reverified=false` for npm / crates / go (TOCTOU gap documented at task 055 / F-026).

### Stability guarantees

| Surface | Stability |
|---------|-----------|
| Subcommand names | Stable across minor versions; additive only |
| Global flags | Stable |
| Exit code semantics (0 / 1 / 2) | **Stable — relied on by CI** |
| JSON top-level shape | Stable; additive only |
| Per-policy `result` values | Stable: exactly `pass`, `warn`, `block` |
| Table column count + order | Stable |
| Per-policy line format | Stable: `  <name>: <verdict>[ — <reason>]` |
| Verbose audit log line format | Stable |

Removing a policy, renaming a `result` value, removing a flag, or changing the audit log format requires a **major version bump**.

---

## Inbound interface: shell wrappers (optional)

The wrapper shims `npmds`, `pipds`, `cargods`, `gods` are **user-installed snippets**, not dep-scan binaries. They MUST:

1. Separate flag tokens (anything starting with `-`) from package-name tokens. Pass **only** package-name tokens to `dep-scan check`.
2. Forward the original argv unchanged to the wrapped manager after `dep-scan check` exits `0`.
3. Abort without exec'ing the wrapped manager when `dep-scan check` exits `1` or `2`.

Sample implementations live in [`../../README.md`](../../README.md#wrapping-package-managers).

---

## Outbound interfaces: registries + sigstore

### `Registry` trait

Source: [`src/registry/mod.rs:109-118`](../../src/registry/mod.rs#L109-L118).

```rust
pub trait Registry: Send + Sync {
    fn get_metadata(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> impl std::future::Future<Output = Result<PackageMetadata, RegistryError>> + Send;
}
```

- `version = None` MUST resolve to the registry's notion of "latest" and return that resolved version in `PackageMetadata.version` — never the literal string `"latest"` (F-009).
- The returned `PackageMetadata` MUST satisfy the rules in [data-model.md § PackageMetadata](data-model.md#packagemetadata--registry--policy-boundary).

### `RegistryError` variants

Source: [`src/registry/mod.rs:60-102`](../../src/registry/mod.rs#L60-L102).

| Variant | When | CLI exit |
|---------|------|----------|
| `NotFound(name)` | Registry returned 404 for the package or version | `2` (or surfaced as P-04 block on typo paths) |
| `RateLimited` | Registry returned 429 or rate-limit body | `2` |
| `NetworkError(msg)` | Transport-layer error (DNS, TLS, connection) | `2` |
| `ParseError(msg)` | Response didn't match expected shape | `2` |
| `InvalidProvenanceUrl(reason)` | PyPI provenance URL SSRF guard fired (B-016) | `2` |
| `InvalidModulePath(reason)` | Go module path grammar validation failed (B-002) | `2` |
| `InvalidVersion(reason)` | Go version-string grammar validation failed (B-003) | `2` |

### Per-registry endpoints

#### npm — `https://registry.npmjs.org` (configurable)

| Endpoint | Use |
|----------|-----|
| `GET /<name>` | Package metadata; resolve `versions[<version>]` or `versions[latest]` |
| `GET /-/npm/v1/attestations/<name>@<version>` | Sigstore provenance attestations (P-09) |
| `GET /downloads/point/last-month/<name>` | Download counts |

`content_hash`: source `dist.integrity` first (SRI `sha512-<base64>` decoded to lowercase hex). Fall back to `dist.shasum` (SHA-1) for diagnostic capture only — F-007 NULLs it on cache write for pass/warn.

#### PyPI — `https://pypi.org` (configurable)

| Endpoint | Use |
|----------|-----|
| `GET /pypi/<name>/<version>/json` | Version-specific metadata |
| `GET /pypi/<name>/json` | All-versions metadata when resolving "latest" |
| `GET /simple/<name>/` (Accept: `application/vnd.pypi.simple.v1+json`) | PEP 691 Simple Index; provides provenance URLs (P-10) |

`content_hash`: `digests.sha256` of the sdist; fall back to the first wheel's `digests.sha256` if no sdist.

Simple Index Content-Type MUST be `application/vnd.pypi.simple.v1+json` exactly. Anything else ⇒ reject (F-012).

#### crates.io — `https://crates.io` (configurable)

| Endpoint | Use |
|----------|-----|
| `GET /api/v1/crates/<name>` | Crate-level metadata |
| `GET /api/v1/crates/<name>/<version>` | Version-specific fields |
| `GET /api/v1/crates/<name>/owners` | Maintainer list |

`content_hash`: `cksum` field as `sha256:<hex>`.

#### Go module proxy — `https://proxy.golang.org` (configurable)

**Validation gates run BEFORE URL composition:**

1. Module path validation (B-002 / F-003).
2. Version string validation (B-003 / F-004) — runs on **every** version string including the proxy's own `@latest` response.

| Endpoint | Use |
|----------|-----|
| `GET /<module>/@v/list` | Version list |
| `GET /<module>/@v/<version>.info` | Version metadata |
| `GET /<module>/@v/<version>.mod` | go.mod content |
| `GET /<module>/@latest` | Latest version (NOT a trust root) |

`content_hash` is not populated by this client — the Go hash lives in the sumdb (`h1:<base64>`).

#### Go sumdb — `https://sum.golang.org` (configurable)

| Endpoint | Use |
|----------|-----|
| `GET /lookup/<module>@<version>` | Signed-note envelope with the `h1:` hash + signed tree head |

The pinned `sum.golang.org` Ed25519 key is a compile-time constant in [`src/policy/go_sumdb.rs`](../../src/policy/go_sumdb.rs). Rotation requires a release (F-013).

### Other outbound interfaces

| Service | Endpoint | Use |
|---------|----------|-----|
| OSV.dev | `https://api.osv.dev/v1/query` | Vulnerability lookups (P-05). No API key. |
| Sigstore Fulcio | _not called at runtime_ | Roots embedded at build time (`fulcio-roots/*.der`) |
| Sigstore Rekor | _not called at runtime_ | Key embedded at build time (`rekor-roots/rekor.pub`). Inclusion proofs arrive in-band in attestation bundles. |

---

## Internal interfaces (Rust traits)

### `Policy` trait

Source: [`src/policy/mod.rs:33-39`](../../src/policy/mod.rs#L33-L39).

```rust
pub trait Policy: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, ctx: &ScanContext) -> PolicyResult;
}
```

- `evaluate` is **synchronous** and MUST NOT make network calls (enrichment happens upstream when `ScanContext` is built).
- The name is the short snake-case label used in JSON `policy_name` and in the per-policy line.

### `PolicyResult` enum

Source: [`src/policy/mod.rs:18-26`](../../src/policy/mod.rs#L18-L26). See [data-model.md § PolicyResult](data-model.md#policyresult--policy--aggregator).

### Signed-note verifier signatures

Source: [`src/signed_note.rs`](../../src/signed_note.rs).

```rust
pub fn parse(signed_note: &str) -> Result<ParsedNote<'_>, String>;

pub fn verify_ed25519(
    signed_note: &str,
    key_str: &str,
) -> NoteVerifyOutcome;

pub fn verify_ecdsa_p256<'a>(
    signed_note: &'a str,
    expected_key_name: &str,
    pem_pubkey: &str,
) -> Result<ParsedNote<'a>, NoteVerifyOutcome>;
```

Notable contract details:

- `parse` and the verifiers take `&str` (UTF-8 signed-note text), not `&[u8]`.
- `parse` returns the parsed note structure on success; on failure the `String` carries the human-readable reason (e.g. `"signed note has empty note_text: …"`).
- `verify_ed25519` returns the outcome directly (not wrapped in `Result`). The success case is `NoteVerifyOutcome::Valid` (unit variant); failures are other variants of the same enum.
- `verify_ecdsa_p256` returns `Ok(ParsedNote<'a>)` so callers (specifically `verify_rekor_checkpoint_impl`) can reuse the parsed note rather than re-invoking `parse` — see [F-015](fitness-functions.md#f-015).
- Trust roots are passed as concrete materials (`key_str` for Ed25519 public-key text; `pem_pubkey` for ECDSA P-256 PEM). The verifier does not hold global state.

Contract details: [behaviors.md § B-019](behaviors.md#b-019-signed-note-parse--verify-rekor--sumdb).

### Interchange signing identity (task 086 trait + task 087 identities)

Source: [`src/interchange_sign.rs`](../../src/interchange_sign.rs).

```rust
// Task 086 — the signing abstraction (synchronous over the DSSE PAE bytes).
pub trait InterchangeSigner {
    fn sign(&self, pae: &[u8]) -> Result<(Vec<u8>, String)>; // -> (sig_bytes, keyid)
}

// Task 087 — concrete identities.
pub struct OperatorKeySigner; // offline: PEM PKCS#8 Ed25519 from signing.key_path
impl OperatorKeySigner {
    pub fn from_key_path(path: &Path) -> Result<Self>;   // Err if unreadable/unparseable
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self>;
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey; // public half (task 089 export)
    pub fn keyid(&self) -> &str;
}
pub struct KeylessSigner; // online: sigstore Fulcio + Rekor
impl KeylessSigner {
    pub fn new(fulcio_url: &str, rekor_url: &str, oidc_token: &str) -> Self; // no network
}

// Shared key-id derivation (single source of truth — task 089 reuses it).
pub fn ed25519_keyid(public_key_bytes: &[u8; 32]) -> String; // lowercase hex SHA-256

// Per-run identity resolution.
pub enum SignerDecision {
    Signer(Box<dyn InterchangeSigner>),
    NoOfflineKey, // fail-closed signal (NOT a silent unsigned signer)
}
impl SignerDecision { pub const NO_OFFLINE_KEY_MESSAGE: &'static str; }
pub fn resolve_signer(
    config: &Config,
    network_probe: impl FnOnce() -> Result<()>,
    keyless_factory: impl FnOnce() -> Box<dyn InterchangeSigner>,
) -> Result<SignerDecision>;
```

Notable contract details:

- `sign` is **synchronous**; `KeylessSigner` bridges to its async Fulcio/Rekor
  HTTP work via `block_in_place` + `Handle::block_on` (requires a multi-thread
  tokio runtime — see ADR 010). `OperatorKeySigner::sign` does no I/O.
- `ed25519_keyid` is the **only** place the operator key-id is derived
  (lowercase hex SHA-256 of the 32 raw public-key bytes); task 089's public-key
  export and the verifier match on this exact value.
- `resolve_signer` never returns a silently-unsigned signer: the absence of an
  offline key is the explicit `NoOfflineKey` variant, which the caller turns
  into a non-zero exit (fail closed). The `network_probe` / `keyless_factory`
  closures are injected so the selection is testable without a real network.

Contract details: [behaviors.md § B-029](behaviors.md#b-029-dsse-signing-for-interchange-output) and [§ B-030](behaviors.md#b-030-signing-identity-resolution-and-fail-closed).

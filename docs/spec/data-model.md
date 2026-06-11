# Data Model

**Project:** dep-scan
**Last updated:** 2026-05-22 (v1.2.0)

What data exists, how it's structured, where it lives, and what relationships hold between entities. Covers persistent storage, in-memory scan state, and data-on-the-wire formats.

Not in this file:
- Operations on the data (that's in [behaviors.md](behaviors.md))
- How the data is accessed (that's in [interfaces.md](interfaces.md))
- Tunable parameters (that's in [configuration.md](configuration.md))

---

## Persistent state

### Store: SQLite cache DB (`~/.dep-scan/cache.db` by default)

**Purpose:** record scan verdicts so already-scanned `(name, version, registry)` triples can be short-circuited on subsequent runs, with content-hash integrity gating.
**Owner:** [`src/cache.rs`](../../src/cache.rs) is the single writer; every other module calls through it.
**Backup / retention:** none. Cache is a soft optimization; it can be deleted at any time and dep-scan will rebuild it on next run.

**Location:**
- Default: `~/.dep-scan/cache.db` (resolved from `$HOME` or `$USERPROFILE`).
- Configurable via `cache_path` in `.dep-scan.toml` or `DEP_SCAN_CACHE_PATH`.
- Tests use `:memory:`.

**File permissions (Unix):** mode `0600` from the first moment the file exists on disk — see [behaviors.md § B-022](behaviors.md#b-022-cache-db-atomic-creation-unix) and [F-018](fitness-functions.md#f-018). WAL companion files (`<path>-wal`, `<path>-shm`) inherit the same mode because SQLite uses the main-file mode when creating them via `open(2)`.

**Windows:** the DB file inherits parent-directory ACLs. There is no `0600` guarantee on Windows; this is documented but not contractually enforced.

#### Entity: `scanned_packages`

```
field_name           type   nullable   notes
─────────────────────────────────────────────
name                 TEXT   no         Package name, exactly as supplied
version              TEXT   no         Resolved version, never the string "latest" (task 038); for git rows: the full commit SHA (task 097)
registry             TEXT   no         Lowercase: npm | pypi | crates | go | git
result               TEXT   no         Aggregate verdict: pass | warn | block
scanned_at           TEXT   no         RFC 3339 UTC timestamp
content_hash         TEXT   yes        <algo>:<hex> — see Content-hash rules; for git rows: sha256 over the fetched tree (task 097)
provenance_identity  TEXT   yes        Verified OIDC subject (npm/PyPI) or "sum.golang.org" (Go)
source_kind          TEXT   yes        "git" for git-sourced rows (task 097); NULL for registry and legacy rows
```

- **Identity:** composite primary key `(name, version, registry)`. Git-sourced rows use the slot `registry = "git"` with `version = commit_sha` (task 097); the `"git"` slot does not collide with any `RegistryType` string.
- **Git source cacheability (task 097):** only **pinned commit SHAs** are cached — an immutable SHA uniquely identifies the fetched tree. **Mutable refs** (branch/tag/short-hash/empty, per `classify_ref` task 094) are **never** written; every scan re-fetches. Git rows are gated by the same content-hash decision matrix below: a missing/`sha1:`/mismatched `content_hash` forces a re-fetch (fail-closed).
- **Lifecycle:** rows are written after every scan (B-021). Invalidated and re-written on content-hash mismatch. Deleted only via cache file removal or manual SQL.
- **Relationships:** none — flat table.
- **Indexes:** primary key index covers all current lookup patterns. No secondary indexes.

#### Entity: `maintainer_history`

```
field_name    type   nullable   notes
─────────────────────────────────────────
name          TEXT   no         Package name
registry      TEXT   no         Same vocabulary as scanned_packages.registry
maintainers   TEXT   no         JSON-encoded array of maintainer usernames / emails (serde_json::to_string)
recorded_at   TEXT   no         RFC 3339 UTC timestamp
```

- **Identity:** primary key `(name, registry)`.
- **Lifecycle:** updated whenever P-06 sees a new maintainer set; first observation either records silently or warns (B-011, task 048).
- **Relationships:** logically tied to a `scanned_packages.(name, registry)` but **not** an FK.

#### Migrations

Additive only. New columns added via `ALTER TABLE … ADD COLUMN …`, gated by a `PRAGMA table_info(scanned_packages)` check so re-runs are idempotent. Pre-029 hash-less rows MUST remain valid and are treated as "needs re-verification" on lookup.

Migration history:
- Initial schema (task 007): `(name, version, registry, result, scanned_at)`.
- Task 029: added `content_hash TEXT NULL`.
- Task 032: added `provenance_identity TEXT NULL`.
- Task 097: added `source_kind TEXT NULL` (`"git"` for git-sourced rows, NULL for registry/legacy rows). Existing registry rows remain valid with no backfill.

---

## Content-hash rules

### Format

`<algo>:<hex>`. Both the algorithm prefix and the hex digest MUST be lowercase. Examples:

```
sha512:5fdb7d11…   ← npm (decoded from dist.integrity base64)
sha256:e3b0c44…   ← PyPI, crates.io
h1:abcdEFG…       ← Go (base64-encoded h1: hash, treated as opaque)
```

### Case normalization (task 046)

Cached `sha512:…` MUST compare equal to a registry-served `SHA512-…`. The verifier lowercases the algorithm prefix and hex digest before comparison. **References:** [F-022](fitness-functions.md#f-022).

### SHA-1 is never trust-gating (task 040)

npm `dist.shasum` is SHA-1. SHAttered (chosen-prefix collision) makes it unsuitable as a cache trust gate.

- A cached row whose `content_hash` starts with `sha1:` MUST re-scan unconditionally, regardless of the registry's current value.
- New writes for `pass` / `warn` verdicts on packages whose only available digest is SHA-1 MUST store `content_hash = NULL` rather than the `sha1:` value. The next lookup falls through to the full pipeline.
- `block` rows MAY store the `sha1:` value for diagnostic purposes; they re-scan on lookup either way.

**References:** [F-007](fitness-functions.md#f-007).

---

## Cache decision matrix

Every cache lookup compares the stored `content_hash` to the registry's currently-published digest and applies this table. There is **no flag** to skip verification.

| Cached `content_hash` | Registry digest | Action |
|-----------------------|-----------------|--------|
| `Some("sha1:…")` | _any_ | **Re-scan unconditionally** ([F-007](fitness-functions.md#f-007)) |
| `Some(a)` | `Some(a)` | Honor cached verdict |
| `Some(a)` | `Some(b)` | Invalidate row, re-scan |
| `Some(a)` | `None` | Invalidate row, re-scan (registry stopped publishing — suspicious) |
| `None` | `Some(b)` | Re-scan (legacy pre-029 row, upgrade in place) |
| `None` | `None` | **Re-scan** — both-`None` is never honored ([F-008](fitness-functions.md#f-008)) |
| `Some(a)` | fetch fails | Re-scan (network, parse, version-not-found, malformed) |

> `--force` on `install` bypasses *verdicts* but MUST NOT bypass content-hash verification ([F-002](fitness-functions.md#f-002)). A user who chooses `--force` after a `block` still only gets to install the bytes the verification matrix would have consulted.

---

## In-memory state

### `PackageMetadata` — registry → policy boundary

Source: [`src/types.rs:98-132`](../../src/types.rs#L98-L132). Every registry client MUST surface this shape, with the rules:

| Field | Type | Required | Drives |
|-------|------|----------|--------|
| `name` | `String` | yes | Cache key, all policy reasons |
| `version` | `String` | yes | **Resolved**, never `"latest"` |
| `description` | `Option<String>` | no | None |
| `published_at` | `Option<DateTime<Utc>>` | no | P-01 (age) |
| `maintainers` | `Vec<String>` | yes (may be empty) | P-06 (maintainer change) |
| `downloads` | `Option<u64>` | no | P-06 (first-seen), P-08 (popularity) |
| `repository_url` | `Option<String>` | no | None |
| `content_hash` | `Option<String>` | no | Cache decision matrix; `sha1:` NULLed on cache write |

Mutability: immutable after construction by the registry client.

### `ScanContext` — policy input bundle

Source: [`src/types.rs:33-78`](../../src/types.rs#L33-L78). Wraps `PackageMetadata` plus enrichment fields:

```rust
pub struct ScanContext {
    pub metadata: PackageMetadata,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub install_scripts: Vec<InstallScript>,
    pub previous_maintainers: Option<Vec<String>>,
    pub npm_attestations: Option<Vec<AttestationBundle>>,
    pub npm_attestation_fetch_error: Option<String>,
    pub pypi_attestation: Option<Option<AttestationBundle>>,
    pub pypi_provenance_fetch_error: Option<String>,
    pub provenance_identity: Option<String>,
    pub go_sumdb_result: Option<GoSumDbResult>,
}
```

- **`*_fetch_error` fields:** when populated, the corresponding provenance policy MUST surface the error (not silently treat as "no attestations").
- **`provenance_identity`:** populated by `main.rs` after a successful P-09 / P-10 / P-11 run, then persisted to the cache row.
- **`npm_attestations: Some(vec![])`:** the endpoint returned 404 — distinct from `None` (not queried).
- **`pypi_attestation: Some(None)`:** queried but no provenance attached to the file.

### `PolicyResult` — policy → aggregator

Source: [`src/policy/mod.rs:18-26`](../../src/policy/mod.rs#L18-L26).

```rust
pub enum PolicyResult {
    Pass,
    Warn(String),
    Block(String),
}
```

`Pass` carries no payload. `Warn`/`Block` carry a human-readable reason. The reason MUST be human-actionable (not bare `"failed"`).

Aggregation rule (`policy::aggregate_results`):

| Any policy returns | Aggregate |
|--------------------|-----------|
| `Block(_)` | `block` (first block's reason) |
| `Warn(_)` and no `Block` | `warn` (first warn's reason) |
| all `Pass` | `pass` |

At the JSON surface, `result` is exactly one of the lowercase strings `"pass"`, `"warn"`, `"block"`. See [interfaces.md § JSON output schema](interfaces.md#json-output-schema).

---

## Data on the wire

### Registry metadata (inbound)

Each registry client deserializes its own response shape into `PackageMetadata`. See [interfaces.md § Registry trait](interfaces.md#registry-trait) and [interfaces.md § Per-registry endpoints](interfaces.md#per-registry-endpoints) for the endpoint vocabulary.

### Sigstore attestation bundles (inbound)

DSSE-envelope JSON containing an in-toto v0.0.2 Statement payload, a Fulcio-issued leaf certificate (PEM), and a `tlogEntries` array with Rekor inclusion proofs + signed checkpoint notes. See [behaviors.md § B-018](behaviors.md#b-018-sigstore-verification-pipeline-npm--pypi) for the verification pipeline and [`src/registry/npm_attestation.rs`](../../src/registry/npm_attestation.rs) for the parser.

### Signed-note envelope (inbound)

Used by Rekor checkpoint and `sum.golang.org` tree heads. Format:

```
<note_text bytes — non-empty>
─                        ← em-dash boundary line
— <key_name> <signature>
— <key_name> <signature>   ← additional rotation signatures permitted
…
```

Parser contract: [behaviors.md § B-019](behaviors.md#b-019-signed-note-parse--verify-rekor--sumdb). Source: [`src/signed_note.rs`](../../src/signed_note.rs).

### Synthetic pip `--require-hashes` file (outbound)

For `dep-scan install --registry pypi`, a temporary requirements file is written via `tempfile::NamedTempFile` (CSPRNG suffix, `O_CREAT|O_EXCL`, mode 0600) containing:

```
<name>==<resolved_version> --hash=sha256:<verified_hex>
```

The file is unlinked automatically when the `NamedTempFile` drops. **References:** task 042, [F-005](fitness-functions.md#f-005).

---

## Out-of-scope threats (data layer)

- **Consistently-lying registry.** Verifying registry metadata against itself passes by construction. Defended by P-09 / P-10 / P-11, not by the cache.
- **Local DB tampering by a privileged attacker.** An attacker with write access to `cache.db` and knowledge of the published digest can flip `block → pass` and set `content_hash` consistently. Row-level HMAC with a per-installation key would address this; out of scope for v1.x.
- **TOCTOU between scan-pass and package-manager exec.** Closed for pip via `--require-hashes` (task 031); for npm / cargo / Go relies on the wrapped manager's own integrity check. Documented via the `--verbose` audit log line (task 055, [F-026](fitness-functions.md#f-026)).

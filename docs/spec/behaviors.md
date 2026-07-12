# Behaviors

**Project:** dep-scan
**Last updated:** 2026-07-12 (task 112: B-112 cached-verdict attribution gate, cross-referenced from B-020)

What the system does, observably. Each behavior describes a triggering condition, the system's response, and any externally-visible side effects. This is the "you can verify this from outside the process" view.

Not in this file:
- *How* it does it (that's in source code; the contract is here, the implementation is there)
- *Why* it does it (that's in ADRs — see [../architecture/decisions/](../architecture/decisions/))
- *What data it operates on* (that's in [data-model.md](data-model.md))
- *What the entry points are* (that's in [interfaces.md](interfaces.md))

## Format

Each behavior is `B-NNN: short imperative title` with:

- **Trigger:** what causes this behavior to fire
- **Response:** what the system does
- **Side effects:** observable effects beyond the immediate response
- **Failure modes:** how it can fail and what the system does on failure
- *(optional)* **References:** ADRs, paired test specs, or fitness functions

Numbers are stable. Removed behaviors stay numbered as `B-NNN: REMOVED — see ADR-XXX`.

---

## Core behaviors

### B-001: Reject `-`-prefixed package-name tokens

- **Trigger:** Any `dep-scan check <PKGS…>` or `dep-scan install <PKGS…>` invocation where one or more positional tokens begin with `-`.
- **Response:** Exit `2` with an error like `package name '-foo' is not valid — package names must not start with '-'`. **No** network call, **no** registry lookup, **no** wrapped-package-manager subprocess invocation occurs.
- **Side effects:** None (fail-closed at the validation boundary).
- **Failure modes:** N/A — this is itself a defensive behavior.
- **References:** [ADR 003 → v1.1.1 hardening](../architecture/decisions/003-content-hash-cache-integrity.md), task 037, [F-001](fitness-functions.md#f-001).

### B-002: Validate Go module path before URL composition

- **Trigger:** Any operation in [`src/registry/go.rs`](../../src/registry/go.rs) that would compose a `proxy.golang.org` URL containing a module path.
- **Response:** Validate the module path against the Go module-path grammar (allowed: alphanumerics, `.`, `-`, `_`, `/`; forbidden: `..` segments, `?`, `#`, whitespace, control chars). Validation failures return `RegistryError::InvalidModulePath(reason)`.
- **Side effects:** None; failure happens before any URL build.
- **References:** task 041, [F-003](fitness-functions.md#f-003).

### B-003: Validate Go version string before URL composition

- **Trigger:** Any operation in [`src/registry/go.rs`](../../src/registry/go.rs) that would compose a proxy URL containing a version string — including the proxy's own `@latest` response, which is **not** a trust root.
- **Response:** Validate the version string against the Go semver / pseudo-version grammar: printable ASCII only; no `/`, `?`, `#`, `%`, `@`, whitespace, CR/LF; no `..`; no percent-encoded forms (`%xx` is rejected even if the bytes decode to benign ASCII). Failures return `RegistryError::InvalidVersion(reason)`.
- **Side effects:** None; failure happens before any URL build.
- **References:** task 060, [F-004](fitness-functions.md#f-004).

### B-004: Scan a package via the policy pipeline

- **Trigger:** `dep-scan check <NAME> --registry <R>` (or any of `dep-scan install`'s embedded check step, or a lockfile entry).
- **Response:**
  1. Load layered config (defaults < `.dep-scan.toml` < env < CLI).
  2. Fetch metadata from registry `R` → `metadata.version` is the **resolved** version (never `"latest"`). For lockfile-driven scans (task 078), the resolved version is the **pinned version from the lockfile** (e.g. `serde@1.0.0` if `Cargo.lock` pins `1.0.0`), not the registry's current latest; the registry client is called with `Some(pinned_version)` so it fetches and returns data for the exact pinned bytes. CLI-arg scans (no lockfile) continue to query the registry's latest version by passing `None`. Bare-name or range-constraint lockfile entries that carry no exact pin also query latest (`None`).
  3. Cache lookup keyed `(name, resolved_version, registry)`:
     - Cache hit ⇒ run the content-hash decision matrix from [data-model.md § Cache decision matrix](data-model.md#cache-decision-matrix). Honor or invalidate accordingly.
     - Cache miss ⇒ continue.
  4. Build `ScanContext` and run policies P-01…P-11 (see [§ B-006 through B-016](#b-006-policy-p-01-age-block-on-young-packages)).
  5. Aggregate per-policy verdicts using the worst-case rule (any block ⇒ `block`; else any warn ⇒ `warn`; else `pass`).
  6. Write the resulting row to the cache (including the registry-published `content_hash` and any verified `provenance_identity`).
  7. Emit output according to `--format` (default `native` table; `json` for legacy JSON array; `osv` for OSV-shaped JSON; `cyclonedx`/`spdx` for SBOM and `vex` for OpenVEX — see B-027, B-028; interchange formats are DSSE-signed per B-029/B-030).
- **Side effects:** Network I/O (registry, OSV.dev, attestation endpoints, sumdb). Local SQLite write. No subprocess invocation.
- **Failure modes:** Exit `2` on registry network failure, invalid config, validation reject. Exit `1` on `warn` or `block` aggregate verdict. Exit `0` on `pass`.
- **References:** [ADR 003](../architecture/decisions/003-content-hash-cache-integrity.md), [`src/policy/mod.rs:74-89`](../../src/policy/mod.rs#L74-L89) (`aggregate_results`).

### B-005: Install a package after a successful scan

- **Trigger:** `dep-scan install <NAME> --registry <R>` exits the scan step with code `0` (or with code `1` if `--force` is given).
- **Response:**
  1. exec the wrapped package manager: `npm install <pkgs>`, `cargo add <pkgs>`, `go get <pkgs>`, or pip (see step 2).
  2. **pip happy path:** every package has a verified sha256 ⇒ write a synthetic requirements file via `tempfile::NamedTempFile` (CSPRNG-suffixed, `O_CREAT|O_EXCL`, mode 0600 — see [F-005](fitness-functions.md#f-005)) containing `<name>==<resolved_version> --hash=sha256:<hex>` per package, then exec `pip install --require-hashes -r <tempfile>`. **pip fallback:** if any package lacks a sha256 (no hash captured, unsupported algorithm, registry fetch failed during the re-confirm pass), emit a `[warn]` line per affected package and fall back to `pip install <packages>` without `--require-hashes`. The TOCTOU gap re-opens in this case and the verbose audit log surfaces `sigstore_reverified=false`.
  3. Under `--verbose`, emit the audit log line specified in [interfaces.md § Verbose audit log](interfaces.md#verbose-audit-log).
  4. Forward the wrapped package manager's exit code.
- **Side effects:** Subprocess fork-exec. Filesystem write inside the synthetic pip requirements file (cleaned up automatically by `NamedTempFile` Drop).
- **Failure modes:** Wrapped command's exit code is forwarded. If `--force` was not given and the scan returned `block`, abort before any exec.
- **References:** task 031 (pip `--require-hashes`), task 042 (`TempReqFile` hardening), task 055 (`--verbose` audit log), [F-005](fitness-functions.md#f-005), [F-026](fitness-functions.md#f-026).

---

## Policy verdicts (P-01 … P-11)

Each policy implements the trait in [`src/policy/mod.rs`](../../src/policy/mod.rs#L33-L39) and returns `PolicyResult::{Pass, Warn(reason), Block(reason)}`. Policies MUST NOT make network calls in `evaluate()` — network I/O happens upstream when `ScanContext` is built.

### B-006: Policy P-01 (`age`) — block on young packages

- **Pass** when `metadata.published_at = Some(t)` and `(now - t) ≥ min_package_age_hours` (default 48h).
- **Warn** when `metadata.published_at = None` (unknown publish date).
- **Block** when the package is younger than the threshold. Reason includes the actual age in hours.
- The boundary is `≥`, not `>`.

### B-007: Policy P-02 (`install_scripts`) — block on dangerous patterns

- **Block** on `eval(`, `child_process`, `os.system`, `subprocess.`, or a base64-shape blob ≥60 chars that contains at least one of `+ / =` (task 051 — pure-hex sequences must not trip).
- Line / block comments (`// …`, `/* … */`, `# …`) MUST be stripped before pattern matching (task 051).
- Scan capped at the first 1 MB (task 045).
- **References:** [F-024](fitness-functions.md#f-024).

### B-008: Policy P-03 (`obfuscation`) — block on encoded payloads

- Six regex patterns (long base64 ≥60, long hex ≥40, `fromCharCode`, unicode escape chains ≥4, URL concat, generic eval-of-string). Patterns compile once via `OnceLock` (task 045).
- Install-script content scanned up to the first 1 MB (DoS bound, not security relaxation).
- **Block** on any match.
- **References:** [F-021](fitness-functions.md#f-021).

### B-009: Policy P-04 (`typosquatting`) — warn/block on edit-distance hits

- **Block** if Levenshtein distance to any popular-package name is `≤ 1` for names of length `≥ 4`.
- **Warn** if normalized similarity score < 0.20 but not in the strict block zone.
- Names longer than 256 chars short-circuit to "not similar" (task 052) — the matrix MUST NOT allocate.
- Popular-package lists are registry-scoped (npm, PyPI, crates.io, Go modules).
- **References:** [F-020](fitness-functions.md#f-020).

### B-010: Policy P-05 (`vulnerability`) — block on OSV hits

- Queries OSV.dev with `(ecosystem, name, version)`. Ecosystem mapping: `npm → npm`, `PyPI → PyPI`, `crates → crates.io`, `go → Go`.
- **Block** on any hit. Reason lists the OSV ID + severity if surfaced.
- **Pass** on empty results from a successful query.
- A failed OSV lookup (network error, non-200, parse failure) is recorded on the
  scan context (`osv_fetch_error`) and the policy returns **Warn** at minimum:
  "vulnerability status is UNKNOWN, not clean" — an empty result from a failed
  fetch never reads as a Pass. The failure is also printed to stderr
  unconditionally (not gated on `--verbose`).

### B-011: Policy P-06 (`maintainer_change`) — warn/block on identity drift

- Reads prior maintainer set from `maintainer_history` table.
- **Block** on full takeover (intersection of old ∪ new is empty).
- **Warn** on partial change.
- **First-observation** behavior is config-gated:
  - `policies.maintainer_first_seen_warning = false` (default): silently record baseline, return `Pass`.
  - `policies.maintainer_first_seen_warning = true` AND `metadata.downloads.unwrap_or(0) == 0` AND no prior baseline: return `Warn` ("first observation of zero-download package").
- **References:** task 048.

### B-012: Policy P-07 (`dependency_confusion`) — warn on internal-namespace names

- **Warn** if the package name (case-insensitively) starts with any token in `dependency_confusion.internal_prefixes` (default `["internal-", "private-", "corp-"]`).

### B-013: Policy P-08 (`popularity`) — warn on low downloads

- **Warn** if `metadata.downloads` is `Some(n)` and `n < popularity.min_downloads` (default 1000).
- `None` downloads (registries that do not publish download counts, e.g. crates.io, Go proxy) are exempt from this check and return **Pass** — absence of telemetry is not a low-popularity signal. See [ADR 004](../architecture/decisions/004-popularity-none-downloads.md).

### B-014: Policy P-09 (`npm_provenance`) — verify sigstore SLSA attestation

- Fetches `/-/npm/v1/attestations/{name}@{ver}`.
- For each bundle, runs the full sigstore pipeline (see [B-017](#b-017-sigstore-verification-pipeline)).
- **Pass** when verification succeeds and the subject sha512 matches `metadata.content_hash`.
- **Warn** when no attestations exist (default); escalates to **Block** when `policies.require_npm_provenance = true`.
- **Block** on any verification failure (chain, inclusion, identity, validity window).
- Populates `ScanContext.provenance_identity` on success → persisted to the cache row.

### B-015: Policy P-10 (`pypi_provenance`) — verify PEP 740 attestation

- Fetches the PEP 691 Simple Index entry with `Accept: application/vnd.pypi.simple.v1+json`.
- Response Content-Type MUST be `application/vnd.pypi.simple.v1+json` exactly (task 049). Other types ⇒ **Block**.
- The provenance URL is validated **before fetch** (task 039 — see [B-016](#b-016-pypi-provenance-url-ssrf-guard)).
- Same sigstore pipeline as B-014, with sha256 subject digests.
- **Warn** (default) / **Block** under `policies.require_pypi_provenance` when no provenance.
- **References:** [F-006](fitness-functions.md#f-006), [F-012](fitness-functions.md#f-012).

### B-016: PyPI provenance URL SSRF guard

- **Trigger:** Before any `GET` of a provenance URL returned by the Simple Index.
- **Response:** Validate the URL:
  - Scheme exactly `https://`
  - Host matches the configured PyPI host **or** the compile-time allowlist (`files.pythonhosted.org`)
  - Resolved IP MUST NOT be in RFC1918, link-local (169.254.0.0/16), loopback (127.0.0.0/8), multicast, or reserved ranges.
- **Failure modes:** `RegistryError::InvalidProvenanceUrl(reason)`. The policy converts this to `Block`.
- **References:** task 039, [F-006](fitness-functions.md#f-006).

### B-017: Policy P-11 (`go_sumdb`) — verify Ed25519 sumdb signature

- Fetches `sum.golang.org/lookup/<module>@<version>`.
- Parses the signed-note envelope (see [B-019](#b-019-signed-note-parse--verify-rekor--sumdb)).
- Verifies Ed25519 signature against the **pinned** `sum.golang.org` public key.
- **Pass** when signature verifies and `h1:` hash matches.
- **Warn** (default) / **Block** under `policies.require_go_sumdb` when module is not in sumdb (404).
- **Block** on any signature-verification failure.
- Populates `ScanContext.provenance_identity = "sum.golang.org"`.

---

## Verification pipelines

### B-018: Sigstore verification pipeline (npm + PyPI)

For each DSSE-signed attestation bundle, the following steps run in order in [`src/sigstore_verify.rs::verify_dsse_bundle`](../../src/sigstore_verify.rs). Fail-closed at every step. Any failure ⇒ `Block` with a reason naming the failing step.

1. **Decode the DSSE payload** from the bundle envelope.
2. **Parse the SLSA / in-toto statement and compare the subject digest.** Extract `subject[].digest.<algo>` and compare byte-for-byte against `metadata.content_hash` (sha512 for npm, sha256 for PyPI). This happens *before* signature verification so that a digest mismatch produces a distinct "subject digest mismatch" error rather than a misleading "signature failure" error.
3. **Extract the leaf certificate** from `verificationMaterial`.
4. **Parse the leaf certificate** with `x509-parser`.
5. **Fulcio chain walk.** Build a path from leaf → intermediate → root using `x509-parser`'s `verify` feature against the embedded Fulcio trust bundle in `fulcio-roots/*.der`. Reject if no valid path exists. Failures prefixed `Fulcio chain validation failed: …` so operators can distinguish chain failures from signature failures.
6. **Extract the public key** from the leaf certificate.
7. **DSSE signature verification.** Verify the envelope signature against the leaf's public key using ECDSA P-256 over the PAE-encoded message (`DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`).
8. **Rekor inclusion proof + signed checkpoint.** Reconstruct the Merkle path from the entry hash to the signed tree-head root using RFC 6962 sibling pairing, and verify the signed checkpoint note signature against the pinned Rekor key. The signed-note parse result is reused — no second parse (task 062, [F-015](fitness-functions.md#f-015)).
9. **Time-window validity.** The Rekor `integratedTime` MUST fall inside the leaf cert's `[notBefore, notAfter]`. This is the actual replay defense for the always-expired-by-the-time-we-check Fulcio certs.
10. **Identity extraction.** Return the first URI SAN from the leaf cert ([ADR 003 / L-2](../architecture/decisions/003-content-hash-cache-integrity.md)). Stored to `ScanContext.provenance_identity` and persisted to the cache row.
11. **Structural Fulcio OID check (belt-and-braces, runs LAST).** Verify the leaf carries the Fulcio issuer-OID extension `1.3.6.1.4.1.57264.1.1`. The cryptographic chain walk in step 5 is the primary trust gate; this structural assertion is retained for behavior parity with the pre-035 implementation ([ADR 003 / L-1](../architecture/decisions/003-content-hash-cache-integrity.md)).

- **References:** [F-013](fitness-functions.md#f-013), [F-015](fitness-functions.md#f-015), tasks 032, 033, 035, 036, 050, 061, 062.

### B-019: Signed-note parse + verify (Rekor + sumdb)

- **Trigger:** Any call to `signed_note::parse` or `verify_ecdsa_p256` / `verify_ed25519`.
- **Parse contract:**
  - Em-dash boundary line separates `note_text` from signature lines.
  - Boundary detection uses a **single-pass walk from the front** (task 044). MUST NOT use `rfind("\n\n")` — brittle against blank lines in note bodies. **References:** [F-017](fitness-functions.md#f-017).
  - `note_text` MUST be non-empty. Zero-byte body ⇒ `Err("signed note has empty note_text: …")` — before any signature-iteration loop runs (task 063, [F-014](fitness-functions.md#f-014)). The error type is `String`, not an enum; the message names the policy that caught it.
- **Verify contract:**
  - **Key-id derivation (per ecosystem):** the 4-byte key-id a signature line must match is ecosystem-specific. Ed25519/sumdb uses Go's `note.keyHash` = `SHA256(key_name + "\n" + key_bytes)[:4]` (`key_bytes` = `0x01 || raw_ed25519_pubkey`); there is **no** `"hash:1:"` prefix — adding one yields a key-id (`9f6cb724`) that never matches the real `sum.golang.org` line (`033de0ae`) and BLOCKs every real Go module (task 110). Rekor/ECDSA uses `SHA256(SPKI_DER)[:4]` (no name) — a deliberately different scheme; the two MUST NOT be unified.
  - Iterates across **all** signature lines (task 043). A non-matching `key_id` MUST `continue` to the next signature line — not return `Invalid`. This closes false-rejections during Rekor key-rotation windows. **References:** [F-016](fitness-functions.md#f-016).
  - Returns `Ok(ParsedNote<'_>)` on the first verifying signature. Returns `Err(NoteVerifyOutcome::…)` when none verify.
- **Trust-root precedence:** verifier receives roots as an explicit argument. P-09/P-10 pass the pinned Rekor key; P-11 passes the pinned `sum.golang.org` key. No global state.

---

## Cache behaviors

### B-020: Content-hash verification on cache hit

- **Trigger:** Any cache lookup for `(name, version, registry)` returns a row.
- **Response:** Apply the decision matrix in [data-model.md § Cache decision matrix](data-model.md#cache-decision-matrix). Honor or invalidate accordingly. There is **no flag** to skip this check.
- **Side effects:** Invalidated rows are deleted; re-scan triggers a full pipeline run.
- **References:** [F-002](fitness-functions.md#f-002), [F-007](fitness-functions.md#f-007), [F-008](fitness-functions.md#f-008), task 030. A row that passes this gate must still pass the attribution gate (B-112) before it is honored as a top-level hit.

### B-021: Cache write after every scan

- **Trigger:** A scan completes (regardless of pass / warn / block).
- **Response:** Write a row to `scanned_packages` with `result`, `scanned_at`, `content_hash` (NULLed if the only available digest was SHA-1 and the verdict is pass/warn — task 040, [F-007](fitness-functions.md#f-007)), and `provenance_identity` if populated.
- **Side effects:** SQLite INSERT OR REPLACE keyed by `(name, resolved_version, registry)`.

### B-022: Cache DB atomic creation (Unix)

- **Trigger:** `Cache::new(path)` on a path that does not yet exist.
- **Response:** Pre-create the file via `OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)` (O_CREAT|O_EXCL atomic), drop the handle, then `Connection::open(path)`. Followed by a fallthrough `set_permissions(0o600)` that narrows any legacy `0644` file.
- **Side effects:** New file on disk with mode `0600` from the first moment it exists. WAL companion files `-wal` / `-shm` inherit the same mode.
- **References:** [F-018](fitness-functions.md#f-018), [F-019](fitness-functions.md#f-019), task 059, task 054.

### B-023: Cache I/O error surfacing

- **Trigger:** `Cache::lookup` returns an `Err` (DB locked, schema corruption, I/O).
- **Response:** Surface the error to stderr. Fail-open is preserved — the scan continues as if cache miss — but the failure is visible.
- **References:** [F-023](fitness-functions.md#f-023), task 047.

### B-112: Cached verdict attribution

- **Trigger:** A cache lookup for `(name, version, registry)` (registry path) or `(name, commit_sha, "git")` (flat-git path) passes the B-020 content-hash gate.
- **Response:** The row is honored as a top-level hit ONLY when it additionally carries full, internally-consistent attribution: `dep_scan_version` present, `policies_json` present and parses to `Vec<PolicyDetail>`, and re-aggregating those policies reproduces the row's stored `result`. Any failure is treated exactly like a content-hash miss: fall through to the existing re-scan path (no explicit invalidate; the re-scan's `INSERT OR REPLACE` upgrades the row in place). See the [attribution gate table](data-model.md#attribution-gate-task-112-stacks-on-top-of-the-content-hash-gate) in data-model.md.
- **Output shape:** An honored hit emits the real resolved version (not a placeholder), the recomputed `age_hours`, the stored `policies` array, the recomputed aggregate `reason`, and an additive `cache: { hit: true, scanned_at, dep_scan_version }` object (copied verbatim from the row). The literal strings `"cached"` (as a `version`) and `"cached result"` (as a `reason`) no longer appear anywhere in output. Fresh scans are unaffected: the `cache` key is omitted entirely (additive-only contract, REQ-112-05).
- **Writes:** `Cache::insert`/`insert_git` stamp `dep_scan_version` internally from `env!("CARGO_PKG_VERSION")` (never a caller-supplied parameter). The flat registry write site and the flat git write site pass the serialized `Vec<PolicyDetail>` used for that verdict's aggregation; the transitive edge-scan git write site (task 106/108, `src/transitive/scanner.rs`) does the same. Other internal writes (e.g. the digest-refresh write in `src/transitive/scan.rs`) pass `None` when no details vec is naturally in scope.
- **Scope:** The task-106 transitive verdict-reuse gate (bare `Verdict`, not a `CheckResult`) is unchanged and carries no attribution requirement. This behavior applies only to the two top-level `CheckResult`-producing cache-hit paths.
- **Side effects:** None beyond the normal re-scan write path; a miss on this gate never invalidates the row explicitly.
- **References:** [data-model.md § scanned_packages](data-model.md#entity-scanned_packages), [interfaces.md § Cache provenance](interfaces.md#cache-provenance-cache-object-task-112), [F-028](fitness-functions.md#f-028), B-020, B-021, B-097, task 112.

### B-097: Git-source cache integration

- **Trigger:** A git-sourced dependency (`DependencySource::Git { url, ref_ }`) reaches the git-dep scan arm.
- **Response:**
  - The ref is classified via `classify_ref` (B/task 094). **Pinned commit SHAs** are looked up in the cache under `(name, commit_sha, "git")`; a verified hit (content-hash gate per B-020) reuses the stored verdict **without re-fetching**. On a miss, hash mismatch, or `sha1:`/missing stored hash, the dep is fetched (task 096), and on a successful fetch the verdict is written under `(name, commit_sha, "git")` with a `sha256:` `content_hash` over the fetched tree.
  - **Mutable refs** (branch/tag/short-hash/empty) are **never** cached — neither looked up nor written — so every scan re-fetches. A fetch failure is never cached (fail-closed).
  - A cache **lookup error** for a git dep is surfaced to stderr as a warning and the scan proceeds with a full re-fetch (never a silent pass, never a hard abort — same posture as B-023 / REQ-047).
- **Side effects:** SQLite INSERT OR REPLACE keyed `(name, commit_sha, "git")` with `source_kind = "git"`, pinned refs only.
- **References:** [ADR 008 § Piece 2 cache resolution](../architecture/decisions/008-git-vcs-dependency-handling.md), B-020, B-023, B-096, tasks 094 / 096 / 097.

### B-098: Policy pipeline on fetched git trees

- **Trigger:** The git-dep scan arm fetches a tree (B-096) on a cache miss / mutable ref (B-097).
- **Context construction:** `ScanContext::from_fetched_tree(&tree)` classifies every materialised file by path: a file whose basename stem is `preinstall`/`install`/`postinstall`, or whose basename is exactly `binding.gyp`, becomes an `install_scripts` entry; **every other file** becomes a `source_files` entry. In both, the entry `name` is the file's path **relative to the fetch root** so a verdict naming the file points the operator at it (REQ-098-05). The builder performs **static analysis only** — it reads each blob's already-materialised bytes (decoded lossily to UTF-8) and **never executes** any file (REQ-098-01, T-098-02). The caller sets `metadata.{name,version}` to the dep name/ref and `git_source = Some((url, ref))`.
- **Pipeline:** The arm runs the mutable-ref policy plus the **same enabled policy set** the registry path uses (T-098-09), then aggregates **worst-verdict-wins** (T-098-08), identical to B-004.
  - `install_scripts` (B-007) fires on dangerous patterns in install-hook files; `obfuscation` (B-008) additionally scans `source_files`, so an obfuscated payload in an ordinary source file of a git dep is still caught (T-098-06).
  - **Registry-only policies return `Pass` for git deps** — `age`, `typosquatting`, `dependency_confusion`, and `maintainer_change` short-circuit to `Pass` when `git_source.is_some()`, because a git dep has no registry publish date, registry name to compare, or maintainer history (REQ-098-03, T-098-14/15). `popularity`, `vulnerability`, and the provenance/sumdb policies already `Pass` on their absent enrichment fields.
- **Cache hit skips the pipeline:** A verified pinned-SHA cache hit (B-097) reuses the stored verdict **without fetching or running any policy** (T-098-10).
- **Output:** Each evaluated policy contributes a `PolicyDetail`; both `--format native` and `--format json` surface the git-dep verdict and the tree-relative path in the message (T-098-12/13).
- **References:** [ADR 008 § Piece 2](../architecture/decisions/008-git-vcs-dependency-handling.md), B-004, B-007, B-008, B-096, B-097, task 098.

### B-108: Transitive dependency scan (capstone)

- **Trigger:** A `check`/`install` scan runs with transitive scanning enabled — either `[transitive] enabled = true` in config or `--transitive` on the CLI (the CLI value overrides config; `--no-transitive` forces off). When disabled, **none** of this behavior runs and the output is byte-for-byte identical to the flat scan (REQ-108-01, T-108-02).
- **Walk:** After the flat scan loop computes and caches every direct dependency's verdict, the transitive walker (ADR 009) traverses the dependency graph from each direct dep. For an npm `package-lock.json` the registry edge graph is read from the lockfile (task 100); other lockfile formats supply their direct deps as roots. Each node is keyed on its cache identity (`(name, version, registry)` or `(name, commit_sha, "git")`).
- **Node verdicts:** Registry-node verdicts are **reused** from the flat results (no new registry network I/O — the lockfile already lists every transitive registry package flat). The only **new** network work is fetching **git sub-trees** (the nodes a lockfile cannot cover), each fetched through the bounded fetch pool (B/task 105) honoring `fetch_concurrency`, charged against the `max_total_nodes` budget. The budget is a **hard upper bound**: every node a git sub-tree's manifest discovers **during the walk** is also charged, so a git sub-tree's declared fan-out cannot evade the ceiling — a breach (from up-front graph nodes or walk-discovered nodes alike) fails closed with `NodeBudgetExceeded`. A git node is fetched + scanned with the **same** git arm B-098 uses.
- **Rollup (fail-closed):** Each root's verdict is the worst across itself and its scanned subtree (worst-verdict-wins, B-004). Every gap — an unfetchable git sub-tree, an `UnresolvedRange` manifest edge, a depth-limit cut, a node-budget breach — contributes **at least `Warn`**, never `Pass`. A `Block` anywhere in the subtree makes the root `Block`. The transitive worst verdict raises the scan's exit code exactly like a flat failure (Warn/Block → exit ≥ 1; T-108-04/16). A malicious transitive node cannot hide behind a clean direct dep.
- **Diagnostics:** `DepthLimitReached`, `CycleDetected`, `NodeBudgetExceeded` (with count + limit), `UnresolvedRange`, and `Unfetchable` (a git sub-tree whose origin could not be resolved or whose fetch failed — carries `node` + a short `reason`, so a fail-closed `warn` row is never bare/unexplained) are surfaced in **both** `--format native` (a `Transitive scan:` section appended after the flat table, reusing `render_native` for the table — REQ-108-04) and `--format json` (a `{"results": [...], "transitive": {...}}` object; the bare results array is preserved when transitive is disabled).
- **Cache binding:** Each scanned git node's `subtree_digest` (B/task 106) is written so a warm re-scan is a cache hit and a **changed child** invalidates its parent: a pre-walk pass recomputes each git parent's subtree digest from its children's current verdicts and invalidates the parent's row on mismatch, forcing a re-scan that propagates the new verdict to the root (REQ-108-06, T-108-17/18).
- **Network discipline:** All fetches are git sub-tree fetches on the scan path; integration tests use only local fixtures or a loopback `git daemon` (zero external network, REQ-108-08).
- **References:** [ADR 009](../architecture/decisions/009-transitive-resolution.md), B-004, B-096, B-097, B-098, tasks 100–107.

---

## Output behaviors

### B-024: Human-readable table output

- **Trigger:** `dep-scan check` with `--format native` (the default, also triggered when no `--format` is given).
- **Response:** One header row (`Package`, `Version`, `Age`, `Result`) + one indented line per policy: `  <policy_name>: <pass|WARN|BLOCK>[ — <reason>]`.
- See [interfaces.md § Example output](interfaces.md#example-output).

### B-025: JSON array output

- **Trigger:** `dep-scan check --format json` or the deprecated alias `--format json` / `--json`.
- **Response:** Single JSON document with the schema in [interfaces.md § JSON output schema](interfaces.md#json-output-schema). `result` is exactly one of `"pass"`, `"warn"`, `"block"`. The deprecated `--json` flag is a backward-compatible alias; `--format` and `--json` are mutually exclusive.

### B-027: OSV-compatible output

- **Trigger:** `dep-scan check --format osv`.
- **Response:** A JSON object `{ "results": [...] }` where each element has:
  - `package.name`, `package.version`, `package.ecosystem` (OSV schema fields)
  - `vulns` — array of `{ "id": "..." }` objects; empty for packages with no findings
  - `dep_scan_result` — extension field: `"pass"` | `"warn"` | `"block"`
- The ecosystem string follows the OSV registry mapping: `npm` → `"npm"`, `pypi` → `"PyPI"`, `crates` → `"crates.io"`, `go` → `"Go"`.

### B-028: SBOM and VEX interchange formats

- **Trigger:** `dep-scan check --format cyclonedx|spdx|vex`.
- **Response:** dep-scan renders the scanned dependency set as a Software Bill of
  Materials or VEX document, with scan verdicts attached:
  - `cyclonedx` → CycloneDX 1.4+ JSON ([`src/sbom.rs::render_cyclonedx`](../../src/sbom.rs)).
  - `spdx` → SPDX 2.3+ JSON ([`src/sbom.rs::render_spdx`](../../src/sbom.rs)).
  - `vex` → OpenVEX, presence-only (`affected` / `fixed` / `under_investigation`
    derived from existing OSV data; no reachability analysis —
    [`src/vex.rs::render_vex`](../../src/vex.rs), [ADR 005](../architecture/decisions/005-interchange-standards-osv-sbom-vex.md)).
- The SBOM is of the **analyzed dependency tree**, not dep-scan's own binary (the
  release-artifact SBOM is a separate concern; see [ADR 005](../architecture/decisions/005-interchange-standards-osv-sbom-vex.md)).
- Like all interchange formats, these are signed by default and gated by
  [B-029](#b-029-dsse-signing-for-interchange-output) / [B-030](#b-030-signing-identity-resolution-and-fail-closed)
  (use `--allow-unsigned` to emit the raw payload).
- *(Superseded the pre-083 stub behavior, which exited non-zero with
  `"not yet implemented"`. The formats shipped in tasks 084/085.)*

### B-029: DSSE signing for interchange output

- **Trigger:** `dep-scan check`/`install` with `--format osv|cyclonedx|spdx|vex`.
- **Response (default):** The rendered interchange payload is wrapped in a DSSE
  envelope JSON object signed **once per run** over the entire result set
  (never per-package):
  ```json
  { "payload": "<base64(payload)>", "payloadType": "<media-type>",
    "signatures": [ { "keyid": "<id>", "sig": "<base64(sig)>" } ] }
  ```
  The signature is computed over the DSSE PAE
  (`DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`, the same
  encoder used for verification in [B-018](#b-018-sigstore-verification-pipeline-npm--pypi) /
  `src/registry/npm_attestation.rs::dsse_pae`). `payloadType` per format:
  `osv` → `application/vnd.osv+json`, `cyclonedx` → `application/vnd.cyclonedx+json`,
  `spdx` → `application/spdx+json`, `vex` → `application/vnd.openvex+json`.
- **`--allow-unsigned`:** The raw interchange payload is emitted with an explicit
  `"_dep_scan_unsigned": true` marker and **no** DSSE envelope; the signer is
  never invoked, so a downstream consumer can detect the unsigned report and
  apply its own policy.
- **`native`/`json` are never signed** and incur zero signing cost — the signer
  is not constructed/invoked on those paths (preserves the local-first/fast
  default scan loop, ADR 006 Q8). `--allow-unsigned` never affects them.
- **Failure mode:** A signing failure is **fatal** — `run_check` returns `Err`,
  nothing is written to stdout, and the process exits non-zero. There is no
  unsigned fallback unless `--allow-unsigned` was explicitly given.
- The signing **identity** (sigstore keyless / operator-provisioned offline key)
  is resolved per run — see [B-030](#b-030-signing-identity-resolution-and-fail-closed).
- Source: [`src/interchange_sign.rs`](../../src/interchange_sign.rs).

### B-030: Signing identity resolution and fail-closed

- **Trigger:** A signed interchange format (`--format osv|cyclonedx|spdx|vex`
  without `--allow-unsigned`) reaches the output dispatch in `run_check`.
- **Resolution order** (`interchange_sign::resolve_signer`):
  1. If `signing.offline == true` (which `DEP_SCAN_OFFLINE` may have forced) →
     **offline path**.
  2. Otherwise a lightweight network probe runs: success ⇒ **online keyless**
     (`KeylessSigner` — Fulcio cert issuance + Rekor log entry, reusing the
     configurable `signing.fulcio_url`/`signing.rekor_url` and an operator-
     supplied `signing.oidc_token`); probe failure ⇒ **offline path**. Keyless
     is only attempted when those three values are configured; otherwise the
     probe reports offline.
- **Offline path:** `signing.key_path` set ⇒ `OperatorKeySigner` loads the
  operator-provisioned **PEM PKCS#8 Ed25519** private key and signs locally with
  no network. The key-id is the **lowercase hex SHA-256 of the 32 raw public-key
  bytes** (`interchange_sign::ed25519_keyid`) so a consumer holding the public
  half can select the right verification key.
- **Fail closed (REQ-087-05):** offline path with **no** `signing.key_path`
  configured ⇒ dep-scan exits non-zero with a message naming `signing.key_path`
  and `--allow-unsigned`, and emits **no** output on stdout — neither a DSSE
  envelope nor a silently-unsigned payload. `--allow-unsigned` (B-029) is the
  only way to emit unsigned interchange output.
- **No embedded private key** ships in the binary or repo (ADR 007); there is no
  ephemeral per-run default signer on the signed path.
- Source: [`src/interchange_sign.rs`](../../src/interchange_sign.rs),
  [`src/main.rs`](../../src/main.rs) (`resolve_interchange_signer`).

### B-026: Verbose-gated diagnostics

- `parse_tlog_entries` missing-field name emits **only** under `--verbose` (task 061, [F-011](fitness-functions.md#f-011)). Default error stays generic.
- Outer `Error:` line shows only the outermost message by default; the full anyhow chain is gated behind `--verbose` (task 053, [F-025](fitness-functions.md#f-025)).
- The install-boundary audit log line is emitted only under `--verbose` (task 055, [F-026](fitness-functions.md#f-026)).

### B-031: Git-sourced dependency visibility in scan output

- **Trigger:** A lockfile entry with `DependencySource::Git` (url + ref) enters the scan loop.
- **Response:** The scan loop's dedicated git-dep arm runs the mutable-ref policy (B-094), **attempts a sandboxed VCS fetch** (B-096, task 096), and on a successful fetch runs the **full policy pipeline** over the fetched tree (B-098, task 098). It produces a `CheckResult` with `version = <ref>`, `registry = "git"`, a `reason` message containing the URL and ref, and one `PolicyDetail` per policy evaluated. No registry client is ever contacted for a git dep.
- **Verdict contract:** The verdict is **never** `Pass` unless the fetch succeeded *and* every policy passed. A fetch that fails, times out, or is blocked by host policy fails closed to at least `Warn` (or `Block` when `mutable_git_ref = "block"`), even for a pinned SHA — an unfetchable dep is not safe (ADR 003 / ADR 008, T-096-15). On a successful fetch the aggregate is worst-verdict-wins across all policies (B-098).
- **Output formats:** Both `--format native` (human-readable table) and `--format json` include a row/element for each git dep with its verdict and message. The ref appears in the version column.
- **Exit code:** Non-zero (exit 1) when at least one git dep yields a `Warn`/`Block`.
- **Registry deps:** Completely unaffected — `DependencySource::Registry` deps continue to route to registry clients as before.
- Source: [`src/main.rs`](../../src/main.rs) (`run_check` scan loop, `classify_dep_routing`, `DepRouting::GitSkip`).

### B-096: Sandboxed VCS fetch

- **Trigger:** The git-dep arm of `run_check` calls `VcsFetcher::fetch(url, ref_)` (task 096). Network I/O happens **only** here — never during config load or lockfile parse (REQ-096-02).
- **Host policy first:** For network schemes, `check_host_policy_for_url` is evaluated **before any socket is opened** (REQ-096-03). A blocked host returns an error with no network I/O. `file://` and bare local paths bypass the host lists (no socket).
- **No code execution (REQ-096-04):** The fetch uses pure-Rust gitoxide (`gix`) to pull the pack into an *ephemeral bare repo*, then reads blobs at the object level and materialises files itself. No `git` CLI, no checkout. Therefore: git hooks never run; submodules (`Commit` entries) are never recursed (recorded as a diagnostic); symlinks (`Link` entries) are never followed (recorded as a diagnostic, never written to disk); tree-entry names containing `..`, separators, NUL, or a drive/absolute prefix produce an error (the fetch fails closed, nothing is written outside the isolated root).
- **Resource bounds:** A blob larger than `vcs.max_blob_bytes` (default 50 MiB) is skipped via its object header without being decoded into memory (REQ-096-08). The fetch is bounded by `vcs.fetch_timeout_secs` (default 30) on a worker thread; an overrun returns an error (REQ-096-07).
- **Single-binary:** The default path works with **no system `git` on PATH** (REQ-096-06, pure-Rust transport).
- **Lifecycle:** The returned `FetchedTree` owns an ephemeral temp dir removed on drop (REQ-096-01).
- **Fail-closed:** Any error (DNS/connect/timeout/ref-not-found/sandbox violation) propagates to B-031's verdict as `Warn`/`Block`, never `Pass` (REQ-096-05).
- Source: [`src/vcs/fetch.rs`](../../src/vcs/fetch.rs).

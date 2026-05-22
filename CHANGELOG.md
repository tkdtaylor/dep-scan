# Changelog

All notable changes to dep-scan are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-05-22

A maintenance release that lands the MEDIUM and LOW findings from the
v1.1.0 security audit, refreshes two transitive dependencies, and tightens
several false-positive paths. No breaking changes.

### Security (MEDIUM findings, tasks 043–050)

- **Signed-note verifiers iterate across multiple signature lines**
  (task 043 / M-7) — `verify_ed25519` and `verify_ecdsa_p256` in
  `src/signed_note.rs` now skip past a non-matching `key_id` and try the
  next signature line instead of returning `Invalid` immediately. Closes
  a false-rejection during Rekor key-rotation windows where multiple
  signatures coexist on a note.
- **Signed-note boundary parser uses em-dash walk** (task 044 / M-8) — the
  fragile `rfind("\n\n")` boundary detection is replaced with a single-pass
  scan that stops at the first em-dash signature line. Robust against blank
  lines that may legitimately appear inside the note body in future Rekor
  formats.
- **Obfuscation policy: regex cache + script size cap** (task 045 / M-1) —
  the six regex patterns compile once via `OnceLock` instead of fresh on
  every `evaluate()` call; install-script content is scanned up to the
  first 1 MB. A 10 MB postinstall can no longer inflate scan time.
- **`verify_hash` lowercases the algorithm prefix** (task 046 / M-2) —
  cached `sha512:<hex>` and registry-served `SHA512-<hex>` now compare
  equal. Closes spurious re-scans driven by registry case inconsistency.
- **Cache I/O errors surface to stderr** (task 047 / M-3) — `cache.lookup`
  errors are no longer silently dropped at the call site; the user sees a
  warning. Fail-open behavior preserved (the scan continues on a
  cache-lookup failure), but tampering of the cache DB is now visible.
- **Maintainer policy: opt-in first-seen warning** (task 048 / M-4) — new
  `maintainer_first_seen_warning` config flag (default `false`, no
  regression). When enabled, packages observed for the first time with
  zero downloads emit a `Warn` to defend against typosquat-from-day-one
  attacks where the attacker is also the first observer.
- **PyPI Simple Index requires correct Content-Type** (task 049 / M-5) —
  responses without `application/vnd.pypi.simple.v1+json` are rejected
  before JSON parsing. A hostile mirror that omits the header and serves
  poisoned-but-valid JSON is no longer accepted.
- **`parse_tlog_entries` reports missing-field errors specifically**
  (task 050 / M-6) — replaces `unwrap_or(0)` fallback with explicit
  `Result<TlogEntry, String>` per-entry, emitting `"missing required
  field: <name>"` diagnostics instead of the misleading
  `"tree_size is zero"`.

### Security (LOW findings, tasks 051–055)

- **Install-script false-positive reduction** (task 051 / L-3 + L-4) — line
  and block comments are stripped before substring matching, so a benign
  `// Function() is the constructor for…` comment no longer trips the
  scanner. The base64-shape detector now requires at least one of `+`, `/`,
  or `=` to actually be present in the match, so pure-hex sequences
  (SHA-256 digests, git SHAs) no longer false-positive.
- **Levenshtein matrix bounded on name length** (task 052 / L-5) — names
  longer than 256 chars short-circuit to "not similar" before any matrix
  allocation.
- **User-visible error output scrubbed by default** (task 053 / L-6) — the
  outer `Error:` line now shows the outermost message only; the full
  anyhow chain (which may include file paths) is gated behind `--verbose`.
- **Cache DB hardened** (task 054 / L-7) — `Cache::new` now `chmod 0600`s
  the SQLite database on Unix (and any future `-wal` / `-shm` companion
  files) and enables `PRAGMA journal_mode = WAL` for durability. Closes
  the privacy-of-usage leak on shared hosts.
- **Sigstore re-verification on install path documented** (task 055 / L-9)
  — `--verbose` now emits an audit log line at the install boundary
  naming the locked version + hash and noting that sigstore is not
  re-verified between scan-pass and `exec`. Source-level comments at each
  install call site record the TOCTOU gap with a link to ADR 003.

### Patched (transitive)

- **`time` 0.3.45 → 0.3.47** — RUSTSEC-2026-0009 (DoS via stack exhaustion
  in time parsing; medium). Pulled in transitively via `x509-parser`
  → `asn1-rs` → `time` after the 058 bump. Patched at the lockfile level.

### Documentation (L-1, L-2, L-8 from the LOW audit, plus quinn confirmation)

- **ADR 003** gained a new section *Notes on sigstore verification mechanics*
  recording the post-chain-walk Fulcio OID check as belt-and-braces, the
  first-URI-SAN-wins identity extraction rule, and the pinned Rekor key
  name pattern.
- **ADR 003** gained a *Build/dependency notes* section confirming the
  HTTP/3 (`quinn`) stack is not linked into the dep-scan release binary —
  re-verified during the v1.2.0 audit pass.

### Security (post-cut hardening, tasks 059–063)

A follow-up security audit on the v1.2.0 prep branch surfaced five new
LOW-severity findings, all fixed before tagging.

- **Cache DB create-then-chmod TOCTOU** (task 059 / N-L-1) —
  `Cache::new` now atomically pre-creates the SQLite file with
  `OpenOptions::new().write(true).create_new(true).mode(0o600)` on Unix
  before handing the path to `Connection::open`. Closes the brief window
  where the file existed as `0644` between `Connection::open` and the
  follow-up `chmod`.
- **Go version-string validation** (task 060 / N-L-2) — version strings
  are validated against printable-ASCII + Go semver/pseudo-version
  grammar (no `/`, `?`, `#`, `%`, `@`, whitespace, CR/LF, no `..`, no
  percent-encoded forms) before any `proxy.golang.org` URL composition.
  Closes a path-confusion primitive that the task-041 module-path
  validator did not cover.
- **Verbose-gated `parse_tlog_entries` diagnostic** (task 061 / N-L-3)
  — the missing-field diagnostic added in task 050 now only emits under
  `--verbose`. The non-verbose error stays generic so registry-served
  attestation shape doesn't leak by default.
- **Single-parse Rekor checkpoint** (task 062 / N-L-4) —
  `verify_ecdsa_p256` now returns `Result<ParsedNote<'_>, NoteVerifyOutcome>`,
  and `verify_rekor_checkpoint_impl` reuses the parsed note instead of
  invoking `signed_note::parse` a second time. Eliminates a benign but
  duplicative parse on the hot path.
- **Empty `note_text` rejection** (task 063 / N-L-5) —
  `signed_note::parse` now returns `Err(NoteError::EmptyText)` when the
  note body is zero bytes, before any signature-iteration loop runs.
  Enforces the structural invariant up front instead of letting the
  empty-text case fall through into signature checks.

### Changed (dependency refreshes, tasks 057–058)

- `rusqlite` 0.31 → 0.39 (8 minor versions), pulling `libsqlite3-sys`
  0.28 → 0.37 (bundled SQLite ~3.45 → ~3.49). All call sites stable; no
  code changes required.
- `x509-parser` 0.16 → 0.18.1, pulling `asn1-rs` 0.6 → 0.7, `der-parser`
  9 → 10, `oid-registry` 0.7 → 0.8. All call sites in `sigstore_verify.rs`
  stable; the Fulcio chain walk and Rekor inclusion proof verifications
  remain byte-identical against the existing test fixtures.
- **Minimum Supported Rust Version (MSRV)** raised from 1.85 to 1.88 to
  accommodate the patched `time` crate's compiler requirement.

### Deferred

- **`reqwest` 0.12 → 0.13** (task 056) — attempted, reverted before cut.
  reqwest 0.13's only stable feature flag that picks a crypto provider is
  `rustls`, which pulls `aws-lc-rs` (a BoringSSL fork with a `cmake`
  build-time dependency). The release workflow's aarch64-linux cross
  build under `cross-rs/cross` would likely fail because the default
  `cross` image does not ship `cmake`. The task file in
  `docs/tasks/backlog/056-bump-reqwest-0-13.md` documents three paths
  to re-attempt this in a future release.

### Stats

- 788 tests passing (up from 534 at v1.1.1 — +254 new tests across the
  20 tasks that landed in this release).
- `cargo clippy --all-targets --all-features -- -D warnings` clean (two
  small lint fixes for clippy 1.95: `manual_is_multiple_of` in the Rekor
  proof verifier, `collapsible_if` in `verify_hash`).
- `cargo audit` clean.

## [1.1.1] — 2026-05-22

### Security

This release bundles the v1.1.0 feature work with six hardening fixes
identified by a post-v1.1.0 security audit. v1.1.0 itself was tagged but
withdrawn before any binaries shipped; users should install v1.1.1 directly.

- **Install command CLI flag injection** (task 037) — package names that
  begin with `-` are now rejected before reaching the wrapped package
  manager. Previously, a token like `--registry=http://attacker` supplied
  as a package name would have been forwarded to `npm install` and
  interpreted as a flag, redirecting the install to a hostile mirror that
  dep-scan never inspected.
- **Cache key now uses the resolved version, not literal "latest"**
  (task 038) — verdicts are stored under `(name, resolved_version)` rather
  than `(name, "latest")`. Closes a replay window where a CDN briefly
  serving the old `dist.integrity` for a republished package could cause
  a stale `pass` verdict to be honored for new bytes.
- **PyPI provenance URL SSRF guard** (task 039) — provenance URLs returned
  by the PyPI Simple Index are now validated to share host with the
  configured registry (or appear in a small compile-time allowlist), to
  be `https://`, and to not resolve to RFC1918 / link-local / loopback
  addresses. Hostile mirrors can no longer redirect provenance fetches to
  internal services or attacker-controlled hosts.
- **SHA-1 content hashes no longer trust-gate the cache for npm**
  (task 040) — npm `dist.shasum` is SHA-1. Cache rows whose content hash
  starts with `sha1:` are now always re-verified (and new `pass`/`warn`
  rows for sha1-only packages store `NULL` instead of the sha1 value).
  Closes the SHAttered chosen-prefix collision window where a republished
  tarball could match the cached hash and skip scanning.
- **Go module path validation** (task 041) — module paths are validated
  against the Go module-path grammar (alphanumerics, `.`, `-`, `_`, `/`;
  no `..` segments; no `?`/`#`/spaces/control chars) before URL
  composition. Closes a path-confusion primitive against Go proxy mirrors.
- **Temp requirements file hardening** (task 042) — `TempReqFile` now uses
  `tempfile::NamedTempFile` (CSPRNG entropy, `O_CREAT|O_EXCL`, mode 0600)
  instead of a `SystemTime`-derived predictable suffix written with the
  default umask. Closes a symlink-race + world-readability gap on
  multi-user hosts.
- Patched four transitive-dependency advisories surfaced by `cargo audit`:
  RUSTSEC-2026-0098, -0099, -0104 (`rustls-webpki`: ignored URI name
  constraints, wildcard escape through name-constraint subtrees, reachable
  panic in CRL parsing during malformed-response handling) and
  RUSTSEC-2026-0097 (`rand`: unsound aliased `&mut` in `ThreadRng` under
  custom logger reseed race). Both crates are reached transitively via
  `reqwest`; the patches are lockfile-only.

### Added (from withdrawn v1.1.0 work, now shipping in v1.1.1)

- Content-hash verification recorded at scan time and re-verified on every
  cache hit, so cached `pass` verdicts cannot be honored for tampered bytes
  (tasks 029, 030).
- `pip install --require-hashes` passthrough — when a Python requirements
  file pins hashes, dep-scan forwards them to pip rather than discarding
  them (task 031).
- npm provenance attestation verification — fetches and verifies the
  in-toto v0.0.2 attestation bundle, extracts `tlog_entries` and the
  signed checkpoint note from npm's registry response (task 032).
- PyPI sigstore attestation verification — fetches the provenance URL
  from the Simple Index response and verifies the bundle (task 033).
- Go `sumdb` signature verification — Ed25519 verification against the
  pinned `sum.golang.org` public key (task 034).
- Full Fulcio root chain verification — walks the certificate chain
  from leaf to root using a pinned trust bundle, with extended-key-usage
  enforcement (task 035).
- Rekor inclusion proof verification — RFC 6962 Merkle inclusion proof
  for transparency log entries (task 036).
- Local `fulcio-roots/` and `rekor-roots/` directories ship the pinned
  trust material with documented refresh procedures.

### Changed

- `Cargo.toml` pins `rust-version = "1.85"` to match the 2024 edition
  features in use. *(Superseded in v1.2.0 — MSRV raised to 1.88 for the
  patched `time` crate.)*
- `tempfile` promoted from dev-dependency to runtime dependency
  (consequence of task 042).

## [1.0.0] — 2026-04-04

First production release. A single binary that scans every dependency
before installation and gates the install on the verdict.

### Added

- Four package registries: **npm**, **PyPI**, **crates.io**,
  **Go modules**.
- Eight detection policies:
  - **Age** — block packages published less than 48h ago
  - **Install scripts** — detect malicious postinstall/preinstall
    scripts (eval, child_process, subprocess)
  - **Obfuscation** — block base64 payloads >60 chars, hex/unicode
    escape chains, `fromCharCode` obfuscation, string concatenation
    building URLs
  - **Typosquatting** — names similar to popular packages
    (e.g. `expresss` vs `express`); 117 popular crates and 124 popular
    Go modules in the lists
  - **Vulnerability** — known CVEs via [OSV.dev](https://osv.dev),
    no API key required
  - **Maintainer change** — track added/removed maintainers, full
    takeover detection
  - **Dependency confusion** — internal-looking names on public
    registries
  - **Popularity** — warn on packages with <1000 downloads
    (configurable)
- **Lockfile parsing**: `package-lock.json`, `requirements.txt`,
  `Cargo.lock`, `go.sum`.
- **Install command**: `dep-scan install <pkg> --registry <name>` scans,
  then invokes the native package manager on pass.
- **CI/CD ready**: `--json` output, exit codes (0 = pass, 1 = violation,
  2 = error).
- `.dep-scan.toml` configuration with environment-variable overrides.
- Local SQLite cache for scan results and maintainer history.
- 262 tests, clippy clean, single ~8.5 MB binary, no runtime dependencies.

### Distribution

- Pre-built binaries on GitHub Releases for linux gnu (x86_64, aarch64),
  darwin (x86_64, aarch64), and windows msvc (x86_64), each accompanied
  by a `sha256sums.txt`.
- Install script: `curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash`

[Unreleased]: https://github.com/tkdtaylor/dep-scan/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/tkdtaylor/dep-scan/releases/tag/v1.2.0
[1.1.1]: https://github.com/tkdtaylor/dep-scan/releases/tag/v1.1.1
[1.0.0]: https://github.com/tkdtaylor/dep-scan/releases/tag/v1.0.0

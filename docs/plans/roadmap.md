# Roadmap

**Project:** dep-scan
**Last updated:** 2026-05-22

## Completed milestones

### v0.1 — Foundation (2026-04-02)

- [x] Project setup and tooling (Rust, ADR 001)
- [x] Core CLI skeleton with subcommands (check, install, config)
- [x] Registry API clients (npm, PyPI) for package metadata
- [x] Minimum package age check (configurable, default 48h)
- [x] Local hash cache (SQLite)

### v0.2 — Core detection (2026-04-02)

- [x] Install script analysis (postinstall, setup.py)
- [x] Typosquatting detection (edit distance against popular packages)
- [x] Maintainer/ownership change detection
- [x] Known vulnerability check (OSV.dev)
- [x] Dependency confusion heuristics

### v0.3 — Expanded ecosystem (2026-04-04)

- [x] crates.io and Go module support
- [x] Popularity/download threshold warnings
- [x] Configurable policy file (.dep-scan.toml)
- [x] Obfuscation detection (base64, hex-encoded URLs, env var exfiltration patterns)

### v1.0 — Production ready (2026-04-04)

- [x] Lockfile parsing (package-lock.json, requirements.txt, Cargo.lock, go.sum)
- [x] Install subcommand wrapping all four package managers
- [x] GitHub Actions CI/CD (automated testing + cross-platform releases)
- [x] Install script for easy binary distribution
- [x] Documentation and installation guide

### v1.1.0 — Cache integrity + sigstore provenance (superseded by v1.1.1)

v1.1.0 was tagged but withdrawn before binaries shipped. Its feature work
shipped in v1.1.1. See [CHANGELOG § 1.1.1](../../CHANGELOG.md).

- [x] Content-hash verification at scan time, re-verified on every cache hit (tasks 029, 030)
- [x] `pip install --require-hashes` passthrough for pinned Python requirements (task 031)
- [x] npm sigstore provenance attestation verification — in-toto bundle + Rekor tlog_entries (task 032)
- [x] PyPI sigstore attestation verification — provenance URL from Simple Index (task 033)
- [x] Go `sumdb` Ed25519 signature verification against pinned `sum.golang.org` key (task 034)
- [x] Full Fulcio root chain walk with extended-key-usage enforcement (task 035)
- [x] Rekor RFC 6962 Merkle inclusion proof verification (task 036)
- [x] Pinned `fulcio-roots/` and `rekor-roots/` trust material shipped with the binary

### v1.1.1 — HIGH security audit fixes (2026-05-22)

Bundled the v1.1.0 feature work with six HIGH-severity findings from a
post-v1.1.0 security audit. See [CHANGELOG § 1.1.1](../../CHANGELOG.md).

- [x] CLI flag-injection guard — package names beginning with `-` are rejected (task 037)
- [x] Cache key uses resolved version, not literal "latest" (task 038)
- [x] PyPI provenance URL SSRF guard — URL validated against configured registry host (task 039)
- [x] npm SHA-1 hashes no longer gate the cache (task 040)
- [x] Go module path validation against Go grammar before URL composition (task 041)
- [x] Temp requirements file uses `tempfile::NamedTempFile` with CSPRNG + `O_EXCL` + mode 0600 (task 042)
- [x] Four transitive-dependency advisories patched (rustls-webpki, rand)

### v1.2.0 — MEDIUM/LOW security fixes + post-cut hardening (2026-05-22)

Maintenance release landing MEDIUM and LOW findings from the v1.1.0 audit,
two transitive-dependency refreshes, and five additional LOW findings caught
during the v1.2.0 prep audit. See [CHANGELOG § 1.2.0](../../CHANGELOG.md).

**MEDIUM findings (tasks 043–050):**
- [x] Signed-note verifier iterates across multiple signature lines (task 043)
- [x] Signed-note boundary parser uses em-dash walk (task 044)
- [x] Obfuscation policy: regex cache + 1 MB script size cap (task 045)
- [x] `verify_hash` normalises algorithm prefix to lowercase (task 046)
- [x] Cache I/O errors surface to stderr instead of silently swallowed (task 047)
- [x] Maintainer first-seen warning behind opt-in config flag (task 048)
- [x] PyPI Simple Index rejects responses without correct Content-Type (task 049)
- [x] `parse_tlog_entries` reports specific missing-field errors (task 050)

**LOW findings (tasks 051–055):**
- [x] Install-script false-positive reduction: strip comments, tighten base64 shape (task 051)
- [x] Levenshtein matrix bounded to 256-char names (task 052)
- [x] User-visible error output scrubbed to outermost message by default (task 053)
- [x] Cache DB hardened: `chmod 0600` + WAL journal mode (task 054)
- [x] Sigstore TOCTOU gap documented at install boundary (task 055)

**Post-cut hardening (tasks 059–063):**
- [x] Cache DB create-then-chmod TOCTOU closed via atomic `O_CREAT|O_EXCL` (task 059)
- [x] Go version-string validation before proxy URL composition (task 060)
- [x] Verbose-gate on tlog diagnostic to avoid attestation shape leakage (task 061)
- [x] Single-parse Rekor checkpoint (eliminates duplicate parse) (task 062)
- [x] Empty note-text rejected before signature iteration (task 063)

**Dependency refreshes:**
- [x] `rusqlite` 0.31 → 0.39 (tasks 057)
- [x] `x509-parser` 0.16 → 0.18.1 (task 058)
- Deferred: `reqwest` 0.12 → 0.13 (task 056) — blocked on cross-compile cmake requirement

---

## Backlog

Unscheduled work lives in [`tasks/backlog/`](../tasks/backlog/). Items get promoted to a milestone when prioritized.

### Future ideas

- Homebrew / AUR / other package manager distribution
- Lock file auto-detection from project root
- `dep-scan watch` — continuous monitoring mode
- Semgrep integration for deep install script analysis
- NVD / CISA KEV / EPSS enrichment for vulnerability severity scoring
- Bloom filter database for offline package existence checks

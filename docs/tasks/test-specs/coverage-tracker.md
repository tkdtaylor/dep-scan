# Test Coverage Tracker

**Project:** dep-scan

## Rules

- Test specs are written **before** implementation begins — no exceptions
- A task is only "complete" when all its test cases pass
- Each row maps a task ID to its spec file and current test status
- Task 001 (`cargo init` scaffold) is a pre-spec bootstrap exception — the
  scaffold produces no behavior to assert against. Every task from 002 onward
  has a paired spec.

## Coverage

| Task ID | Feature | Spec file | Tests written | Status |
|---------|---------|-----------|---------------|--------|
| 001 | `cargo init` scaffold | _(bootstrap — pre-spec exception)_ | n/a | ✅ |
| 002 | CLI skeleton with clap | 002-cli-skeleton-test-spec.md | 11/11 | Done |
| 003 | Configuration system | 003-config-system-test-spec.md | 10/10 | Done |
| 004 | Package metadata types + registry trait | 004-types-and-registry-trait-test-spec.md | 6/6 | Done |
| 005 | npm registry client | 005-npm-registry-client-test-spec.md | 8/8 | Done |
| 006 | PyPI registry client | 006-pypi-registry-client-test-spec.md | 12/12 | Done |
| 007 | SQLite hash cache | 007-sqlite-cache-test-spec.md | 10/10 | Done |
| 008 | Minimum package age policy | 008-age-policy-test-spec.md | 7/7 | Done |
| 009 | Check subcommand integration | 009-check-integration-test-spec.md | 8/8 | Done |
| 010 | ScanContext + multi-policy pipeline | 010-multi-policy-pipeline-test-spec.md | 11/11 | Done |
| 011 | OSV.dev vulnerability client + policy | 011-osv-vulnerability-test-spec.md | 10/10 | Done |
| 012 | Install script extraction + analysis | 012-install-script-analysis-test-spec.md | 10/10 | Done |
| 013 | Typosquatting detection | 013-typosquatting-test-spec.md | 13/13 | Done |
| 014 | Maintainer change detection | 014-maintainer-change-test-spec.md | 9/9 | Done |
| 015 | Dependency confusion heuristics | 015-dependency-confusion-test-spec.md | 7/7 | Done |
| 016 | v0.2 integration tests | 016-v2-integration-test-spec.md | 7/7 | Done |
| 017 | RegistryType expansion + config | 017-registry-type-expansion-test-spec.md | 7/7 | Done |
| 018 | crates.io registry client | 018-crates-registry-test-spec.md | 8/8 | Done |
| 019 | Go module proxy client | 019-go-module-registry-test-spec.md | 7/7 | Done |
| 020 | Popular package lists for crates.io + Go | 020-popular-crates-go-test-spec.md | 7/7 | Done |
| 021 | Obfuscation detection policy | 021-obfuscation-detection-test-spec.md | 11/11 | Done |
| 022 | Popularity policy + v0.3 integration tests | 022-popularity-integration-test-spec.md | 8/8 | Done |
| 023 | Lockfile parser | 023-lockfile-parser-test-spec.md | 10/10 | Done |
| 024 | Install subcommand | 024-install-subcommand-test-spec.md | 6/6 | Done |
| 025 | GitHub Actions CI workflow | 025-ci-workflow-test-spec.md | ✅ | Done |
| 026 | GitHub Actions release workflow | 026-release-workflow-test-spec.md | ✅ | Done |
| 027 | Install script | 027-install-script-test-spec.md | ✅ | Done |
| 028 | v1.0 polish and release | 028-v1-polish-test-spec.md | ✅ | Done |
| 029 | Capture content hash in scan cache | 029-content-hash-capture-test-spec.md | 16/16 | ✅ |
| 030 | Verify content hash on cache hit | 030-content-hash-verify-test-spec.md | 13/13 | ✅ |
| 031 | Pip --require-hashes passthrough | 031-pip-require-hashes-passthrough-test-spec.md | 13/13 | ✅ |
| 032 | npm provenance attestation verification | 032-npm-provenance-verification-test-spec.md | 21/21 | ✅ |
| 033 | PyPI sigstore attestation verification (PEP 740) | 033-pypi-provenance-verification-test-spec.md | 22/22 | ✅ |
| 034 | Go checksum database signature verification | 034-go-sumdb-cross-check-test-spec.md | 22/22 | ✅ |
| 035 | Full Fulcio root chain verification | 035-fulcio-chain-walk-test-spec.md | 19/19 | ✅ |
| 036 | Rekor inclusion proof verification | 036-rekor-inclusion-proof-test-spec.md | 28/28 | ✅ |
| 037 | Install command CLI flag injection hardening | 037-install-flag-injection-test-spec.md | 18/18 | ✅ |
| 038 | Use resolved version as cache key instead of "latest" | 038-cache-resolved-version-key-test-spec.md | 13/13 | ✅ |
| 039 | PyPI provenance URL SSRF hardening | 039-pypi-provenance-url-ssrf-test-spec.md | 17/17 | ✅ |
| 040 | Reject SHA-1 content hashes as cache trust gates for npm | 040-npm-sha1-cache-bypass-test-spec.md | 14/14 | ✅ |
| 041 | Go module path validation before URL composition | 041-go-module-path-validation-test-spec.md | 26/26 | ✅ |
| 042 | Harden TempReqFile against predictable filename / symlink attack | 042-temp-file-symlink-hardening-test-spec.md | 14/14 | ✅ |
| 043 | Signed-note multi-signature iteration for key rotation | 043-signed-note-multi-sig-iteration-test-spec.md | 15/15 | ✅ |
| 044 | Signed-note boundary parser — em-dash walk replaces rfind | 044-signed-note-boundary-parser-test-spec.md | 17/17 | ✅ |
| 045 | Obfuscation policy — compile regexes once and cap script size | 045-obfuscation-regex-cache-script-cap-test-spec.md | 14/14 | ✅ |
| 046 | verify_hash algorithm-prefix case normalization | 046-verify-hash-case-normalization-test-spec.md | 16/16 | ✅ |
| 047 | Cache I/O error surfacing | 047-cache-io-error-surfacing-test-spec.md | 12/12 | ✅ |
| 048 | Maintainer policy trust-on-first-use warning | 048-maintainer-first-seen-warning-test-spec.md | 14/14 | ✅ |
| 049 | PyPI Simple Index strict content-type enforcement | 049-pypi-simple-index-content-type-test-spec.md | 16/16 | ✅ |
| 050 | parse_tlog_entries missing-field diagnostics | 050-tlog-entry-missing-field-diagnostics-test-spec.md | 17/17 | ✅ |

| 051 | Install-script false-positive reduction (L-3 + L-4) | 051-install-script-false-positive-reduction-test-spec.md | 19/19 | ✅ |
| 052 | Bound Levenshtein matrix on package-name length (L-5) | 052-levenshtein-length-bound-test-spec.md | 13/13 | ✅ |
| 053 | Scrub user-visible error output (L-6) | 053-error-output-scrubbing-test-spec.md | 9/9 | ✅ |
| 054 | Cache DB privacy hardening (L-7) | 054-cache-db-privacy-hardening-test-spec.md | 13/13 | ✅ |
| 055 | Sigstore re-verification on install path (L-9) | 055-sigstore-install-path-audit-test-spec.md | 11/11 | ✅ |
| 056 | Bump reqwest 0.12 → 0.13 | 056-bump-reqwest-0-13-test-spec.md | 0/12 | ⚠️ deferred — see backlog/056 |
| 057 | Bump rusqlite 0.31 → 0.39 | 057-bump-rusqlite-0-39-test-spec.md | 18/18 | ✅ |
| 058 | Bump x509-parser 0.16 → 0.18 | 058-bump-x509-parser-0-18-test-spec.md | 18/18 | ✅ |
| 059 | Close cache DB create-then-chmod TOCTOU (N-L-1) | 059-cache-create-toctou-test-spec.md | 15/15 | ✅ |
| 060 | Validate Go version strings before URL composition (N-L-2) | 060-go-version-string-validation-test-spec.md | 31/31 | ✅ |
| 061 | Verbose-gate parse_tlog_entries malformed-entry diagnostic (N-L-3) | 061-tlog-diagnostic-verbose-gate-test-spec.md | 14/14 | ✅ |
| 062 | Single-parse refactor for verify_rekor_checkpoint_impl (N-L-4) | 062-single-parse-rekor-checkpoint-test-spec.md | 16/16 | ✅ |
| 063 | Reject empty note_text in signed_note::parse (N-L-5) | 063-signed-note-empty-text-rejection-test-spec.md | 13/13 | ✅ |
| 064 | Add `cargo audit` step to CI | 064-cargo-audit-in-ci-test-spec.md | 8/8 | ✅ |
| 065 | Multi-OS test matrix in CI | 065-multi-os-ci-matrix-test-spec.md | 8/8 | ✅ |
| 066 | Pin MSRV (1.88) in CI test job | 066-msrv-pin-in-ci-test-spec.md | 8/8 | ✅ |
| 067 | Dog-food — dep-scan scans its own `Cargo.lock` in CI | 067-dogfood-own-cargo-lock-test-spec.md | 10/10 | ✅ |
| 068 | Sign release artifacts with cosign / sigstore | 068-sign-releases-with-cosign-test-spec.md | 0/10 | ❌ |
| 069 | Generate CycloneDX SBOM per release | 069-cyclonedx-sbom-per-release-test-spec.md | 0/8 | ❌ |
| 070 | Add `SECURITY.md` | 070-security-md-test-spec.md | 10/10 | ✅ |
| 071 | Add `RELEASE_CHECKLIST.md` | 071-release-checklist-test-spec.md | 0/10 | ❌ |
| 072 | Refresh `roadmap.md` through v1.2.0 | 072-roadmap-refresh-through-v1-2-test-spec.md | 0/7 | ❌ |
| 073 | Remove (or relocate) scaffold leftovers | 073-remove-scaffold-leftovers-test-spec.md | 8/8 | ✅ |
| 074 | Ship `shims/` directory with installable wrapper scripts | 074-shims-directory-test-spec.md | 0/12 | ❌ |
| 075 | Add `examples/` directory | 075-examples-directory-test-spec.md | 0/13 | ❌ |
| 076 | Add `CONTRIBUTING.md` | 076-contributing-md-test-spec.md | 0/10 | ❌ |
| 077 | Add `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1) | 077-code-of-conduct-test-spec.md | 0/8 | ❌ |
| 078 | Lockfile scanner uses pinned versions, not registry "latest" | 078-lockfile-pinned-version-propagation-test-spec.md | 18/18 | ✅ |
| 079 | Dogfood allowlist mechanism for justified block verdicts | 079-dogfood-allowlist-mechanism-test-spec.md | 19/19 | ✅ |
| 080 | Fix typosquat false-positive on `version_check` | 080-fix-version-check-typosquat-false-positive-test-spec.md | 9/9 | ✅ |
| 081 | Investigate `getrandom` maintainer changes | 081-getrandom-maintainer-investigation-test-spec.md | 12/15 | ✅ (BENIGN — T-081-11..13 N/A on BENIGN path; T-081-14 satisfied by follow-up task 082) |
| 082 | Recognise crates.io `trustpub_data` (false-positive fix surfaced by 081) | 082-recognise-trustpub-data-in-crates-registry-test-spec.md | 8/8 (T-082-09 validated by allowlist removal; T-082-10 by tooling gate) | 🟡 Verified by: L3: cargo test 7 new T-082 tests pass + clippy/fmt clean |

## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ | Done |
| ⏳ | In progress |
| ❌ | Not started |
| ⚠️ | Blocked |

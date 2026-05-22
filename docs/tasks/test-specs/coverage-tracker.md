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
| 045 | Obfuscation policy — compile regexes once and cap script size | 045-obfuscation-regex-cache-script-cap-test-spec.md | 0/14 | ❌ |
| 046 | verify_hash algorithm-prefix case normalization | 046-verify-hash-case-normalization-test-spec.md | 0/16 | ❌ |
| 047 | Cache I/O error surfacing | 047-cache-io-error-surfacing-test-spec.md | 0/12 | ❌ |
| 048 | Maintainer policy trust-on-first-use warning | 048-maintainer-first-seen-warning-test-spec.md | 0/14 | ❌ |
| 049 | PyPI Simple Index strict content-type enforcement | 049-pypi-simple-index-content-type-test-spec.md | 0/16 | ❌ |
| 050 | parse_tlog_entries missing-field diagnostics | 050-tlog-entry-missing-field-diagnostics-test-spec.md | 0/17 | ❌ |

## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ | Done |
| ⏳ | In progress |
| ❌ | Not started |
| ⚠️ | Blocked |

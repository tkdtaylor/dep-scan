# Fitness functions

**Status:** Authoritative — code MUST conform.
**Last updated:** 2026-07-12 (F-028: cached-verdict attribution, task 112)

A **fitness function** is a security invariant that the codebase MUST
maintain across releases. Most rows below are a contract pinned by at
least one paired test case (the `T-NNN-NN` markers in
`docs/tasks/test-specs/`), so a green `cargo test` suite is the running
proof that they hold. Two rows are gated differently and are flagged as
such in the table: **F-010** (no hardcoded registry URLs) is a source-grep
gate enforced at code review, and **F-027** (policy-count completeness, a
`warn` rule) is verified by the manual drift audit. Everything else is
`cargo test`–automated.

This is the "things that must never silently regress" list. If a test
that pins an F-row breaks, the right next step is to investigate
whether the invariant was deliberately changed (update the spec) or
silently broken (fix the code) — **never** to delete the test.

## Rules

| ID | Rule | Severity | Origin task | Verified by |
|----|------|----------|-------------|-------------|
| **F-001** | Package-name tokens beginning with `-` MUST be rejected before any subprocess invocation, on **every** subcommand that takes package names | block | 037 | T-037-* tests in `src/validation.rs` and CLI integration tests |
| **F-002** | Content-hash verification MUST run on every cache hit. `--force` MUST NOT bypass it. There is no flag to skip it. | block | 030 | T-030-* in `tests/hash_verify_integration.rs` + `src/main.rs` |
| **F-003** | Go module paths MUST pass grammar validation **before** URL composition (no `..`, no `?`/`#`/spaces, etc.) | block | 041 | T-041-* in `tests/go_module_path_validation_integration.rs` + `src/registry/go.rs::validate_go_module_path` |
| **F-004** | Go version strings MUST pass grammar validation **before** URL composition (printable ASCII, no `/?#%@\r\n`, no `..`, no percent-encoded) | block | 060 | T-060-* in `src/registry/go.rs::validate_go_version` |
| **F-005** | The pip `--require-hashes` temp file MUST be created via `tempfile::NamedTempFile` (CSPRNG suffix, `O_CREAT\|O_EXCL`, mode 0600) — no `SystemTime`-derived predictable suffix | block | 042 | T-042-* in `tests/temp_file_hardening_integration.rs` + `src/main.rs` |
| **F-006** | The PyPI provenance URL MUST pass scheme/host/IP-class validation before fetch. RFC1918 / link-local / loopback / multicast IPs MUST be rejected. | block | 039 | T-039-* in `src/registry/pypi_provenance.rs` |
| **F-007** | SHA-1 (`sha1:*`) content hashes MUST NOT trust-gate the cache. Cached `sha1:` rows MUST re-scan unconditionally; new `pass`/`warn` rows for sha1-only packages MUST store `NULL` instead of the sha1 value. | block | 040 | T-040-* in `tests/npm_sha1_cache_bypass_integration.rs` + `src/main.rs` + `src/registry/npm.rs` |
| **F-008** | The both-`None` cache state (cached_hash = None AND registry_hash = None) MUST re-scan. Never honor. | block | 030 | T-030-13 in `tests/hash_verify_integration.rs` |
| **F-009** | The cache key MUST be `(name, resolved_version, registry)`. The literal string `"latest"` MUST NOT appear as a cached version. | block | 038 | T-038-* in `tests/cache_version_key_integration.rs` + `tests/hash_verify_integration.rs` |
| **F-010** | Registry URLs MUST be configurable. Hardcoding a registry URL in source is forbidden. | block | (CLAUDE.md) | code review — grep for `https://registry.npmjs.org` etc. outside `default_*_url()` helpers |
| **F-011** | `parse_tlog_entries` malformed-entry diagnostics MUST be gated behind `--verbose`. The default error MUST stay generic so registry-served attestation shape doesn't leak. | block | 061 | T-061-* in `tests/tlog_diagnostic_verbose_gate_integration.rs` + `src/registry/npm_attestation.rs` |
| **F-012** | PyPI Simple Index responses MUST have Content-Type `application/vnd.pypi.simple.v1+json`. Anything else MUST be rejected before JSON parsing. | block | 049 | T-049-* in `tests/pypi_provenance_integration.rs` + `src/registry/pypi_provenance.rs` |
| **F-013** | Sigstore / sumdb trust roots MUST be pinned at build time. No runtime download of trust material. Rotation requires a dep-scan release. | block | 035 / 034 | T-035-* and T-034-* — chain-walk tests in `src/sigstore_verify.rs`, sumdb fixtures in `tests/go_sumdb_integration.rs`, embedded files in `fulcio-roots/`, `rekor-roots/`, `src/policy/go_sumdb.rs::SUMDB_PUBLIC_KEY_STR` |
| **F-014** | `signed_note::parse` MUST return `Err` with an `"empty note_text"` message when the note body is zero bytes — *before* any signature-iteration loop runs. The error type is `String`, not an enum. | block | 063 | T-063-* in `src/signed_note.rs` |
| **F-015** | `verify_ecdsa_p256` MUST return `Result<ParsedNote<'_>, NoteVerifyOutcome>`; `verify_rekor_checkpoint_impl` MUST consume that parsed note rather than calling `signed_note::parse` a second time. | block | 062 | T-062-* in `src/signed_note.rs` + `src/sigstore_verify.rs` |
| **F-016** | Signed-note verifiers MUST iterate across all signature lines for key rotation. A non-matching `key_id` MUST `continue` to the next line, not return `Invalid` immediately. | block | 043 | T-043-* in `src/signed_note.rs` |
| **F-017** | The signed-note boundary parser MUST use a single-pass em-dash walk, not `rfind("\n\n")`. Robust against blank lines inside the note body. | block | 044 | T-044-* in `src/signed_note.rs` + `src/sigstore_verify.rs` (T-044-14 = `verify_rekor_checkpoint` no-rfind guard) |
| **F-018** | Cache DB file (Unix) MUST be created atomically with mode `0600`. No window where the file exists as `0644`. | block | 059 | T-059-* in `src/cache.rs` |
| **F-019** | Cache DB SQLite mode MUST be WAL (`PRAGMA journal_mode = WAL`). Companion `-wal` / `-shm` files inherit the same `0600` mode. | block | 054 | T-054-* in `tests/cache_privacy_hardening_integration.rs` + `src/cache.rs` |
| **F-020** | Levenshtein matrix MUST short-circuit on names longer than 256 chars. Adversarial 100KB names MUST NOT allocate the matrix. | block | 052 | T-052-* in `src/typosquat.rs` length-bound tests |
| **F-021** | Obfuscation regex patterns MUST compile once via `OnceLock`. Install-script scan MUST be capped at the first 1 MB. | block | 045 | T-045-* in `src/policy/obfuscation.rs` cache + cap tests |
| **F-022** | `verify_hash` MUST be case-insensitive on the algorithm prefix. `sha512:…` and `SHA512-…` MUST compare equal. | block | 046 | T-046-* in `tests/hash_verify_integration.rs` + `src/main.rs::verify_hash` |
| **F-023** | Cache I/O errors MUST surface to stderr. Silent error swallowing is forbidden. Fail-open behavior preserved. | block | 047 | T-047-* in `tests/cache_io_error_surfacing_integration.rs` + `tests/cache_privacy_hardening_integration.rs` + `tests/error_output_scrubbing_integration.rs` |
| **F-024** | Install-script policy MUST strip line/block comments before pattern matching. The base64-shape detector MUST require at least one of `+`, `/`, `=`. | block | 051 | T-051-* (`src/policy/install_script.rs` false-positive tests) |
| **F-025** | User-visible error output MUST scrub the anyhow chain by default. The full chain is gated behind `--verbose`. | warn | 053 | T-053-* (`tests/error_output_scrubbing_integration.rs`) |
| **F-026** | The verbose audit log line at the install boundary MUST name the locked version + hash and MUST note that sigstore is not re-verified between scan-pass and `exec` (except for pip via `--require-hashes`). | warn | 055 | T-055-* (`tests/sigstore_install_path_audit_integration.rs`) |
| **F-027** | The twelve policies (eleven registry policies + `mutable_ref`; `vcs_host` is a function-based gate, not a `Policy` impl) are the complete set. Adding or removing a policy requires updating `policies.md`, the README policy table, and the overview's "Twelve policies in total" count in the same PR. | warn | (CLAUDE.md "Common rationalizations") | Manual drift audit (the cp-fix-drift / project-audit number-citation layer) |
| **F-028** | A cached verdict MUST NOT be served without full attribution (real resolved version, per-policy `policies` array, the dep-scan version that produced it). A row missing `dep_scan_version`, missing/unparseable `policies_json`, or whose re-aggregated policies disagree with the stored `result`, MUST be treated as a miss and re-scanned, never served. | block | 112 | T-112-09..13 in `tests/cache_attribution_integration.rs` + `src/main.rs::attributed_cache_hit` |

## Severity meanings

| Severity | Meaning |
|----------|---------|
| **block** | A regression here is a security defect. Cannot ship a release with a broken `block`-severity fitness function. |
| **warn** | A regression degrades user experience or developer ergonomics but does not introduce a security defect. Should be fixed before a release but is not a hard blocker. |

## Adding a fitness function

1. The new F-row MUST cite the originating task ID (where the test was
   written) and at least one paired `T-NNN-*` marker.
2. The invariant SHOULD be pinned by a `cargo test` case — prefer
   automation: if it can be expressed as a test, it MUST be. The two
   exceptions already in the table (F-010, a source-grep gate; F-027, a
   `warn`-severity count verified by the drift audit) are the documented
   limit; a new manual gate needs an explicit justification for why it
   cannot be automated.
3. The row MUST be added in the same PR that introduces the
   corresponding code change.

## How fitness functions relate to other docs

- **ADR 003** — gives the rationale for *why* most of these invariants
  exist.
- **`policies.md` / `cache.md` / `sigstore-verification.md`** — describe
  the contracts that, when violated, would trip one of these tests.
- **`docs/tasks/test-specs/`** — the source of truth for the
  `T-NNN-*` markers cited above.

If a contract in `policies.md` is enforced by an F-row here, the F-row
links back to that contract by name, not by line number — line numbers
will drift, names will not.

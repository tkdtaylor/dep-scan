# Task 055 — Sigstore re-verification on install path (L-9)

**Status:** backlog
**Depends on:** 024 (install subcommand), 031 (pip require-hashes), 032 (npm
provenance), 033 (PyPI provenance), 034 (go sumdb)
**Security finding:** L-9 (LOW — TOCTOU gap acknowledged in ADR 003)
**Touches:** `src/main.rs` (`run_install`, `run_pip_install`)

## Objective

Investigate what each `run_*_install` code path re-checks after `run_check`
returns, document the findings, and make the TOCTOU gap visible — either by
adding a verbose log line that names the locked version and content hash (option b,
preferred for this LOW finding) or by adding sigstore re-verification (option a,
higher effort).

## Background

ADR 003 documents the TOCTOU gap as accepted: the scan happens before the package
manager is invoked; an attacker who can modify the registry between scan and install
could substitute a different payload.  The security audit (L-9) asked us to verify
the actual behavior of the install path and ensure the gap is at least visible.

### Current behavior (as of v1.1.1)

- **npm / cargo / go:** `run_install` calls `run_check` once.  After the scan
  passes, it invokes `npm install <name>`, `cargo add <name>`, or `go get <path>`.
  The package manager re-resolves the version and downloads the tarball
  independently.  No content hash or sigstore provenance is re-checked.
- **PyPI:** `run_pip_install` re-fetches metadata from PyPI after the scan to
  build a `--require-hashes` requirements file (task 031).  The sha256 content
  hash is re-confirmed, but sigstore provenance is NOT re-run.

### Chosen remediation — option (b): log the locked version + hash

The HIGH and MEDIUM findings are already addressed.  For this LOW finding, the
preferred remediation is to add a `--verbose` log line at the start of the install
step that names:
- The resolved version (from the scan's metadata fetch)
- The content hash that was observed during the scan
- A note that sigstore provenance is not re-verified at install time

This makes the gap visible to operators running dep-scan in verbose mode without
adding extra network round trips.

If the implementer determines that option (a) — full sigstore re-verification —
is feasible without significant complexity, they may implement it instead.  The
test spec covers both outcomes; the implementer must document their choice in a
source comment at the call site and update the coverage-tracker row to indicate
which T-055-05 / T-055-06 tests apply.

## Requirements

- **REQ-055-01:** For npm/cargo/go, `run_install` emits a verbose log line before
  invoking the package manager that names the resolved version and content hash
  from the scan.
- **REQ-055-02:** For PyPI, `run_pip_install` emits a verbose log line noting that
  the sha256 hash was re-confirmed but sigstore provenance was not re-run.
- **REQ-055-03:** The log lines appear only when `--verbose` is passed.
- **REQ-055-04:** A source comment at the call site of each package manager
  invocation documents whether sigstore is re-verified (option a) or not (option b).
- **REQ-055-05:** All existing task 024 and 031 tests continue to pass.

## Acceptance criteria

- [ ] npm install verbose output contains the resolved version and hash prefix
  (REQ-055-01); verified by T-055-01.
- [ ] cargo install verbose output contains the resolved version (REQ-055-02);
  verified by T-055-02.
- [ ] go install verbose output contains the resolved version (REQ-055-02);
  verified by T-055-03.
- [ ] PyPI install verbose output names the hash-re-verification and notes
  sigstore gap (REQ-055-02); verified by T-055-04.
- [ ] Log line is suppressed without `--verbose` (REQ-055-03); verified by T-055-08.
- [ ] Source comment documents the option chosen (REQ-055-04).
- [ ] Task 024 and 031 regression suites pass (REQ-055-05); verified by
  T-055-09, T-055-10.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` pass.

## Out of scope

- Pinning the package manager invocation to a specific version string
  (`express@4.18.2` instead of `express`) — this changes the user-facing behavior
  and requires a separate design decision.
- Full sigstore re-verification at install time — only required if the implementer
  chooses option (a).

## Risk notes

- The cached metadata from `run_check` may not be directly accessible in
  `run_install` without an additional fetch.  The simplest approach is to return
  the resolved version + hash from `run_check` (or read them from the cache after
  the scan) rather than making an additional network call.
- For cargo and go, the content hash may not be stored in the cache if the package
  was not previously scanned (e.g. first run); the log line should gracefully handle
  `None` content hashes.

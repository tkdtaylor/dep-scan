# Test Spec — Task 055: Sigstore re-verification on install path (L-9)

## Context

`run_install` in `src/main.rs` delegates the scan to `run_check` and then, if
the scan passes, invokes the underlying package manager.  ADR 003 documents the
TOCTOU gap between scan and install as accepted, but the security audit (L-9)
asked us to verify what each `run_*_install` path actually re-checks after the
scan returns, and to make the gap visible — either by adding sigstore
re-verification or by logging the version + hash that was locked during the scan.

**Finding (from code audit):** `run_install` calls `run_check` once, which fetches
metadata, runs the policy pipeline (including sigstore provenance where configured),
caches the result, and returns an exit code.  After `run_check` returns:
- **npm / cargo / go:** `run_install` immediately invokes the package manager
  (`npm install`, `cargo add`, `go get`) with the original package name.  No hash,
  version, or sigstore re-check is performed.  The package manager resolves and
  downloads the package independently.
- **PyPI:** `run_pip_install` re-fetches metadata and builds a `--require-hashes`
  requirements file (task 031).  The content hash is re-verified, but sigstore
  provenance is NOT re-verified (only the sha256 digest is re-confirmed).

The chosen remediation for this task is **option (b)** — log the locked version
and content hash at the start of the install step so the gap is visible — rather
than adding full sigstore re-verification (which would double the network round
trips and is out of scope for a LOW finding).

The test spec accommodates both outcomes: if the implementer chooses to add
sigstore re-verification (option a), the additional assertions in this spec must
pass.  If the implementer chooses option (b), the log-line assertions must pass.

---

## Unit tests — install-path audit (option b: log-line approach)

### T-055-01: `run_install` for npm emits a log line naming the version and hash before invoking npm
- Arrange: wiremock serves npm metadata for `"express@4.18.2"` with
  `dist.integrity = "sha512-AAAA..."`.
- Run `dep-scan install express --registry npm --verbose`.
- Expected: stderr contains a line matching
  `"installing express@4.18.2 (sha512:… — sigstore not re-verified at install time)"` or
  an equivalent message that names the resolved version, the hash, and the absence
  of sigstore re-verification.
- Note: the exact wording is up to the implementer; the spec asserts the presence
  of the version string and hash prefix in the output, not the exact phrase.

### T-055-02: `run_install` for cargo emits a log line naming the version and hash
- Arrange: wiremock serves crates.io metadata for `"serde@1.0.210"`.
- Run `dep-scan install serde --registry cargo --verbose`.
- Expected: stderr contains the resolved version `"1.0.210"` and a hash reference
  before the cargo invocation.

### T-055-03: `run_install` for go emits a log line naming the version
- Arrange: wiremock serves Go proxy metadata for `"github.com/gin-gonic/gin@v1.9.1"`.
- Run `dep-scan install github.com/gin-gonic/gin --registry go --verbose`.
- Expected: stderr contains the resolved version `"v1.9.1"` before the go invocation.

### T-055-04: `run_pip_install` log line documents that sha256 is re-verified but sigstore is not
- Arrange: wiremock serves PyPI metadata with `sha256:beef…` for `"flask@3.0.0"`.
- Run `dep-scan install flask --registry pypi --verbose`.
- Expected: stderr contains a message indicating the sha256 hash was re-confirmed
  and that sigstore provenance was not re-run at install time.

---

## Unit tests — install-path audit (option a: sigstore re-verification)

These tests apply only if the implementer chooses to add sigstore re-verification.
If option (b) is chosen, these tests are marked N/A in the coverage tracker.

### T-055-05 (option a only): `run_install` for npm re-runs sigstore provenance check
- Arrange: wiremock serves npm provenance attestation alongside metadata.
- Run `dep-scan install express --registry npm`.
- Expected: the sigstore verification path (`extract_provenance_identity`) is
  invoked a second time during the install step, not only during `run_check`.
- Verified by: spy/mock on `RealSigstoreVerifier` or by checking that the
  provenance policy log appears twice in verbose output.

### T-055-06 (option a only): If sigstore re-verification fails at install time, install is aborted
- Arrange: scan succeeds (attestation valid), but the wiremock attestation
  endpoint is torn down before the install step re-fetches.
- Expected: `run_install` returns exit code `1` or `2` and the install command
  is not executed.

---

## Behavioral assertions (both options)

### T-055-07: When scan returns exit code 0 and the install proceeds, the package manager
  is invoked with the originally requested package name (not a version-pinned form)
- This asserts that the current behavior of passing `express` (not `express@4.18.2`)
  to `npm install` is either preserved (option b) or replaced with a pinned form
  (option a).
- Expected: the behavior chosen is documented in a source comment at the call site.

### T-055-08: When verbose output is absent (`--verbose` not passed), no extra log lines
  about the TOCTOU gap are emitted
- Run `dep-scan install express --registry npm` (no `--verbose`), wiremock clean.
- Expected: stdout/stderr do not contain the version-lock log line (it is
  verbose-only output).

---

## Regression tests

### T-055-09: All task 024 install-subcommand tests pass
- Run `cargo test install`
- Expected: 0 failures.

### T-055-10: All task 031 pip require-hashes tests pass
- Run `cargo test pip_require_hashes`
- Expected: 0 failures.

### T-055-11: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check` all pass.

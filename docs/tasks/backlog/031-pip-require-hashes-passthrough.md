# Task 031 — Close TOCTOU window for pip via `--require-hashes`

**Status:** backlog
**Depends on:** 029, 030

## Objective

Eliminate the TOCTOU gap between dep-scan's verification fetch and pip's own download. Per [ADR 003](../../architecture/decisions/003-content-hash-cache-integrity.md), npm/cargo/Go all verify content integrity themselves at install time; **pip does not, unless `--require-hashes` is passed**. Today, an attacker who republishes a PyPI package in the window between `dep-scan install`'s verification fetch and pip's resolver fetch can substitute bytes that dep-scan already approved.

This task closes that window by passing dep-scan's just-verified hash through to pip via a synthetic requirements file.

## Behavior

In `run_install`'s pip branch ([src/main.rs:462](../../../src/main.rs#L462)):

1. After the scan passes (or `--force` is used), collect the `(name, version, content_hash)` triple for every package being installed — pulled from `PackageMetadata` populated in task 029.
2. If every package has a `Some` hash: write a temp requirements file in `<tempdir>/dep-scan-<random>.txt` with lines of the form `<name>==<version> --hash=sha256:<hex>`, one per line.
3. Invoke pip as `pip install --require-hashes -r <tempfile>` instead of `pip install <packages>`.
4. Delete the temp file after pip exits, regardless of exit code.
5. If *any* package has `None` for the hash (private PyPI mirror that doesn't publish digests, or the rare case from T-029-07), **fall back** to the existing `pip install <packages>` invocation and log a one-line warning to stderr: `warning: <pkg> has no verifiable hash from <registry-url>; pip will not verify integrity at download time`.

Non-pip registries are unaffected — npm, cargo, and Go already self-verify.

## Acceptance criteria

- [ ] `run_install` PyPI branch builds a synthetic `--require-hashes` requirements file from the metadata captured during the scan
- [ ] Requirements file lines use the format `<name>==<version> --hash=sha256:<hex>` (PyPI hashes are always sha256 per task 029)
- [ ] Temp file is created in `std::env::temp_dir()` with a random suffix and is removed in a `Drop`-style cleanup that runs even if pip exits non-zero
- [ ] When all packages have hashes, pip is invoked as `pip install --require-hashes -r <tempfile>`
- [ ] When *any* package lacks a hash, fall back to `pip install <packages>` and print a per-package stderr warning naming the registry URL
- [ ] No change to npm, cargo, or Go install paths
- [ ] Integration test: pip install with a clean package — temp requirements file is generated, pip is invoked with `--require-hashes -r`, file is cleaned up afterward
- [ ] Integration test: pip install where the metadata returned `content_hash = None` — fallback path is taken, warning printed, no `--require-hashes` argument
- [ ] Integration test: pip install with mixed packages (one has hash, one doesn't) — fallback path is taken; the partial-passthrough is not attempted (all-or-nothing avoids per-package divergence)
- [ ] `--force` interacts cleanly: if force is used after a hash mismatch re-scan, the `--require-hashes` passthrough still applies to whatever hash was observed at the end of the (forced) scan
- [ ] All tests pass, `cargo clippy` clean, `cargo fmt --check` clean

## Out of scope

- npm/cargo/Go passthrough — those package managers already verify at install time
- Downloading and locally re-hashing the artifact (`--paranoid` mode) — separate deferred work
- Building a full requirements file from a lockfile-scoped install — this task only covers explicit `dep-scan install <pkg> [<pkg>...]` invocations

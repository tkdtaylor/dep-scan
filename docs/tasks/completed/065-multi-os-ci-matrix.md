# Task 065 — Multi-OS test matrix in CI

**Status:** completed
**Depends on:** none
**Source:** post-v1.2.0 holistic review (Tier A #3)
**Touches:** `.github/workflows/ci.yml`

## Objective

Run the test job on `ubuntu-latest`, `macos-latest`, and `windows-latest` so
platform-specific regressions surface in CI, not at release-tag time.

## Background

The release workflow builds five platforms (linux x86_64 + aarch64, macOS
x86_64 + aarch64, windows x86_64). CI only verifies Ubuntu. The mismatch means
a macOS-specific or Windows-specific bug — most likely in the `cfg(unix)` /
`cfg(windows)` paths in `src/cache.rs` (file-mode handling) or `src/main.rs`
(temp-file paths) — slips through every PR.

Three relevant code paths that differ by OS:

- `Cache::new` (`src/cache.rs:54-102`) — `cfg(unix)` paths run
  `OpenOptions::create_new + mode(0o600)` and `set_permissions(0o600)`; Windows
  is no-op.
- `TempReqFile` for pip (`src/main.rs`) — uses `tempfile::NamedTempFile` which
  has platform-specific implementations.
- Sigstore fixture I/O — file separators, line endings.

We've never run the suite on macOS or Windows.

## Behavior

1. Convert the `test` job's `runs-on` to a matrix over
   `[ubuntu-latest, macos-latest, windows-latest]`.
2. `clippy` and `fmt` jobs stay Linux-only (they're cargo-tool checks, not
   platform-specific behavior).
3. `audit` job (task 064) stays Linux-only.
4. The matrix should use `fail-fast: false` so a Windows failure doesn't mask a
   real macOS regression.
5. If any platform has known-failing tests at the time of landing, document
   them with `#[cfg_attr(target_os = "…", ignore)]` or a tracking issue — do
   not silently skip.

## Acceptance criteria

- [ ] `test` job has a matrix over the three OSes
- [ ] `fail-fast: false` set on the matrix
- [ ] All three matrix legs pass against current `main` (or any platform-skips
      are explicitly documented)
- [ ] Workflow YAML is valid
- [ ] `clippy`, `fmt`, and `audit` jobs stay Linux-only (no churn there)

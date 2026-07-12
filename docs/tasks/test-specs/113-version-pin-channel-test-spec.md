# Test Spec — Task 113: version-pin-channel

## Context

Three uncoordinated dep-scan versions exist across the ecosystem: code-scanner's Docker image pin, reverse-engineer's Docker image pin, and host PATH installs. Task 113 publishes a machine-readable version pin that consumers share: a top-level `PINNED_VERSION` file in this repo containing exactly one release tag (current: `v1.3.1`, matching `Cargo.toml` `version = "1.3.1"` and the git tag format `v1.3.1`), updated as part of the release-prep commit, plus a documented consumer convention (README section and interfaces.md entry). It is a text file with one version string at a stable raw URL, not a service.

Repo facts the assertions below rely on (verified at time of writing):

- `install.sh` already accepts `--version=<tag>` (`PIN_VERSION`, line 36) and uses the value verbatim in `https://github.com/tkdtaylor/dep-scan/releases/download/${version}/...`, so the pin file must store the tag WITH the `v` prefix.
- `install.sh --dry-run` exits 0 before any download; with `--version=` set it also skips the GitHub API "latest" lookup, so a dry-run with a pin is fully offline.
- `dep-scan --version` prints `dep-scan <X.Y.Z>` without the `v` (clap `#[command(name = "dep-scan", version, about)]`, `src/cli.rs:40`, from `CARGO_PKG_VERSION`).
- `RELEASE_CHECKLIST.md` section "2. Release prep" is the numbered list where the pin bump belongs (alongside `Cargo.toml` and `CHANGELOG.md`, staged in the same `chore: cut vX.Y.Z` commit).
- README has a `## Contents` index at line 21; the new section slots into it.
- CI (`.github/workflows/ci.yml`) runs `cargo test`, so a Rust integration test asserting pin/Cargo.toml lockstep makes a forgotten bump fail CI on the release-prep commit itself.

All tests are offline; no network assertions.

---

## Pin file shape and lockstep (new `tests/version_pin_integration.rs`)

Locate the file via `concat!(env!("CARGO_MANIFEST_DIR"), "/PINNED_VERSION")`.

### T-113-01: `PINNED_VERSION` exists at the repo root
- `std::fs::read_to_string` succeeds on `<CARGO_MANIFEST_DIR>/PINNED_VERSION`.

### T-113-02: Content is exactly `"v" + CARGO_PKG_VERSION + "\n"` (byte-exact)
- Assert `contents == format!("v{}\n", env!("CARGO_PKG_VERSION"))`.
- With the current tree this means the literal bytes `v1.3.1\n`, but the assertion MUST be written against the env macro, never a hardcoded literal, so the test is the lockstep gate: bumping `Cargo.toml` without bumping `PINNED_VERSION` (or vice versa) fails `cargo test`, and therefore fails CI on the `chore: cut vX.Y.Z` commit.

### T-113-03: Format is a single `v`-prefixed semver line
- Exactly one `\n`, located at the end (`contents.matches('\n').count() == 1` and `contents.ends_with('\n')`).
- The trimmed value matches `^v[0-9]+\.[0-9]+\.[0-9]+$` (hand-rolled check or `regex` dev-dependency only if one is already in the tree; prefer a manual split-and-parse on `.` with `u64::from_str` to avoid a new dependency).
- No leading/trailing spaces or tabs, no CR (`!contents.contains('\r')`). This is the shape consumers shell-substitute directly into `install.sh --version="$(curl -fsSL <raw url>)"`.

---

## Documentation contract (same integration test file, grep-style assertions)

### T-113-04: README documents the channel and both consumer conventions
- `README.md` contains a `## Version pinning for consumers` heading, the literal raw URL `https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/PINNED_VERSION`, the string `--version=` (the install.sh pass-through), and the string `dep-scan --version` (the host drift check).
- The `## Contents` index contains a link to the new section.

### T-113-05: RELEASE_CHECKLIST.md includes the pin bump in release prep
- `RELEASE_CHECKLIST.md` contains the string `PINNED_VERSION` inside section "2. Release prep" (assert the substring appears after the `## 2. Release prep` heading and before `## 3.`), and the step 5 `git add` line includes `PINNED_VERSION`.

### T-113-06: interfaces.md documents the published pin channel
- `docs/spec/interfaces.md` contains a section documenting `PINNED_VERSION`: the raw URL, the exact format (`single line, "v" + semver + "\n"`), and a stability row stating the file path, URL, and format are stable (a format change requires a major version bump). Grep for `PINNED_VERSION` in the file.

---

## install.sh compatibility (offline, `std::process::Command` from the same test file; skip on Windows with `#[cfg(unix)]`)

### T-113-07: The pin value drives install.sh verbatim in dry-run
- Run `bash install.sh --dry-run --version="$(pin file contents, trimmed)"` from the repo root (read the file in the test and pass the trimmed value as the arg; do not shell out to curl).
- Exit status 0.
- stdout contains `Pinned version: v1.3.1` (build the expected string from the file contents, not a literal).
- stdout contains the composed release URL `https://github.com/tkdtaylor/dep-scan/releases/download/v<X.Y.Z>/dep-scan-v<X.Y.Z>-` (prefix match is enough; the target triple varies by host).
- No network access happens: dry-run with a pin never calls `get_latest_version` and exits before download. This proves the file's format is exactly what `install.sh --version=` consumes.

---

## Tooling gate

### T-113-08: No regressions
- `cargo test` (full suite, including the new `version_pin_integration`) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.
- No new dependencies in `Cargo.toml` (the test uses std only).

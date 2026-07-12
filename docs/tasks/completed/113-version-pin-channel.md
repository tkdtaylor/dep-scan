# Task 113 — version-pin-channel

**Status:** backlog
**Depends on:** none (independent of task 112; the two can land in either order)
**Consumers:** code-scanner and reverse-engineer Docker builds, host PATH installs; consumer-side tasks that fetch the pin are being planned in parallel in those repos
**ADR:** not needed if the design below is followed as-is (a text file, no service); write one only on deviation
**Scope:** small
**Touches:** `PINNED_VERSION` (new, repo root), `tests/version_pin_integration.rs` (new), `README.md` (new section + Contents index entry), `RELEASE_CHECKLIST.md` (release-prep step), `docs/spec/interfaces.md` (new published-channel section)

## Objective

Publish a machine-readable version pin that all dep-scan consumers share: a top-level `PINNED_VERSION` file containing exactly one release tag, kept in lockstep with `Cargo.toml` by a cargo test and bumped in the release-prep commit. Document the consumer convention: Docker builds (code-scanner, reverse-engineer) fetch the pin file and install exactly that release; host installs check drift by comparing `dep-scan --version` against it. Dead simple: a text file with one version string at a stable raw URL, not a service.

## Context / Background

Three uncoordinated dep-scan versions exist across the ecosystem today: code-scanner's Docker image pins one version, reverse-engineer's Docker image pins another, and host PATH installs float on whatever `install.sh` resolved as latest at install time. There is no single place a consumer can ask "which dep-scan should I be running?". This matters more with task 112 in flight: the cached-verdict attribution contract only helps code-scanner's gate if the deployed dep-scan is a release that has it.

Repo conventions checked while writing this task (no existing pin convention found, so `PINNED_VERSION` is the name; nothing in the tree collides with it):

- Release tags are `vX.Y.Z` (`git tag` shows `v1.0.0` ... `v1.3.1`); `Cargo.toml` currently has `version = "1.3.1"`.
- `install.sh` already accepts `--version=<tag>` (the `PIN_VERSION` var, line 36) and interpolates the value verbatim into `https://github.com/tkdtaylor/dep-scan/releases/download/${version}/dep-scan-${version}-<target>.<ext>`. So the pin file stores the tag WITH the `v` prefix and consumers pass it through unmodified. No install.sh change is needed.
- `dep-scan --version` prints `dep-scan 1.3.1` (clap `version` attribute, `src/cli.rs:40`), so the host drift check re-adds the `v` before comparing.
- `RELEASE_CHECKLIST.md` section "2. Release prep" is where version-bearing files are bumped and staged into the single `chore: cut vX.Y.Z` commit; the pin joins that list so it can never lag a tag.
- CI runs `cargo test` on every push, so the lockstep test (pin == `v` + `CARGO_PKG_VERSION`) makes a forgotten bump fail CI on the release-prep commit itself.

## Exact changes

### 1. `PINNED_VERSION` (new file, repo root)

Exact content (six bytes + newline, no other whitespace, LF only):

```
v1.3.1
```

The value always names the release consumers should install: the latest tagged release. On the day this task lands, that is the current `Cargo.toml` version because `main` is at 1.3.1 released; from then on the release checklist keeps it current. Published (like `install.sh` already is) at the stable raw URL:

```
https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/PINNED_VERSION
```

### 2. `tests/version_pin_integration.rs` (new)

Implements T-113-01 through T-113-07 (std only, offline, no new dependencies):

- T-113-01/02/03: file exists; content is byte-exactly `format!("v{}\n", env!("CARGO_PKG_VERSION"))`; single LF-terminated `v`-semver line (manual split-and-parse, no regex crate).
- T-113-04/05/06: grep-style doc assertions on `README.md`, `RELEASE_CHECKLIST.md`, `docs/spec/interfaces.md` (details in the test spec).
- T-113-07 (`#[cfg(unix)]`): `bash install.sh --dry-run --version=<trimmed pin>` exits 0, prints `Pinned version: <pin>` and the composed `releases/download/<pin>/dep-scan-<pin>-` URL prefix. Fully offline: dry-run with a pin skips the GitHub API lookup and exits before download.

### 3. `README.md`: new section + index entry

Add `## Version pinning for consumers` (place it after `## Supported ecosystems`, before `## Develop locally`) and add a matching line to the `## Contents` index (line 21). Section body defines the convention, exactly this contract (wording may be tightened, content must not change):

- What: `PINNED_VERSION` at the repo root holds the single release tag consumers should install, format `vX.Y.Z` plus trailing newline, updated in the same commit as every release version bump. Fetch it from the raw URL above.
- Docker consumers (code-scanner, reverse-engineer) install exactly the pinned release:

```dockerfile
RUN set -eux; \
    PIN="$(curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/PINNED_VERSION)"; \
    curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh \
      | INSTALL_DIR=/usr/local/bin bash -s -- --version="${PIN}"
```

- Host installs check drift:

```bash
pin="$(curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/PINNED_VERSION)"
local="v$(dep-scan --version | awk '{print $2}')"
[ "$pin" = "$local" ] || echo "dep-scan version drift: local ${local}, pinned ${pin}"
```

- Integrity note: the pin file rides on GitHub main-branch integrity; binary integrity is enforced downstream by `install.sh`'s existing sha256sums verification and cosign-signed releases. The pin is a coordination channel, not a trust root.

### 4. `RELEASE_CHECKLIST.md`: release-prep step

In section "2. Release prep", add a numbered item after the `CHANGELOG.md` item: bump `PINNED_VERSION` to `vX.Y.Z` (the tag being cut; `cargo test` fails if it diverges from `Cargo.toml`). Extend the step-5 `git add` line to `git add Cargo.toml Cargo.lock CHANGELOG.md PINNED_VERSION`.

### 5. `docs/spec/interfaces.md`: published-channel section (additive; same commit per repo convention)

Add a new top-level section (alongside the existing inbound/outbound interfaces, suggested placement after "Inbound interface: shell wrappers") titled `## Published channel: version pin (PINNED_VERSION)` documenting: the file path and raw URL, the exact format (single line, `v` + semver + LF), producer rule (bumped in the release-prep commit, lockstep-enforced by `tests/version_pin_integration.rs`), consumer rules (Docker exact-install, host drift check, both as in the README), and a stability table row: file name, URL, and format are stable; changing any of them is a breaking change requiring a major version bump. This is additive to the stable contract; nothing existing is modified beyond inserting the section.

## Step-by-step outline

1. Step 0: `scripts/start-task.sh 113 version-pin-channel` (branch or worktree; `cd` in if WORKTREE).
2. Commit the test spec milestone if not already committed (`test: add spec for task 113 — version-pin-channel`), adding the coverage-tracker.md row (🟡 pending).
3. Create `PINNED_VERSION` with content `v1.3.1` + newline. If `Cargo.toml` has moved past 1.3.1 by execution time, use `v<that version>` instead; T-113-02 defines the truth.
4. Write `tests/version_pin_integration.rs` (T-113-01..07); run it red where docs are missing.
5. Add the README section + Contents entry (exact contract above).
6. Add the RELEASE_CHECKLIST.md step and extend its `git add` line.
7. Add the interfaces.md section.
8. Gate: `cargo test && cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --check`.
9. Move this file to `docs/tasks/completed/` (use `git mv`), update `coverage-tracker.md`, commit `feat: complete task 113 — version-pin-channel`, push. Run spec-verifier before promoting the tracker row.

## Requirements

### REQ-113-01: Single-source pin file
`PINNED_VERSION` at the repo root, one `v`-prefixed semver line plus trailing LF, nothing else. Directly consumable by `install.sh --version=` with zero transformation.

### REQ-113-02: Lockstep enforced by cargo test
`tests/version_pin_integration.rs` asserts the content equals `"v" + CARGO_PKG_VERSION + "\n"` via the env macro (never a hardcoded literal). A version bump that misses either file fails `cargo test`, and therefore CI.

### REQ-113-03: Release process owns the bump
RELEASE_CHECKLIST.md section 2 lists the pin bump and stages it in the `chore: cut vX.Y.Z` commit.

### REQ-113-04: Documented consumer convention
README section (with Contents entry) defines the raw URL, the Docker exact-install recipe, and the host drift check, in copy-pasteable form.

### REQ-113-05: Spec updated in the same commit
interfaces.md documents the channel with a stability statement (file name, URL, format stable; changes are major-version events).

### REQ-113-06: No service, no new dependencies
No endpoints, no polling daemons, no auto-update, no new crates. Text file + docs + one test file.

## Acceptance criteria

- [x] `PINNED_VERSION` exists at the repo root (T-113-01)
- [x] Content byte-equals `"v" + CARGO_PKG_VERSION + "\n"` (T-113-02)
- [x] Single-line `v`-semver format, LF only, no stray whitespace (T-113-03)
- [x] README section + Contents entry with raw URL, Docker recipe, drift check (T-113-04)
- [x] RELEASE_CHECKLIST.md release-prep step + `git add` line updated (T-113-05)
- [x] interfaces.md published-channel section with stability row (T-113-06)
- [x] `bash install.sh --dry-run --version=<pin>` exits 0 and echoes the pin and release URL (T-113-07)
- [x] `cargo test` exits 0, clippy clean (`-D warnings`), fmt clean, no new dependencies (T-113-08)

## Closeout note

Implemented as specified. Runtime observation for the record (offline, `bash install.sh --dry-run --version="$(cat PINNED_VERSION)"`):

```
Detected platform: linux/x86_64 (x86_64-unknown-linux-gnu)
Pinned version: v1.3.1
Binary: dep-scan-v1.3.1-x86_64-unknown-linux-gnu.tar.gz
Install directory: /home/kevin/.local/bin

[dry-run] Would download: https://github.com/tkdtaylor/dep-scan/releases/download/v1.3.1/dep-scan-v1.3.1-x86_64-unknown-linux-gnu.tar.gz
[dry-run] Would verify checksum from: https://github.com/tkdtaylor/dep-scan/releases/download/v1.3.1/sha256sums.txt
[dry-run] Would install to: /home/kevin/.local/bin/dep-scan
```

Negative check performed by hand: temporarily edited `PINNED_VERSION` to `v0.0.0`, ran `cargo test --test version_pin_integration t113_02`, confirmed T-113-02 failed with a clear left/right diff, then restored the file and confirmed it passed again. The `tests/version_pin_integration.rs` doc comment initially triggered `clippy::doc_lazy_continuation` (a `T-113-01..03:`-style line read as an unindented list continuation); reworded to plain sentences, no functional change.

## Verification plan

- `cargo test --test version_pin_integration` (all assertions are concrete input→output checks, offline).
- `cargo test` full suite + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo fmt --check`.
- Runtime observation for the record (offline): run `bash install.sh --dry-run --version="$(cat PINNED_VERSION)"` from the repo root and quote the `Pinned version:` and `[dry-run] Would download:` lines. This exercises the exact consumer path (pin → install.sh) without network.
- Negative check by hand: temporarily edit `PINNED_VERSION` to `v0.0.0`, run `cargo test --test version_pin_integration`, confirm T-113-02 fails, revert. This proves the lockstep gate actually gates.

## Test spec

`docs/tasks/test-specs/113-version-pin-channel-test-spec.md`

## Out of scope

- Changes in code-scanner or reverse-engineer (their Docker builds adopt the recipe via their own tasks, planned in parallel in those repos).
- Any change to `install.sh` (it already supports `--version=`).
- Signing the pin file or building an update service; binary integrity remains install.sh checksums + cosign.
- Automating the bump (the checklist + failing test is the mechanism; a release script is a possible future task).
- Cutting a release; this task lands the channel, the next release exercises the checklist step.

## Dependencies

None. Independent of task 112, but the pair together is what restores code-scanner's supply-chain gate: 112 makes cached verdicts gateable, 113 lets consumers converge on a release that includes 112.

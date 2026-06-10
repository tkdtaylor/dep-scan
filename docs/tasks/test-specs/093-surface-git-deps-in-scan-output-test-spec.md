# Test Spec — Task 093: Surface git deps in scan output

## Context

ADR 008 piece 1 — the final deliverable of the detection piece. Tasks 090/091/092
ensure that git-sourced dependencies are parsed and stored as
`DependencySource::Git`. This task wires git deps through the scan loop in
`src/main.rs` so they appear in scan output with a distinct, informative verdict
instead of being silently dropped or crashing.

The ADR's stated deliverable for piece 1 is **visibility**: dep-scan reports
"this dependency is git-sourced, resolved from `<url>` at `<ref>`." No code
fetch occurs yet (that is task 097). The scan verdict for a git dep is a `Warn`
with a message naming the URL and ref, so the user knows the dep exists and
needs further action. The safe fallback stub introduced by task 090 is replaced
by this real routing.

This task depends on 090, 091, and 092 (the source model and both parsers must
exist). It does NOT depend on task 094 (mutable-ref policy), which layers on top.

---

## Routing: git deps reach a dedicated arm, not a registry client

### T-093-01: `DependencySource::Git` dep does not trigger a registry client call
- Set up a wiremock/mock registry server.
- Feed a lockfile with a single git dep to the scan loop.
- The mock server receives zero requests.
- Confirms the git dep is not mis-routed to an npm/crates/PyPI/Go registry.

### T-093-02: `DependencySource::Registry` deps are unaffected
- Feed a lockfile with one registry dep and one git dep.
- The mock registry server receives exactly one request (for the registry dep).
- The registry dep produces its normal verdict.

---

## Scan output for git deps

### T-093-03: Git dep produces a `Warn` verdict with URL and ref in the message
- Feed a lockfile with one git dep:
  `DependencySource::Git { url: "https://github.com/evil/repo", ref_: "main" }`.
- `CheckResult.verdict == Verdict::Warn`.
- `CheckResult.message` contains `"https://github.com/evil/repo"` and `"main"`.

### T-093-04: Git dep verdict message mentions it is git-sourced
- The `CheckResult.message` contains the word "git" (case-insensitive) or the
  URL scheme, so a human reading the output understands the dependency is not
  from a registry.

### T-093-05: Git dep appears in `--format native` table output
- Run a full scan against a lockfile with a git dep.
- stdout (or the native table) contains the package name and a row indicating
  a warning, not a blank or "unknown."

### T-093-06: Git dep appears in `--format json` output with correct fields
- Run with `--format json`.
- The JSON array contains an element for the git dep with `"verdict": "warn"` and
  a non-empty `"message"` field.

### T-093-07: Dep name is preserved in the output for git deps
- Input dep `name = "evil-pkg"`, `source = Git { url: "…", ref_: "abc" }`.
- `CheckResult.package_name == "evil-pkg"`.

---

## Fail-closed: unscannable git dep is never a pass

### T-093-08: Git dep verdict is never `Pass` when VCS fetch is unavailable
- In the absence of a VCS fetch client (tasks 097+ are not yet implemented),
  the verdict for a git dep must not be `Pass`. It must be `Warn` or `Block`.
- Rationale: ADR 003/008 fail-closed posture — a dep dep-scan cannot scan must
  not be silently treated as safe.

### T-093-09: Exit code is non-zero when a git dep is present (warn-is-non-zero)
- The scan loop exits with a non-zero code when there is at least one `Warn`
  verdict from a git dep (consistent with how other `Warn` verdicts behave).

---

## Multiple git deps

### T-093-10: Multiple git deps each produce individual verdicts
- Feed a lockfile with two git deps (different URLs).
- `results.len() == 2`, each with a `Warn` verdict.

### T-093-11: Mixed lockfile: registry dep passes, git dep warns
- Input: one valid registry dep (mock returns metadata, passes all policies),
  one git dep.
- Two results: one `Pass` (registry), one `Warn` (git).

---

## Version field for git deps in output

### T-093-12: Git dep `CheckResult` records the ref as the "version" for display
- The `CheckResult` for a git dep uses the git ref as the display version
  (e.g., the commit SHA or branch name), not an empty string.
- Ensures the output row is human-readable: `"evil-pkg @ main — git-sourced, url …"`.

---

## Tooling gate

### T-093-13: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

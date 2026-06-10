# Test Spec — Task 094: Mutable-ref policy

## Context

ADR 008 piece 3 (delivered second in sequencing) — distinguish a mutable git ref
(branch name or tag) from a pinned commit SHA, and warn or block when a
dependency points at a mutable ref. This policy runs at the policy layer with no
code fetch, so it is cheap to ship and mitigates the branch-flip variant
immediately after piece-1 visibility lands.

Default severity: `Warn`. Block is opt-in via `[policies] mutable_git_ref =
"block"` in `.dep-scan.toml`. This mirrors the non-regressive default pattern
from ADR 002.

A pinned commit SHA is any ref that looks like a full 40-hex-character SHA-1
or 64-hex-character SHA-256 commit hash. Everything else (branch names, tag
names, short hashes, semantic version tags, empty string) is mutable.

This policy is wired only for `DependencySource::Git` deps (task 090/091/092).
Registry deps pass through unchanged.

---

## Ref classification

### T-094-01: 40-hex SHA-1 commit is classified as pinned
- `classify_ref("a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b5")` returns `Pinned`.

### T-094-02: 64-hex SHA-256 commit is classified as pinned
- `classify_ref("a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b5a3b5c7d9e1f2a3b5c7d9e1f2")` returns `Pinned`.

### T-094-03: Branch name `main` is classified as mutable
- `classify_ref("main")` returns `Mutable`.

### T-094-04: Branch name `master` is classified as mutable
- `classify_ref("master")` returns `Mutable`.

### T-094-05: Branch name with slashes `feature/my-branch` is classified as mutable
- `classify_ref("feature/my-branch")` returns `Mutable`.

### T-094-06: Short hash (7 hex chars) is classified as mutable
- `classify_ref("abc1234")` returns `Mutable`.
- Short hashes cannot be trusted as unique identifiers at scale; they are mutable
  in the ADR's sense because they do not fully pin the commit.

### T-094-07: SemVer tag `v1.2.3` is classified as mutable
- `classify_ref("v1.2.3")` returns `Mutable`.
- Git tags are mutable — they can be force-pushed.

### T-094-08: Empty ref is classified as mutable
- `classify_ref("")` returns `Mutable`.
- An empty ref is the worst case: completely unresolved.

### T-094-09: 39-hex string (one char short of SHA-1) is classified as mutable
- `classify_ref("a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b")` returns `Mutable`.
- Only exact 40-hex or 64-hex strings count as pinned.

### T-094-10: Mixed-case hex in a 40-char string is classified as pinned
- `classify_ref("A3B5C7D9E1F2A3B5C7D9E1F2A3B5C7D9E1F2A3B5")` returns `Pinned`.
- SHA matching is case-insensitive.

---

## Policy verdicts (default Warn mode)

### T-094-11: Mutable ref produces `Warn` with message naming the ref
- `MutableRefPolicy` in default warn mode.
- Input: `DependencySource::Git { url: "https://github.com/user/repo", ref_: "main" }`.
- `PolicyVerdict::Warn`; message contains `"main"` and some indication of mutability.

### T-094-12: Pinned ref produces `Pass`
- Input: `DependencySource::Git { url: "…", ref_: "a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b5" }`.
- `PolicyVerdict::Pass`.

### T-094-13: Empty ref produces `Warn` with message
- Input: `DependencySource::Git { url: "…", ref_: "" }`.
- `PolicyVerdict::Warn`; message distinguishes "no ref specified" from a named
  branch.

### T-094-14: Policy is `Pass` for `DependencySource::Registry` deps
- Input: a `PackageMetadata` with no git source context.
- `PolicyVerdict::Pass` — the policy is a no-op for registry deps.

---

## Block mode (opt-in config)

### T-094-15: `mutable_git_ref = "block"` produces `Block` for mutable ref
- Config: `[policies] mutable_git_ref = "block"`.
- Input: git dep with `ref_ = "main"`.
- `PolicyVerdict::Block`.

### T-094-16: `mutable_git_ref = "block"` still passes pinned ref
- Config: `[policies] mutable_git_ref = "block"`.
- Input: git dep with 40-hex SHA ref.
- `PolicyVerdict::Pass`.

### T-094-17: `mutable_git_ref = "warn"` is the default — no config key required
- Config with no `mutable_git_ref` key.
- `Config::default().policies.mutable_git_ref == MutableRefSeverity::Warn`.

### T-094-18: `mutable_git_ref = "off"` disables the policy
- Config: `mutable_git_ref = "off"`.
- Input: git dep with mutable branch ref.
- `PolicyVerdict::Pass`.

---

## Config loading

### T-094-19: Unknown `mutable_git_ref` value returns error at config load
- Config: `mutable_git_ref = "explode"`.
- `Config::load` returns `Err`; error message mentions `mutable_git_ref`.

### T-094-20: `config init` emits `[policies] mutable_git_ref` with default and comment
- Running `dep-scan config init` writes a `.dep-scan.toml` including
  `mutable_git_ref = "warn"` under `[policies]` with a comment explaining the
  setting.

---

## Integration with scan loop

### T-094-21: Mutable-ref warn appears in `--format json` output
- Scan a lockfile with one git dep pointing at `"main"`.
- JSON output element has `"verdict": "warn"` and `"message"` containing `"main"`.

### T-094-22: Policy fires before any VCS fetch (no network calls)
- The mutable-ref policy check runs in the scan loop before (and independently
  of) any VCS fetch client. A wiremock stub server captures zero requests.
- Confirms: piece-3 policy has no dependency on piece-2 (VCS client).

---

## Tooling gate

### T-094-23: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

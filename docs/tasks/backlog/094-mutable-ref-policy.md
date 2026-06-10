# Task 094 — Mutable-ref policy

**Status:** backlog
**Depends on:** 090 (source model), 093 (git deps surface in scan loop — policy
               needs them to reach the policy pipeline)
**ADR:** 008 (piece 3 — mutable-ref policy; sequenced before VCS client because
         it requires no code fetch)
**Touches:** `src/policy/mutable_ref.rs` (new), `src/config.rs` (new config
            field `mutable_git_ref`), `src/main.rs` (wire policy into the git
            dep arm)

## Objective

Add a policy that distinguishes a mutable git ref (branch name, tag, or absent
ref) from a pinned commit SHA, and warns or blocks based on configuration.
Default severity: `Warn`. Block is opt-in. The policy runs at the policy layer
with no code fetch, giving piece-1 + piece-3 together the ability to catch the
branch-flip variant cheaply.

## Background

ADR 008's branch-flip threat: a git dependency that points at `main` (or any
mutable ref) can be made malicious with a single push to that ref — no new
package version, no registry activity. The only signal is the ref shape.

A pinned commit SHA is a full 40-hex (SHA-1) or 64-hex (SHA-256) string. These
are the only ref forms dep-scan treats as immutable. Everything else — branch
names, tag names, short hashes, SemVer tags, empty strings — is mutable because
git tags can be force-pushed and short hashes are non-unique.

This mirrors the ADR 002 pattern of non-regressive defaults: the policy warns
by default and requires explicit `mutable_git_ref = "block"` to block installs.
Setting `mutable_git_ref = "off"` disables it entirely.

## Requirements

### REQ-094-01: `classify_ref(ref_: &str) -> RefKind` helper
Add a pure function `classify_ref` (in `src/policy/mutable_ref.rs`) that returns
`RefKind::Pinned` for exactly 40-char or 64-char lowercase/uppercase hex strings,
and `RefKind::Mutable` for everything else (including empty string).

### REQ-094-02: `MutableRefPolicy` struct implements `Policy`
`MutableRefPolicy::check(&self, ctx: &ScanContext) -> PolicyVerdict`:
- If `ctx` carries no git source info (registry dep): return `Pass`.
- If `ctx` carries a git ref that is `Pinned`: return `Pass`.
- If `ctx` carries a mutable ref: return `Warn` or `Block` based on config.
- Message must name the ref value.

### REQ-094-03: Config field `policies.mutable_git_ref`
Add `mutable_git_ref: MutableRefSeverity` to the `[policies]` section in
`Config`. Accepted values: `"warn"` (default), `"block"`, `"off"`. Unknown
values return `Err` at config load time. Default: `Warn`.

### REQ-094-04: `config init` emits the new config key with comment
The `config init` command writes `mutable_git_ref = "warn"` under `[policies]`
with a human-readable comment.

### REQ-094-05: Policy fires with no network calls
The mutable-ref check is purely over the ref string. No VCS fetch occurs. The
policy must complete before (and independently of) any VCS client invocation.

## Acceptance criteria

- [ ] `classify_ref` returns `Pinned` for 40-hex and 64-hex strings, `Mutable` otherwise
- [ ] `MutableRefPolicy` returns `Pass` for pinned refs and registry deps
- [ ] `MutableRefPolicy` returns `Warn` for mutable refs in default config
- [ ] `mutable_git_ref = "block"` produces `Block` for mutable refs
- [ ] `mutable_git_ref = "off"` disables the policy (`Pass` for all)
- [ ] Empty ref is classified as mutable
- [ ] Short hashes and SemVer tags are classified as mutable
- [ ] `config init` includes `mutable_git_ref = "warn"` with comment
- [ ] Zero network calls (wiremock stub receives zero requests)
- [ ] All T-094-01 through T-094-23 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/094-mutable-ref-policy-test-spec.md`

## Out of scope

- VCS source client / code fetch (task 097)
- Cache integration for git sources (task 098)
- Host allow/deny policy (task 096)
- Policy for verifying the ref is a valid commit at the remote (requires fetch)

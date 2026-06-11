# Task 096 — VCS fetch client — sandboxed, read-only fetch

**Status:** backlog
**Depends on:** 090 (source model), 093 (git deps routed in scan loop), 095
               (host-policy check available before fetch)
**ADR:** 008 (piece 2 — VCS source client; this is the highest-risk piece)
**Touches:** `src/vcs/fetch.rs` (new module), `src/main.rs` (wire fetch into the
            git-dep scan arm, replacing the warn-only stub from task 093)

## Objective

Implement a sandboxed, read-only VCS fetch client (`VcsFetcher`) that retrieves
a repository at a specified ref into an ephemeral, isolated working area so its
contents can be statically analysed. This is dep-scan's first fetch of raw
third-party source code and the highest-security-risk piece in ADR 008.

## Critical design decisions to resolve before implementation

ADR 008 explicitly leaves two questions open. The task executor **must** resolve
both and document the decisions (update ADR 008 or write ADR 009) before writing
any implementation code:

**1. Fetch mechanism:** Pure-Rust git library (e.g. `gix`) vs. optional shell-out
to a system `git` binary. The single-binary constraint (CLAUDE.md, ADR 001)
requires that the default path work without any installed `git`. Pure-Rust is the
expected answer; shell-out may be offered as optional acceleration only if it is
truly optional and produces identical results.

**2. Sandbox boundary:** What operations are forbidden to guarantee no code
execution on Linux, macOS, and Windows? The executor must enumerate:
- How git hooks are disabled (never call `git clone`? operate only at object
  level? explicit hook-dir override?)
- How submodule recursion is prevented
- How symlink-outside-root escapes are caught
- How path-traversal entries in tree objects are caught
- Any platform-specific gaps

The test spec (T-096-06 through T-096-10) tests the *behavioral contract* of
these constraints; the ADR update documents the mechanism.

## Requirements

### REQ-096-01: `VcsFetcher::fetch(url: &str, ref_: &str) -> Result<FetchedTree>`
Returns an opaque `FetchedTree` handle backed by an ephemeral temp dir. The
temp dir is cleaned up when `FetchedTree` is dropped. The caller iterates files
in the tree via a `FetchedTree::files() -> impl Iterator<Item = FetchedFile>`
method. `FetchedFile` exposes `path: &Path` (relative to the fetch root) and
`content: &[u8]`.

### REQ-096-02: Network only on explicit scan
`VcsFetcher` must be instantiated and `fetch` called only from within the scan
code path, never from config load, lockfile parse, or any other implicit path.

### REQ-096-03: Host policy checked before any TCP connection
`fetch` must call `check_host_policy_for_url` (task 095) and return `Err`
immediately if the host is blocked, without opening any socket.

### REQ-096-04: No code execution — hard constraints
The fetch implementation must never:
- Execute git hooks (pre-receive, post-checkout, post-merge, etc.)
- Recurse into submodules
- Follow symlinks that point outside the fetch working area
- Write files at paths containing `..` or absolute paths

Violation of any of these must produce `Err`, not a silent write or a panic.

### REQ-096-05: Fail-closed on network error or timeout
Network failure, DNS failure, timeout, or ref-not-found all return `Err` with a
descriptive message. An `Err` from `fetch` propagates to the scan loop as a
`Warn` or `Block` verdict (consistent with task 093/094), never `Pass`.

### REQ-096-06: Works without a system `git` binary
The pure-Rust code path must function in an environment where no `git` binary
is on `PATH`. (Optional: shell-out acceleration when `git` is present, producing
identical output.)

### REQ-096-07: `VcsFetcher` timeout is configurable
Add `vcs.fetch_timeout_secs: u64` to `VcsConfig` (default 30). If the fetch
does not complete within the timeout, return `Err`.

### REQ-096-08: Very large blobs are capped
A single blob larger than `vcs.max_blob_bytes` (configurable, default 50 MB)
is skipped with a diagnostic warning, not read into memory. This prevents OOM
on adversarially large fetched files.

## Acceptance criteria

- [ ] `VcsFetcher::fetch` returns a tree of files for a valid ref
- [ ] FetchedTree is cleaned up on drop (no temp files left behind)
- [ ] Git hooks are never executed (T-096-06 sentinel test passes)
- [ ] Submodule callbacks are never triggered (T-096-07 sentinel test passes)
- [ ] Symlinks outside fetch root are not followed (T-096-08)
- [ ] Path traversal (`../`) in tree entries is rejected (T-096-09)
- [ ] Absolute paths in tree entries are rejected (T-096-10)
- [ ] Network failure returns `Err` within timeout (T-096-13/14)
- [ ] Unfetchable dep produces `Warn`/`Block`, never `Pass` (T-096-15)
- [ ] Host policy enforced before any TCP connection (T-096-16/17)
- [ ] Works with no system `git` on PATH (T-096-19)
- [ ] Design decisions documented (ADR 008 update or new ADR 009)
- [ ] All T-096-01 through T-096-21 pass
- [ ] `cargo test` exits 0, clippy clean, fmt clean

## Test spec

`docs/tasks/test-specs/096-vcs-fetch-sandbox-test-spec.md`

## Out of scope

- Cache integration for fetched git sources (task 097)
- Running policy pipeline against fetched trees (task 098)
- Transitive dependency resolution (task 099)
- KMS / authenticated fetch (future)

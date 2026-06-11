# Test Spec — Task 096: VCS fetch client — sandboxed, read-only fetch

## Context

ADR 008 piece 2 — the VCS source client that fetches a repository at a specified
ref so its contents become available for static analysis. This is dep-scan's
**first network fetch of raw third-party source code**, which is the highest-risk
piece in ADR 008.

### Open design questions (must be resolved before implementation begins)

ADR 008 explicitly leaves two decisions open that directly govern this task.
The task executor **must** resolve both before writing any implementation code,
by either updating ADR 008 with the resolution or writing a new ADR 009:

1. **Fetch mechanism:** Pure-Rust git (e.g. `gix` family) vs. optional shell-out
   to a system `git` binary when present. The single-binary constraint (CLAUDE.md,
   ADR 001) argues for pure-Rust as the default. Shell-out is acceptable only as
   optional graceful acceleration — it must not be the only code path. Document
   the chosen approach and the rationale.

2. **Sandbox boundary:** What isolation is sufficient to guarantee "no code
   execution" across all supported platforms (Linux, macOS, Windows)? Specifically:
   git hooks, submodule recursion callbacks, symlink escapes, and path traversal
   in tree extraction. The ADR names this the "security crux of piece 2." The
   executor must document the chosen sandbox boundary (e.g. never call
   `git clone`, operate on pack-file / object-level primitives, explicitly disable
   hooks, never recurse submodules) and note any platform-specific gaps.

The test cases below are written against the *behavior contract* regardless of
which mechanism is chosen. They are adversarial-heavy because the fetch surface
accepts untrusted data.

---

## Network-only-on-explicit-scan invariant

### T-096-01: No fetch occurs during config load or lockfile parse
- Call `Config::load` and `lockfile::parse` with a git-dep lockfile.
- Assert no outbound connections are made (mock HTTP/TCP layer captures zero
  calls).
- The fetch client is not instantiated until the explicit scan path is entered.

### T-096-02: No fetch occurs outside the scan subcommand
- Invoke dep-scan with a subcommand other than `check` (e.g. `config init`).
- No outbound connections.

---

## Happy-path fetch

### T-096-03: Fetches tree at a pinned commit SHA
- Stand up a local bare git repo (test fixture) with a known commit SHA.
- `VcsFetcher::fetch(url, ref_)` where `ref_` is the full commit SHA.
- Returns a handle (temp dir or in-memory tree) containing the files at that
  commit.
- Does not fetch any other commits or branches.

### T-096-04: Fetched tree is ephemeral (cleaned up after scope exit)
- After the fetch handle is dropped, the temp working area no longer exists on
  disk (or in memory).

### T-096-05: Fetch of a non-existent ref returns `Err`, not hang
- `VcsFetcher::fetch(url, "nonexistent-branch-xyz")` returns `Err` with a
  message naming the ref.
- Does not hang indefinitely (timeout respected — see T-096-07).

---

## No code execution — adversarial inputs

### T-096-06: Git hooks in the fetched repo are never executed
- Construct a test repo fixture that contains a `hooks/pre-receive` (or
  `hooks/post-checkout`, etc.) script that writes a sentinel file to disk.
- Run `VcsFetcher::fetch` against this repo.
- Assert the sentinel file was NOT created — the hook was never run.
- This is the most critical single test in this spec.

### T-096-07: Submodule init/update callbacks are never triggered
- Construct a test repo fixture with a `.gitmodules` file pointing at a
  (local) submodule repo that contains a hook writing a sentinel file.
- Run `VcsFetcher::fetch` against the parent repo.
- Assert the sentinel file was NOT created — submodule recursion did not occur.

### T-096-08: Symlink in fetched tree pointing outside the fetch root is not followed
- Construct a test repo fixture containing a symlink `evil -> /etc/passwd`
  (or equivalent on Windows: `evil -> C:\Windows\System32`).
- Run `VcsFetcher::fetch`.
- Assert dep-scan does not read the target of the symlink and does not expose
  any bytes from outside the fetch working area.
- The symlink entry may be surfaced as a warning or skipped; it must not be
  followed.

### T-096-09: Path traversal via tree entry (`../../../etc/passwd`) is rejected
- Construct a test repo fixture (or a crafted pack file / object) where a tree
  entry has a path component containing `..`.
- `VcsFetcher::fetch` returns `Err` or skips the offending entry without
  writing any file outside the isolated working area.
- The working area's parent directories are not written to.

### T-096-10: Absolute path in tree entry is rejected
- Tree entry with an absolute path (e.g. `/etc/cron.d/evil` on Unix,
  `C:\Windows\evil` on Windows).
- Same behavior as T-096-09: `Err` or skip, no write outside the fetch root.

### T-096-11: Zero-byte file in fetched tree does not cause panic
- Repo fixture with an empty file.
- Fetch succeeds; the empty file is represented in the tree (size 0).

### T-096-12: Very large file (>50 MB) in fetched tree is capped or rejected
- Repo fixture with a single >50 MB blob.
- Fetch returns `Err` or truncates/skips the blob with a diagnostic message.
- dep-scan must not OOM on adversarially large fetched files.

---

## Offline / network failure behaviour (fail-closed)

### T-096-13: Fetch with no network connectivity returns `Err` with clear message
- Configure the fetch client to use a non-routable address (`192.0.2.1`).
- `VcsFetcher::fetch` returns `Err` within a reasonable timeout.
- Error message indicates network failure, not a panic.

### T-096-14: Fetch timeout is enforced — does not hang indefinitely
- Use a TCP server that accepts the connection but never sends data.
- `VcsFetcher::fetch` returns `Err` after the configured timeout.
- Default timeout must be finite and documented in config.

### T-096-15: A dep that cannot be fetched is never treated as a `Pass`
- `VcsFetcher::fetch` failure propagates to a `Block` or `Warn` verdict in the
  scan loop (ADR 003/008 fail-closed: unfetchable != safe).
- Exact severity is `Block` when `mutable_git_ref = "block"` and `Warn`
  otherwise, consistent with task 094 behaviour.

---

## Host policy enforcement before fetch

### T-096-16: Host not on allow list is rejected before any TCP connection
- Config: `vcs.allowed_hosts = ["github.com"]`.
- Attempt fetch from `evil.example.com`.
- `VcsFetcher::fetch` returns `Err` before making any network call.
- Mock TCP server at `evil.example.com` receives zero connections.

### T-096-17: Host on deny list is rejected before any TCP connection
- Config: `vcs.denied_hosts = ["evil.example.com"]`.
- Mock server at `evil.example.com` receives zero connections.

---

## Fetch is read-only

### T-096-18: Fetcher does not write to the source repository
- Run fetch against a local bare repo.
- After fetch, the bare repo's object store and refs are byte-for-byte identical
  to before the fetch (no `git push`, no ref updates, no lock files left behind).

---

## Single-binary constraint

### T-096-19: Fetch works without a system `git` binary on PATH
- Run the test in an environment where `PATH` contains no `git` binary
  (e.g. a tmp dir with no executables).
- `VcsFetcher::fetch` still succeeds against a local test fixture.
- This confirms the pure-Rust default path is functional.

### T-096-20: If a system `git` is present, it may be used as optional acceleration
  but the result is identical
- Run the same fetch with and without a system `git` on PATH.
- Both succeed and produce byte-for-byte identical file trees in the fetch root.
- (Only required if the implementation supports optional shell-out per the
  resolved open question.)

---

## Tooling gate

### T-096-21: No regressions
- `cargo test` (full suite) exits 0.
- `cargo clippy --all-targets --all-features -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

---

## Security-hardening addendum (post-implementation audit)

A security audit of the delivered fetch client found a Critical and a High
finding rooted in a false premise in the original ADR: `gix-transport` compiles
the `ssh` **and** `file` transports in *unconditionally* (they are not
feature-gated out), and **both spawn a subprocess** (`git-upload-pack` for
`file://`, the local `ssh` binary for `ssh://`). An attacker-controlled lockfile
can emit such a URL, breaking the "pure-Rust gix ⇒ no subprocess" guarantee. The
following test cases pin the fix and MUST pass.

### SEC-001 / SEC-002: scheme allow-list, fail-closed
- `check_scheme_allowed` permits ONLY `https://` and `git://` (case-insensitive);
  these are the transports gix services without spawning a subprocess.
- Every other input is rejected with an `Err` naming the disallowed scheme:
  `file://`, `ssh://`, `git+ssh://`, `http://`, `ext::`, scp-style
  `user@host:path`, bare local paths, and unrecognised input.
- End-to-end: a `Cargo.lock` with `source = "git+file:///…#<sha>"` scanned through
  the binary yields verdict `warn` (never `pass`), the reason names `file://` and
  the scheme allow-list, and NO `git-upload-pack` subprocess is spawned (the gate
  runs before any gix connection). Same for `git+ssh://` → `warn`, fail-closed.
- No scheme bypass of the host policy: the removed `is_local_scheme` helper used
  to exempt `file://` from the host check (the bypass); local/unknown schemes now
  fail closed at the allow-list gate. Host policy still applies to https/git.

### SEC-002 subprocess-orphan
- Because only https (reqwest) and `git://` (TCP) are permitted, an allowed fetch
  spawns NO child process — there is no orphan-on-timeout concern. The
  subprocess-spawning transports never reach the fetch.

### SEC-003 / SEC-004: DoS caps on tree materialisation
- Aggregate total-byte budget (`vcs.max_total_bytes`, default 512 MiB): a tree of
  individually-under-cap blobs whose sum exceeds the budget fails closed with a
  diagnostic mentioning "total bytes".
- Aggregate file-count budget (`vcs.max_total_files`, default 50 000): a tree with
  more files than the budget fails closed with a diagnostic mentioning "file count".
- Recursion-depth limit (`MAX_TREE_DEPTH` = 100): a tree nested past the limit
  fails closed with a diagnostic mentioning "depth" — never a stack overflow.

### SEC-005: policed host matches gix's connecting host
- For a tricky userinfo URL (`https://a@b@host/x`), `extract_host` agrees with
  `gix::url::parse(...).host()`, so policy cannot be parsed against one host while
  gix connects to another.

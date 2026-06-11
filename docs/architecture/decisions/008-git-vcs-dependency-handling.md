# ADR 008 — Git/VCS dependency handling and transitive scanning

**Status:** Proposed
**Date:** 2026-06-10

## Context

dep-scan today has a structural blind spot: it scans only **published registry
packages** (npm, PyPI, crates.io, the Go proxy) and only the **flat list of direct
entries** in a lockfile. Two whole classes of dependency escape every policy in the
pipeline.

**1. Git/VCS-sourced dependencies are silently dropped or mis-routed.** The npm
lockfile parser (`src/lockfile.rs:88-95`) keys off the `version` field and ignores the
`resolved` field. A git dependency's `resolved` value is a git URL of the form
`git+ssh://…#<ref>` (or `git+https://…#<ref>`), with no usable `version` — so the entry
is either dropped (empty `version` is skipped) or, when a placeholder version is present,
mis-routed to the npm registry as a plain `name@version` lookup that does not correspond
to the code actually installed. The main scan loop (`src/main.rs:311-331`) converts every
lockfile entry to a `PackageRef { name, version }` and routes it exclusively to a registry
client; there is no VCS/git client. The same gap exists for Cargo's `git+` sources.

**2. There is no transitive resolution anywhere.** The scan calls
`get_metadata(name, version)` per direct entry and never reads a package's *own*
dependency manifest. A payload that is one hop away — a clean direct dependency that pulls
in a malicious indirect one — is never seen unless that indirect package happens to also be
a direct entry in the same lockfile.

**The motivating threat (the "o3forms" npm incident).** A published npm package is
spotless: ~350 bytes, no install scripts, nothing the install-script scanner
(`src/policy/install_script.rs`) or the obfuscation detector
(`src/policy/obfuscation.rs`) would flag — because both operate only on registry
metadata. But the package declares a dependency on a GitHub repo via a git URL, and the
malware lives in *that repo*: it steals AWS/Azure/GCP credentials, maps the internal
network, and exfiltrates to a Cloudflare Workers endpoint. npm never sees the payload, and
neither does any SCA tool that scans only the registry. dep-scan currently inherits exactly
that blind spot on both axes at once — the git dep is dropped (axis 1) and, even if it were
a transitive registry dep, never walked (axis 2).

**The branch-flip variant makes this worse and cheaper for the attacker.** If the git
dependency points at a **mutable ref** — a branch or tag — rather than a pinned commit SHA,
the repository can look completely legitimate for weeks and then flip to malicious with a
single push. No new npm release is cut, no version changes, nothing in the registry moves.
dep-scan has no policy that distinguishes a mutable ref from a pinned commit SHA, so even
the *shape* of this risk is invisible today.

This ADR records the decision to close both axes, in dependency order, and is explicit
about which pieces are cheap and high-value versus which constitute a heavy, separable epic.

## Constraints

These carry over from the project's standing invariants (CLAUDE.md, ADR 002, ADR 003,
overview *Constraints and non-goals*) and bind every piece below:

- **Local-first / network only on explicit scan.** dep-scan makes network calls *only*
  when the user explicitly invokes a scan. Fetching a git repo is a network call and must
  obey this rule — no cloning during config load, lockfile parse, or any implicit path.
- **Single static binary, no runtime dependencies.** Whatever fetches a git repo must not
  require a system `git` binary, a language runtime, or any other out-of-band tool to be
  present for dep-scan to function. (Optional acceleration via a system `git` if present is
  acceptable as graceful degradation, mirroring the optional-Semgrep pattern in ADR 002 — but
  the default path must work from the single binary.)
- **No hardcoded hosts/URLs.** Per CLAUDE.md, registry URLs are configurable; VCS hosts and
  any allow/deny host policy must likewise be configurable, never hardcoded. There is no
  built-in trust in `github.com` over any other host.
- **No code execution, ever.** dep-scan does not modify or run packages (overview non-goal).
  Fetching source to *scan* it must never trigger build scripts, install hooks, submodule
  hooks, or git hooks. The fetch is read-only data acquisition for static analysis.
- **Fail-closed on unscannable input.** Consistent with ADR 003's cache posture: a
  dependency dep-scan cannot resolve, fetch, or scan must not be silently treated as a pass.

## Decision

Close the blind spot in four pieces, ordered by dependency. Pieces 1 and 3 are cheap,
self-contained, and high-value on their own; piece 2 unlocks deep scanning of git sources;
piece 4 is the heavy, separable epic.

### 1. Detect git/VCS URLs in lockfiles

Read the source fields the parsers currently discard and surface git-sourced dependencies
as a **distinct dependency kind** rather than dropping them or mis-routing them to a
registry client.

- npm: read the `resolved` field; recognize `git+ssh://…#<ref>`, `git+https://…#<ref>`,
  and shorthand GitHub/GitLab forms; extract `(host, repo, ref)`.
- Cargo: recognize `git+` sources and their `#<rev>` fragment.
- Model the result as a new dependency-source variant (e.g. extend `LockfileDependency`
  /`PackageRef` with a `source: Registry | Git { url, ref }` distinction) so downstream
  code can branch on kind instead of assuming "registry" everywhere.

The deliverable of piece 1 by itself is **visibility**: dep-scan stops silently dropping
git deps and instead reports "this dependency is git-sourced, resolved from `<url>` at
`<ref>`." That visibility is the precondition for both piece 2 (fetch it) and piece 3
(judge its ref), and is independently shippable.

### 2. A VCS source client

Add a VCS source client that fetches/clones the repository at the specified ref so its
contents become scannable. **This is the first time dep-scan fetches raw source code rather
than registry metadata**, which is the consequential design shift in this ADR and carries
the heaviest security implications:

- **Sandboxed, read-only fetch with no code execution.** The fetch must not run build
  scripts, install hooks, git hooks, or submodule callbacks. Prefer a shallow fetch of the
  single ref into an isolated, ephemeral working area; treat the result as untrusted data.
- **Honor "network only on explicit scan."** The client runs only inside the scan path,
  never implicitly.
- **Configurable hosts.** A configurable allow/deny host policy gates which VCS hosts may
  be fetched; nothing is hardcoded. Offline/air-gapped operation must degrade clearly
  (fail-closed with a legible message), not hang.
- **Caching.** Fetched-and-scanned git sources should cache by a *pinned-commit* key so a
  re-scan of an immutable SHA is a cache hit. Mutable refs cannot be safely cached by ref
  name — see piece 3 and the cache open question below.
- Once fetched, the existing policy pipeline (install-script scanner, obfuscation detector,
  etc.) runs against the source tree, finally giving those policies something to inspect for
  git-sourced code.

### 3. Mutable-ref policy

Add a policy that distinguishes a **mutable git ref** (branch or tag) from a **pinned
commit SHA**, and warns or blocks when a dependency points at a mutable ref.

- **Default severity: Warn.** Block is opt-in via configuration (mirroring how the
  `maintainer_first_seen` and similar policies stay non-regressive by default in ADR 002).
- **High value, low cost — and it works without piece 2.** Pieces 1 + 3 together catch the
  branch-flip variant *at the policy layer with no code fetch at all*: piece 1 surfaces the
  ref, piece 3 judges whether it is pinned. A dependency on a moving branch is flagged
  regardless of whether the repo currently looks clean. This is the cheapest meaningful
  mitigation of the motivating threat and should land early.

### 4. Transitive resolution

Walk fetched and registry packages' **own dependency manifests** so payloads one hop (or
more) away are scanned, instead of only the flat lockfile entries.

This is by far the **largest scope** and is framed here as a **possibly-separate epic** with
genuine unresolved design questions (see *Open questions*): depth limits, cycle detection,
whether the lockfile or each package's manifest is the source of truth for the edge set, and
the impact on the `(name, version, registry)` cache model — which has no representation for
a git source or for "this verdict depended on these transitive children." This ADR commits
to the *direction* (transitive scanning is in scope for the product) but deliberately does
**not** commit to a single resolution algorithm here; that is left to the epic's own design
work so we do not over-commit to a model that the cache and source-kind changes from pieces
1–3 may reshape.

## Implementation order

| Priority | Piece | Scope | Network fetch of code? | Mitigates |
|----------|-------|-------|------------------------|-----------|
| 1 | Detect git/VCS URLs in lockfiles | Low–Medium | No | Silent-drop / mis-route blind spot; precondition for 2 & 3 |
| 2 | Mutable-ref policy (Warn default) | Low | No | Branch-flip variant, at the policy layer |
| 3 | VCS source client (sandboxed fetch) | High | Yes (first time) | Malicious code in git-sourced repos |
| 4 | Transitive resolution | Highest (separable epic) | Inherits 3 | One-hop-away payloads |

Note the ordering swap relative to the *Decision* numbering: piece 3 (mutable-ref policy)
is sequenced **before** piece 2 (VCS client) in delivery because it depends only on piece 1,
is cheap, and mitigates the branch-flip threat without any code fetch. The heavier VCS
client follows. The transitive epic is last and gated on its own open questions.

## Open questions

- **VCS fetch mechanism.** ~~Pure-Rust git (e.g. a `gix`-family crate) vs. optional shell-out
  to a system `git` when present.~~ **RESOLVED (task 096) — see "Piece 2 resolution" below.**
- **Sandbox boundary for the fetch.** ~~What isolation is sufficient to guarantee "no code
  execution" across platforms (git hooks, submodule recursion, symlink escapes, path
  traversal in archive/tree extraction)?~~ **RESOLVED (task 096) — see "Piece 2 resolution".**
- **Host trust policy shape.** Allow-list, deny-list, or both; default posture; how it
  composes with enterprise mirrors. Must stay configuration-driven (no hardcoded hosts).
  *(Largely settled by task 095: both lists, deny-wins, open default posture, case-insensitive,
  config-driven. Task 096 hardening: there is NO scheme bypass of the host policy. `file://`,
  `ssh://`, bare local paths, and any non-`https`/`git` scheme are rejected fail-closed by the
  scheme allow-list before the host check; the host policy applies to the permitted https/git
  schemes. The earlier note that `file://` bypasses the host lists was the SEC-002 bypass and
  has been removed.)*

## Piece 2 resolution (task 096 — sandboxed VCS fetch client)

Both open questions that govern piece 2 are resolved here, since piece 2 is the highest-risk
component and its implementation cannot proceed without fixing them.

### Fetch mechanism: pure-Rust gitoxide (`gix`), no shell-out

The default and only fetch path uses the pure-Rust `gix` (gitoxide) crate, satisfying the
single-binary constraint (ADR 001): the fetch works with **no system `git` on `PATH`**
(verified by T-096-19, which strips `PATH` and still fetches via gix's pure-Rust `git://`
transport). HTTPS fetches reuse the existing `reqwest` + `rustls` stack
(`blocking-http-transport-reqwest-rust-tls`), adding no new TLS backend. The optional
shell-out acceleration is **omitted**: it would add a second code path, a second sandbox to
audit, and a correctness-parity burden, for no benefit on the dominant HTTPS path.

`gix` feature set is minimal and deliberately excludes worktree checkout/mutation
(`worktree-mutation`), submodule features, and the curl transport.

#### Correction (security review): the ssh/file transports are NOT excluded by features

An earlier draft of this section claimed the `ssh` and `file` transports were compiled out
by the `gix` feature selection. **That claim was false.** `gix-transport` compiles the
`file` **and** `ssh` transports in *unconditionally* — they are not behind any feature we
can turn off — and **both spawn a subprocess**:

- `file://` (and bare local paths) spawns `git-upload-pack`;
- `ssh://` (and scp-style `user@host:path`) spawns the local `ssh` binary.

Either subprocess can execute attacker-influenced code, which directly breaks the sandbox's
central guarantee (*pure-Rust gix ⇒ no subprocess, no code execution*) for any URL an
attacker-controlled lockfile can emit.

#### Real defense: a fail-closed scheme allow-list at the fetch boundary (SEC-001/SEC-002)

`VcsFetcher::fetch` enforces a **scheme allow-list as its very first action**, before any
host-policy check, any gix connection, any socket, or any worker thread. Only the two
transports gix services **entirely in-process** are permitted:

- `https://` — the bundled `reqwest`/`rustls` HTTP transport (no subprocess);
- `git://`   — the pure-Rust TCP daemon protocol (no subprocess).

**Every** other input fails closed with an `Err` naming the disallowed scheme: `file://`,
`ssh://`, `git+ssh://`, `ext::`, `http://` (cleartext — rejected to keep the allow-list to
exactly the two audited in-process transports), scp-style `user@host:path`, bare local
paths, and anything unrecognised. Because the gate runs before any connection is prepared,
a rejected scheme opens **no socket and spawns no process**. The `Err` propagates to the
scan loop, which fails closed (Warn, or Block under `mutable_git_ref = "block"`) — never
Pass. Consequently, **no allowed transport (https/git) ever spawns a child process**, so the
"no subprocess / no code execution" guarantee holds for every fetch that is permitted to run.

The previous design exempted `file://` (and bare local paths) from the host-policy check on
the rationale that they "open no network socket." That exemption was itself the bypass
(SEC-002): it let an attacker-controlled local-scheme URL skip policy entirely. There is now
**no scheme exemption** from the host check — unknown/local schemes fail closed at the
allow-list gate, and the host policy still applies to the allowed https/git schemes.

#### DoS caps on tree materialisation (SEC-003/SEC-004)

In addition to the per-blob cap (`vcs.max_blob_bytes`, default 50 MiB), the materialiser
enforces three aggregate budgets so an adversarial tree of individually-under-cap objects
cannot exhaust disk, inodes, or the stack — each fails closed with a diagnostic:

- **Total materialised bytes** — `vcs.max_total_bytes`, default 512 MiB.
- **Total materialised file count** — `vcs.max_total_files`, default 50 000.
- **Tree recursion depth** — constant `MAX_TREE_DEPTH = 100` (comfortably exceeds any real
  repo layout while bounding stack usage); a tree nested past this limit fails closed before
  it can overflow the stack.

The byte and count budgets are configurable on `[vcs]`; the depth limit is a constant.

### Sandbox boundary: fetch-to-objects, materialise-ourselves

We **never invoke the `git` CLI** and **never check out a git working tree**. The fetch
pulls the pack into an *ephemeral bare repository* in a temp dir; we then resolve the
requested ref to a commit, peel to its root tree, and walk the tree **at the object level**,
reading blobs from the object database and materialising files into an isolated subdir
*ourselves*. Because no checkout ever runs:

- **Git hooks never execute** (T-096-06). There is no `git` process and no checkout step, so
  pre-receive/post-checkout/post-merge/etc. are structurally unreachable.
- **Submodules are never recursed** (T-096-07). Gitlink (`Commit`) tree entries are recorded
  as a `SubmoduleNotRecursed` diagnostic and skipped; `.gitmodules` is treated as ordinary
  data. No submodule fetch/init occurs.
- **Symlinks are never followed** (T-096-08). `Link` tree entries are recorded as a
  `SymlinkNotFollowed` diagnostic; their target string is never resolved or read, and no
  symlink is created on disk (so it cannot be traversed later).
- **Path traversal is rejected** (T-096-09). Every tree-entry name is validated as a single
  safe path component; `..`, `.`, empty names, names containing `/` or `\`, and NUL bytes
  produce `Err` (the whole fetch fails closed). A defence-in-depth check re-validates the
  full relative path and confirms the canonicalised write target stays under the fetch root.
- **Absolute paths are rejected** (T-096-10). A leading separator or a Windows drive-letter
  prefix (`C:`) is rejected. Note: a real git tree entry name cannot contain `/` (git
  plumbing rejects it), so the only absolute-looking single-component name an adversary can
  smuggle into a *real* tree is the drive-prefix form, which the validator catches; the
  leading-slash case is covered by the path-component validator unit test.
- **OOM / DoS protection** (T-096-12, SEC-003/SEC-004). A blob whose object header reports a
  size larger than `vcs.max_blob_bytes` (default 50 MiB) is skipped with a `BlobTooLarge`
  diagnostic *without being decoded into memory* — the size is read from the object header
  first. Aggregate caps (total bytes `vcs.max_total_bytes` 512 MiB, total file count
  `vcs.max_total_files` 50 000, and recursion depth `MAX_TREE_DEPTH` 100) fail the fetch
  closed before disk/inode/stack exhaustion. See the DoS-caps subsection above.
- **Timeout / fail-closed** (T-096-05/13/14/15). The fetch runs on a worker thread bounded by
  `vcs.fetch_timeout_secs` (default 30): an internal watchdog trips gix's cooperative
  interrupt flag, and the caller additionally bounds the channel receive so `fetch` returns
  within the budget plus a small grace even if gix is stuck in an uninterruptible syscall.
  Any network/DNS/timeout/ref-not-found error returns `Err`, which the scan loop turns into a
  `Warn` (or `Block` when `mutable_git_ref = "block"`) — an unfetchable dep is **never**
  `Pass`. **No subprocess-orphan concern (SEC-002):** because the only permitted transports
  are https (reqwest) and `git://` (TCP), an allowed fetch spawns no child process at all, so
  there is no child that could be left detached when the timeout fires. The subprocess-spawning
  transports (`file://`, `ssh://`) never reach the fetch — they are rejected at the scheme
  allow-list before any connection is prepared.

**Platform notes.** Path-traversal and absolute-path validation normalise on both `/` and
`\` separators and treat a leading drive-letter or UNC-style prefix as absolute, so a tree
authored on Windows cannot escape the fetch root on a Unix host or vice versa. Symlinks are
never materialised on any platform, so the long-standing Windows symlink/junction and case-
insensitivity hazards do not apply to our materialised tree. The one platform-specific gap
to revisit when piece 4 (transitive) lands: case-insensitive/Unicode-normalised filesystems
could collapse two distinct tree entry names onto one path — currently harmless (last writer
wins inside the sandbox) but worth a normalisation pass if collisions ever become
security-relevant.

#### Security re-audit residuals (task 096 follow-up)

A re-audit confirmed the critical subprocess-escape (SEC-001/SEC-002) is closed and found
three further items, resolved as follows:

- **SEC-005-RESIDUAL — host-policy parse-vs-connect divergence (Medium, fixed).** The host
  allow/deny check is only sound if the host it *polices* is the host gix actually *connects
  to*. The previous `extract_host` hand-parsed the URL and split the post-scheme remainder on
  `['/', '?', '#']` before taking the authority. gix does **not** treat `#`/`?` as authority
  terminators — it splits the authority only at the first `/`, then `rsplit_once('@')`. So
  `https://github.com#@evil.com/x` and `https://github.com?@evil.com/x` were policed as host
  `github.com` while gix connected to `evil.com` — an allow-list/deny-list bypass and SSRF
  vector for any attacker-controlled lockfile URL. **Fix:** `extract_host` now derives the
  host from gix's *own* parser (`gix::url::parse(url.into())?.host()`, lowercased), so the
  policed host equals the connecting host **by construction**; the divergence is eliminated
  rather than patched. Unparseable URLs and URLs gix parses with no host component return
  `None`, preserving the fail-closed contract in `check_host_policy_for_url`. Parity tests
  assert `extract_host(url) == gix::url::parse(url).host()` for the `#@`, `?@`, git:// `#@`,
  and `a@b@host` vectors, plus explicit regressions that each bypass vector now polices the
  real connecting host (`evil.com` / `evil.internal`), never the decoy `github.com`.

- **SEC-006 — unbounded network pack download (Medium, mitigated by post-fetch budget).** The
  `max_blob_bytes` / `max_total_bytes` / `max_total_files` caps bound only *materialisation*,
  which runs **after** `prepare.fetch_only(...)` has already streamed the entire pack to disk.
  A malicious server on an allowed host could therefore stream an arbitrarily large pack,
  filling the temp filesystem before any cap applies — bounded only by `fetch_timeout_secs`.
  gix 0.84's high-level `PrepareFetch` API exposes no clean in-fetch byte/object budget hook
  (option (a) would require reimplementing the fetch negotiation against the low-level
  `gix-protocol`/`gix-pack` API — out of scope and high-risk), so we took **option (b)**: a
  new configurable budget `vcs.max_pack_bytes` (default 1 GiB) is enforced **immediately after
  `fetch_only` returns and before any materialisation** by summing the on-disk size of the
  fetched object store (`<repo>/objects`, never following symlinks) and failing closed if it
  exceeds the budget. This is a *post-fetch* check — the pack is already on disk when measured
  — so it bounds disk *after the fact* but caps before materialisation can amplify it; the
  streaming download itself remains bounded only by `fetch_timeout_secs`. The two bounds
  combine: the timeout caps how long a stream may run, the pack budget caps how much it may
  leave on disk before any further processing.

- **SEC-007 — detached stuck worker (Low, documented residual).** The hard wall-clock bound in
  `VcsFetcher::fetch` is enforced by bounding the channel `recv` on the caller thread; if the
  worker thread is wedged in a syscall gix cannot cooperatively interrupt, `fetch` still
  returns on time but the worker is **detached** and keeps running until it unwinds (or the
  process exits). It owns its own `TempDir`, so its scratch space is reclaimed when it finally
  ends; the residual is a possibly-lingering background thread/socket, not a leak of attacker
  data into a `Pass` verdict. Acceptable for task 096; revisit if process-lifetime thread
  accumulation ever becomes observable in practice.

Out of scope for task 096 (handled later): running the *policy pipeline* over the fetched
tree is task 098 — this task delivers the fetch + sandbox and the fail-closed wiring only, so
a successfully fetched git dep is materialised but not yet scanned. Cache integration is task
097; transitive resolution is task 099.
- **Cache key for git sources.** The current cache is keyed `(name, version, registry)`.
  Immutable commit SHAs key cleanly; mutable refs and "no registry" git sources do not. Does
  the key become `(name, commit_sha, source)`? Are mutable-ref results cacheable at all?
- **Transitive: source of truth.** Lockfile (already-resolved, complete, but may omit git
  sub-trees) vs. each package's own manifest (authoritative for edges but requires
  resolution and re-introduces version-range ambiguity).
- **Transitive: depth limit and cycle detection.** Default max depth; cycle handling;
  performance budget when one scan fans out into hundreds of transitive nodes; how partial
  failures (one unfetchable node) roll up into the top-level verdict under fail-closed.

## Piece 2 cache resolution (task 097 — VCS fetch cache integration)

This resolves the **"Cache key for git sources"** open question above.

- **Key.** Git-sourced results are cached under `(name, commit_sha, "git")`, reusing the
  existing `(name, version, registry)` schema: `version` holds the full commit SHA and the
  registry slot is the literal `"git"`. The `"git"` slot does **not** collide with any
  `RegistryType` string (`npm`, `pypi`, `crates`, `go`), so a crate `foo@abc…` and a git dep
  `foo@abc…` are distinct rows.
- **Only pinned SHAs are cacheable.** A full commit SHA is immutable and uniquely identifies
  the fetched tree, so it is a safe cache key. A **mutable ref** (branch name, tag, short
  hash, empty) does **not** uniquely identify a tree — its content can change between scans —
  so mutable-ref results are **never written to the cache**. Every scan of a mutable ref
  re-fetches and re-checks. The pinned-vs-mutable decision is made by `classify_ref` (task
  094); it is not reimplemented in the cache layer.
- **Schema migration.** An additive, idempotent `source_kind TEXT` column is added to
  `scanned_packages` (only when absent — mirrors the task-029/032 migrations). Git rows carry
  `source_kind = "git"`; registry rows and all legacy/pre-097 rows carry `NULL`. No column
  drops, no backfill, existing registry entries remain readable.
- **Content-hash integrity (ADR 003 / task 030).** Each git row stores a `sha256:` digest
  computed over the fetched tree (length-framed path+content per file, deterministic order).
  On lookup the task-030 `verify_hash` gate is applied; a row whose stored hash is missing,
  `sha1:`-prefixed, or otherwise non-matching fails the gate and forces a re-fetch
  (fail-closed). Fetch failures are not cached — there is no tree to anchor the hash to.
- **Cache I/O errors (REQ-047-01/02 posture).** A DB error on a git-dep lookup is surfaced
  to stderr as a warning and the scan proceeds with a full re-fetch — never a silent pass,
  never a hard abort.

## Consequences

- **+** Closes a real, exploited blind spot (the o3forms class): git-sourced and one-hop-away
  payloads become visible to the existing policy pipeline instead of bypassing it entirely.
- **+** Pieces 1 + 3 deliver meaningful protection against the branch-flip variant **early
  and cheaply**, with no network fetch of code and no change to the security posture beyond a
  new policy verdict.
- **+** Surfacing a distinct git dependency *kind* removes the current silent-drop /
  mis-route behavior, which is itself a correctness and trust improvement regardless of the
  later pieces.
- **−** Piece 2 introduces dep-scan's **first fetch of raw third-party source code**, a
  materially larger trust boundary and attack surface (untrusted trees, hooks, submodules,
  path/symlink traversal) than fetching registry metadata. This must be designed
  sandbox-first and is the highest-risk piece.
- **−** The `(name, version, registry)` cache model does not represent git sources or
  transitive provenance; piece 4 (and to a lesser extent piece 2) will force a cache-schema
  evolution, with the usual migration care (additive, idempotent — per the cache-schema
  conventions in the overview).
- **−** Transitive scanning can turn a single top-level scan into a large fan-out; without
  depth limits, cycle detection, and good caching it risks slow scans — directly in tension
  with the "fast, local-first" product promise. This is why piece 4 is scoped as a separable
  epic rather than committed to here.
- **−** Offline/air-gapped operation gains a new fail-closed path: a git dependency that
  cannot be fetched cannot be scanned and must not pass silently, so some previously
  "passing" (because dropped) dependency sets will now correctly fail or warn.

## References

- [ADR 002](002-detection-strategy.md) — detection strategy; optional-tool / graceful-degradation
  pattern and the default-non-regressive policy posture reused by piece 3
- [ADR 003](003-content-hash-cache-integrity.md) — fail-closed cache posture and the
  `(name, version, registry)` cache model that pieces 2 & 4 must evolve
- `src/lockfile.rs` — npm parser that currently discards the `resolved` git URL (piece 1)
- `src/main.rs` (scan loop) — registry-only routing with no VCS client (pieces 1 & 2)
- `src/policy/install_script.rs`, `src/policy/obfuscation.rs` — policies that today see only
  registry metadata and would gain git-sourced trees to inspect (piece 2)

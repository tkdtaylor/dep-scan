//! Sandboxed, read-only VCS (git) fetch client — ADR 008 piece 2 (task 096).
//!
//! This module is dep-scan's **first network fetch of raw third-party source
//! code** and is the highest-security-risk component in ADR 008.  Every design
//! choice here is driven by one goal: *fetch the bytes of a repository at a
//! pinned ref without ever executing any code from that repository*.
//!
//! ## Sandbox model (REQ-096-04)
//!
//! We never invoke the `git` CLI and we never check out a git working tree.
//! Instead we:
//!
//! 1. Check the host allow/deny policy **before opening any socket**
//!    (REQ-096-03) via [`crate::policy::vcs_host::check_host_policy_for_url`].
//! 2. Fetch the pack into an **ephemeral bare repository** in a temp dir using
//!    pure-Rust gitoxide (`gix`).  No `git clone`, no checkout, no worktree, so
//!    git hooks, smudge/clean filters, and submodule callbacks are structurally
//!    unreachable — there is no code path that would ever run them.
//! 3. Resolve the requested ref to a commit, peel to its root tree, and walk
//!    the tree **at the object level**, reading each blob from the object
//!    database.  We materialise files into an isolated `materialised/` subdir
//!    of the temp dir ourselves, applying our own sandbox checks on every tree
//!    entry path:
//!    - reject path components containing `..` (path traversal, REQ-096-04),
//!    - reject absolute paths,
//!    - never follow symlinks (`Link` entries are recorded as metadata only —
//!      their *target string* is never resolved or read),
//!    - never recurse into submodules (`Commit`/gitlink entries are skipped).
//! 4. Cap blob size: a blob whose object header reports a size larger than
//!    `max_blob_bytes` is skipped with a diagnostic **without being decoded
//!    into memory** (REQ-096-08), preventing OOM on adversarial inputs.
//!
//! The whole temp dir — bare repo plus materialised tree — is removed when the
//! returned [`FetchedTree`] is dropped (REQ-096-01 / T-096-04).
//!
//! ## Platform notes
//!
//! Path-traversal and absolute-path checks normalise on both `/` and `\`
//! separators and treat a leading drive-letter (e.g. `C:`) or UNC prefix as
//! absolute, so a tree authored on Windows cannot escape the fetch root on a
//! Unix host or vice versa.  Symlinks are never materialised on any platform.

// The `FetchedTree` accessor API (`files`, `FetchedFile::path` / `::content`,
// `is_empty`, `diagnostics`) is the contract task 098 will consume when it runs
// the policy pipeline over fetched trees.  In this task the scan loop only reads
// `len()`, and the accessors are otherwise exercised solely by the behavioural
// tests below, so non-test builds see them as unused.  Suppress until 098 wires
// the consumer in — mirrors the same forward-reference pattern in
// `policy/vcs_host.rs`.
#![allow(dead_code)]

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use tempfile::TempDir;

use crate::config::Config;
use crate::policy::vcs_host::check_host_policy_for_url;

/// A single file materialised from a fetched git tree.
///
/// `path` is always **relative** to the fetch root and has been validated to
/// contain no `..` components and to be non-absolute.  `content` is the decoded
/// blob bytes (for regular files) — symlink and submodule entries never produce
/// a `FetchedFile`.
pub struct FetchedFile<'a> {
    path: &'a Path,
    content: &'a [u8],
}

impl<'a> FetchedFile<'a> {
    /// The path of this file relative to the fetch root.
    pub fn path(&self) -> &'a Path {
        self.path
    }

    /// The raw bytes of this file.
    pub fn content(&self) -> &'a [u8] {
        self.content
    }
}

/// Owned backing storage for one materialised file.
struct FetchedFileOwned {
    path: PathBuf,
    content: Vec<u8>,
}

/// A non-fatal observation made while materialising a fetched tree.
///
/// These are surfaced to the caller (and ultimately to scan output) so that an
/// operator can see *why* a file was not scanned — e.g. a symlink that was not
/// followed, a submodule that was not recursed, or a blob that exceeded the
/// size cap.  A diagnostic never escalates to an error on its own; truly unsafe
/// inputs (path traversal, absolute paths) produce an `Err` from [`fetch`]
/// instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchDiagnostic {
    /// A symlink entry was found and deliberately not followed.  The string is
    /// the entry path relative to the fetch root.
    SymlinkNotFollowed(String),
    /// A submodule (gitlink) entry was found and deliberately not recursed.
    SubmoduleNotRecursed(String),
    /// A blob exceeded `max_blob_bytes` and was skipped without being decoded.
    BlobTooLarge { path: String, size: u64, cap: u64 },
}

/// An opaque handle to a fetched repository tree, backed by an ephemeral temp
/// dir that is removed on drop (REQ-096-01).
pub struct FetchedTree {
    /// Kept alive so the temp dir (bare repo + materialised tree) is removed on
    /// drop.  The field is never read directly — its `Drop` does the work.
    _temp: TempDir,
    files: Vec<FetchedFileOwned>,
    diagnostics: Vec<FetchDiagnostic>,
}

impl std::fmt::Debug for FetchedTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately compact: never dump (potentially large / untrusted) blob
        // contents into debug/error output.
        f.debug_struct("FetchedTree")
            .field("files", &self.files.len())
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

impl FetchedTree {
    /// Iterate the regular files materialised from the fetched tree.
    pub fn files(&self) -> impl Iterator<Item = FetchedFile<'_>> {
        self.files.iter().map(|f| FetchedFile {
            path: f.path.as_path(),
            content: f.content.as_slice(),
        })
    }

    /// The number of regular files in the tree.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the tree contains no regular files.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Non-fatal observations made while materialising the tree (skipped
    /// symlinks, submodules, oversized blobs).
    pub fn diagnostics(&self) -> &[FetchDiagnostic] {
        &self.diagnostics
    }

    /// The absolute path of the isolated materialisation root on disk.  Used by
    /// tests to assert nothing was written outside it.
    #[cfg(test)]
    fn root(&self) -> PathBuf {
        self._temp.path().join("materialised")
    }
}

/// A sandboxed, read-only VCS fetch client.
///
/// Construct with [`VcsFetcher::from_config`] (the only supported entry point —
/// it captures the timeout and blob-size budget and a clone of the host
/// policy).  `VcsFetcher` performs network I/O **only** when [`fetch`] is
/// called, and `fetch` is only reachable from the explicit scan path
/// (REQ-096-02): nothing in config load or lockfile parse constructs one.
///
/// [`fetch`]: VcsFetcher::fetch
pub struct VcsFetcher {
    config: Arc<Config>,
}

impl VcsFetcher {
    /// Build a fetcher from the loaded configuration.  Captures the fetch
    /// timeout, blob-size cap, and host allow/deny lists.
    pub fn from_config(config: &Config) -> Self {
        Self {
            config: Arc::new(config.clone()),
        }
    }

    /// Fetch the repository at `url`, resolve `ref_` to a tree, and materialise
    /// its files into an ephemeral, isolated working area.
    ///
    /// # Errors
    ///
    /// Returns `Err` (fail-closed, REQ-096-05) on any of:
    /// - the host is blocked by policy (checked **before** any socket opens,
    ///   REQ-096-03),
    /// - the URL has no resolvable host,
    /// - the network fetch fails (DNS, connection refused, transport error),
    /// - the fetch exceeds `vcs.fetch_timeout_secs` (REQ-096-07),
    /// - `ref_` does not resolve to a commit in the fetched repository,
    /// - a tree entry path attempts traversal (`..`) or is absolute
    ///   (REQ-096-04).
    pub fn fetch(&self, url: &str, ref_: &str) -> Result<FetchedTree> {
        // REQ-096-03: host policy is the *first* thing we do.  If the host is
        // not permitted we return immediately and open NO socket — this check
        // runs on the caller's thread, before any worker is spawned.
        //
        // `file://` URLs (and bare local paths) open no network socket and have
        // no remote host to police, so the host allow/deny lists — which govern
        // *network egress* — do not apply.  They still pass through the full
        // sandbox materialisation below.  All other schemes are policed.
        if !is_local_scheme(url) {
            check_host_policy_for_url(url, &self.config)
                .with_context(|| format!("VCS host policy rejected fetch of {url}"))?;
        }

        if ref_.is_empty() {
            bail!("refusing to fetch git url {url} with an empty ref (fail-closed)");
        }

        let timeout = Duration::from_secs(self.config.vcs.fetch_timeout_secs);
        let max_blob_bytes = self.config.vcs.max_blob_bytes;

        // REQ-096-07: enforce a hard wall-clock bound on `fetch` returning.
        //
        // The network fetch + materialisation runs on a worker thread.  The
        // worker also runs an internal watchdog that trips gix's interrupt flag
        // (so gix aborts cooperatively at its next check point), but we do NOT
        // rely solely on that: we bound the channel `recv` ourselves so `fetch`
        // is guaranteed to return within `timeout` plus a small grace period
        // even if the worker is stuck in a syscall gix cannot interrupt.  A
        // stuck worker is detached; it owns its own `TempDir`, so when it does
        // eventually unwind (or the process exits) the temp dir is cleaned up.
        let url_owned = url.to_string();
        let url_for_err = url_owned.clone();
        let ref_owned = ref_.to_string();
        let (tx, rx) = std::sync::mpsc::channel::<Result<FetchedTree>>();
        let worker_timeout = timeout;
        std::thread::spawn(move || {
            let result = fetch_blocking(&url_owned, &ref_owned, worker_timeout, max_blob_bytes);
            // Ignore send errors: if the receiver already timed out and went
            // away, we simply drop the result (and its TempDir cleans up).
            let _ = tx.send(result);
        });

        // Grace period above the network budget so the cooperative watchdog
        // inside the worker (which trips at `timeout`) is given a chance to
        // produce a descriptive timeout error before our own hard bound fires.
        let grace = Duration::from_secs(5);
        match rx.recv_timeout(timeout + grace) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => bail!(
                "git fetch of {url_for_err} did not complete within {}s (hard timeout, fail-closed)",
                timeout.as_secs()
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                bail!("git fetch worker terminated unexpectedly (fail-closed)")
            }
        }
    }
}

/// Perform the blocking fetch + tree materialisation.  Runs on a worker thread.
fn fetch_blocking(
    url: &str,
    ref_: &str,
    timeout: Duration,
    max_blob_bytes: u64,
) -> Result<FetchedTree> {
    // The single temp dir owns everything: the ephemeral bare repo lives in
    // `repo/`, and we materialise the tree into `materialised/`.  Both are
    // removed when `FetchedTree` (and thus the `TempDir`) is dropped.
    let temp = tempfile::Builder::new()
        .prefix("dep-scan-vcs-")
        .tempdir()
        .context("failed to create ephemeral temp dir for VCS fetch")?;
    let repo_dir = temp.path().join("repo");
    let materialised_dir = temp.path().join("materialised");
    std::fs::create_dir(&materialised_dir).context("failed to create materialisation root")?;

    // Fetch the pack into a bare repository.  No worktree, no checkout, so no
    // hooks / filters / submodule callbacks can ever run (REQ-096-04).
    let repo = fetch_into_bare_repo(url, &repo_dir, timeout)
        .with_context(|| format!("failed to fetch git repository {url}"))?;

    // Resolve the requested ref to a tree.
    let tree = resolve_ref_to_tree(&repo, ref_)
        .with_context(|| format!("could not resolve git ref {ref_:?} for {url}"))?;

    // Walk the tree at the object level, materialising blobs with full sandbox
    // enforcement.  An unsafe path (traversal / absolute) aborts with Err.
    let mut files = Vec::new();
    let mut diagnostics = Vec::new();
    materialise_tree(
        &repo,
        &tree,
        Path::new(""),
        &materialised_dir,
        max_blob_bytes,
        &mut files,
        &mut diagnostics,
    )?;

    Ok(FetchedTree {
        _temp: temp,
        files,
        diagnostics,
    })
}

/// Fetch `url` into a fresh bare repository at `repo_dir` using pure-Rust gix.
///
/// A watchdog thread flips an interrupt flag after `timeout`, which gix checks
/// during the fetch, giving us a hard wall-clock budget (REQ-096-07).
fn fetch_into_bare_repo(url: &str, repo_dir: &Path, timeout: Duration) -> Result<gix::Repository> {
    let should_interrupt = Arc::new(AtomicBool::new(false));

    // Watchdog: trip the interrupt flag once the budget is exhausted.  We use a
    // polling loop with a done-flag so the thread exits promptly when the fetch
    // finishes early (rather than sleeping the full timeout every call).
    let done = Arc::new(AtomicBool::new(false));
    let watchdog_interrupt = Arc::clone(&should_interrupt);
    let watchdog_done = Arc::clone(&done);
    let deadline = Instant::now() + timeout;
    let watchdog = std::thread::spawn(move || {
        while !watchdog_done.load(Ordering::SeqCst) {
            if Instant::now() >= deadline {
                watchdog_interrupt.store(true, Ordering::SeqCst);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let result = (|| -> Result<gix::Repository> {
        let mut prepare = gix::clone::PrepareFetch::new(
            url,
            repo_dir,
            // Bare: object database only, never a working tree.
            gix::create::Kind::Bare,
            gix::create::Options::default(),
            gix::open::Options::isolated(),
        )
        .with_context(|| format!("failed to prepare fetch of {url}"))?;

        // We deliberately do NOT call `with_ref_name`: it panics when given a
        // hex object id (T-096-03 fetches by full commit SHA).  The default
        // refspec fetches refs into the object db; we resolve the ref locally.
        let (repo, _outcome) = prepare
            .fetch_only(gix::progress::Discard, &should_interrupt)
            .map_err(|e| anyhow!("git fetch failed: {e}"))?;
        Ok(repo)
    })();

    // Stop the watchdog and join it.
    done.store(true, Ordering::SeqCst);
    let _ = watchdog.join();

    match result {
        Ok(repo) => Ok(repo),
        Err(e) => {
            if should_interrupt.load(Ordering::SeqCst) {
                bail!(
                    "git fetch of {url} timed out after {}s (fail-closed)",
                    timeout.as_secs()
                );
            }
            Err(e)
        }
    }
}

/// Resolve `ref_` to the root tree of the commit it names.
///
/// Accepts a full commit SHA, a tag, or a branch name.  We resolve manually
/// (without gix's `revision` feature, keeping the dependency surface minimal):
///
/// 1. If `ref_` parses as a full hex object id, look the object up directly and
///    peel it to a tree (handles T-096-03 pinned commit SHAs).
/// 2. Otherwise try a sequence of reference names — the ref verbatim, the
///    remote-tracking branch `refs/remotes/origin/<ref>` that a clone writes,
///    and the tag `refs/tags/<ref>` — peeling the first that resolves.
fn resolve_ref_to_tree<'repo>(
    repo: &'repo gix::Repository,
    ref_: &str,
) -> Result<gix::Tree<'repo>> {
    // 1. Full commit SHA: parse and look up directly.
    if let Ok(id) = gix::ObjectId::from_hex(ref_.as_bytes())
        && let Ok(object) = repo.find_object(id)
    {
        let tree = object
            .peel_to_tree()
            .map_err(|e| anyhow!("commit {ref_:?} does not peel to a tree: {e}"))?;
        return Ok(tree);
    }

    // 2. Symbolic ref: branch / tag.  Try a few standard spellings.
    let candidates = [
        ref_.to_string(),
        format!("refs/remotes/origin/{ref_}"),
        format!("refs/tags/{ref_}"),
        format!("refs/heads/{ref_}"),
    ];
    let mut last_err: Option<String> = None;
    for name in &candidates {
        match repo.find_reference(name.as_str()) {
            Ok(mut reference) => {
                let tree = reference
                    .peel_to_tree()
                    .map_err(|e| anyhow!("ref {name:?} does not peel to a tree: {e}"))?;
                return Ok(tree);
            }
            Err(e) => last_err = Some(e.to_string()),
        }
    }

    bail!(
        "git ref {ref_:?} not found in fetched repository{}",
        last_err.map(|e| format!(" ({e})")).unwrap_or_default()
    )
}

/// Recursively materialise a tree object, applying sandbox checks on every
/// entry path.  `rel_prefix` is the path of `tree` relative to the fetch root.
fn materialise_tree(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    rel_prefix: &Path,
    materialised_root: &Path,
    max_blob_bytes: u64,
    files: &mut Vec<FetchedFileOwned>,
    diagnostics: &mut Vec<FetchDiagnostic>,
) -> Result<()> {
    use gix::object::tree::EntryKind;

    for entry in tree.iter() {
        let entry = entry.map_err(|e| anyhow!("failed to decode tree entry: {e}"))?;
        let filename = entry.filename().to_string();

        // REQ-096-04: reject a single path component that is unsafe *before*
        // joining it to anything.  A git tree entry's filename is a single path
        // component, but adversarial inputs may smuggle separators or `..`.
        validate_component(&filename)
            .with_context(|| format!("unsafe tree entry name {filename:?}"))?;

        let rel_path = rel_prefix.join(&filename);

        match entry.mode().kind() {
            EntryKind::Tree => {
                let subtree = entry
                    .object()
                    .map_err(|e| anyhow!("failed to read subtree {filename:?}: {e}"))?
                    .peel_to_tree()
                    .map_err(|e| anyhow!("entry {filename:?} is not a tree: {e}"))?;
                materialise_tree(
                    repo,
                    &subtree,
                    &rel_path,
                    materialised_root,
                    max_blob_bytes,
                    files,
                    diagnostics,
                )?;
            }
            EntryKind::Blob | EntryKind::BlobExecutable => {
                // REQ-096-08: check the blob size from the object header BEFORE
                // decoding it into memory, so an oversized blob never allocates.
                let oid = entry.oid().to_owned();
                let header = repo
                    .find_header(oid)
                    .map_err(|e| anyhow!("failed to read header for {filename:?}: {e}"))?;
                if header.size() > max_blob_bytes {
                    diagnostics.push(FetchDiagnostic::BlobTooLarge {
                        path: rel_path.to_string_lossy().into_owned(),
                        size: header.size(),
                        cap: max_blob_bytes,
                    });
                    continue;
                }

                let object = entry
                    .object()
                    .map_err(|e| anyhow!("failed to read blob {filename:?}: {e}"))?;
                let content = object.detach().data;

                write_materialised_file(materialised_root, &rel_path, &content)?;
                files.push(FetchedFileOwned {
                    path: rel_path,
                    content,
                });
            }
            EntryKind::Link => {
                // REQ-096-04: a symlink is NEVER followed.  We do not resolve or
                // read its target string, and we do not create a symlink on
                // disk (which could later be traversed).  It is recorded as a
                // diagnostic only.
                diagnostics.push(FetchDiagnostic::SymlinkNotFollowed(
                    rel_path.to_string_lossy().into_owned(),
                ));
            }
            EntryKind::Commit => {
                // REQ-096-04: a gitlink (submodule) is NEVER recursed into.  We
                // do not fetch or init the submodule repository.
                diagnostics.push(FetchDiagnostic::SubmoduleNotRecursed(
                    rel_path.to_string_lossy().into_owned(),
                ));
            }
        }
    }

    Ok(())
}

/// Validate a single git tree entry name (one path component).
///
/// Rejects (REQ-096-04, T-096-09 / T-096-10):
/// - empty names, `.`, `..`,
/// - any name containing a path separator (`/` or `\`) — a tree entry name is
///   supposed to be a single component; embedded separators are an escape
///   attempt,
/// - any name that looks absolute (leading separator, or a `X:` drive prefix).
fn validate_component(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("empty tree entry name");
    }
    if name == "." || name == ".." {
        bail!("tree entry name {name:?} is a path-traversal component");
    }
    if name.contains('/') || name.contains('\\') {
        bail!("tree entry name {name:?} contains a path separator");
    }
    if name.contains('\0') {
        bail!("tree entry name {name:?} contains a NUL byte");
    }
    // A bare `..` anywhere as a *component* is caught above; guard against a
    // component that is exactly `..` after trimming is unnecessary, but reject
    // a Windows drive-letter prefix that would make a joined path absolute.
    if is_windows_drive_prefix(name) {
        bail!("tree entry name {name:?} looks like an absolute Windows path");
    }
    Ok(())
}

/// Whether `url` refers to a local repository (no network host to police).
///
/// Returns `true` for `file://` URLs and for bare filesystem paths (absolute or
/// relative) that contain no `://` scheme and no SCP-style `host:path` form.
/// These open no network socket, so the host allow/deny policy — which governs
/// network egress — does not apply.  Network schemes (`https://`, `ssh://`,
/// `git://`, and SCP-style `git@host:path`) return `false` and are policed.
fn is_local_scheme(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("file://") {
        return true;
    }
    // Any explicit scheme other than file:// is treated as remote.
    if lower.contains("://") {
        return false;
    }
    // No scheme: could be a bare path (local) or SCP-style `user@host:path`
    // (remote).  SCP form has a colon that is NOT part of a Windows drive
    // letter and appears before any path separator.
    if let Some(colon) = url.find(':') {
        let before = &url[..colon];
        // Windows drive path like `C:\repo` — local.
        if is_windows_drive_prefix(url) {
            return true;
        }
        // `host:path` (no slash before the colon) — treat as remote SCP form.
        if !before.contains('/') && !before.contains('\\') {
            return false;
        }
    }
    // Bare path with no remote-looking colon — local.
    true
}

/// Whether `s` begins with a Windows drive-letter prefix like `C:` or `C:\`.
fn is_windows_drive_prefix(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Write `content` to `rel_path` under `root`, enforcing that the resolved
/// target stays strictly inside `root` (defence in depth on top of the
/// per-component validation).
fn write_materialised_file(root: &Path, rel_path: &Path, content: &[u8]) -> Result<()> {
    // Defence in depth: even though every component was validated, re-check the
    // whole relative path for traversal / absoluteness before touching disk.
    if rel_path.is_absolute() {
        bail!("refusing to write absolute path {}", rel_path.display());
    }
    for comp in rel_path.components() {
        match comp {
            Component::Normal(_) => {}
            // ParentDir == `..`, RootDir / Prefix == absolute, CurDir == `.`
            other => bail!(
                "refusing to write path {} with unsafe component {other:?}",
                rel_path.display()
            ),
        }
    }

    let target = root.join(rel_path);

    // Final belt-and-braces check: the canonical-ish parent must live under
    // `root`.  We compare without canonicalising the (not-yet-existing) target
    // file, by canonicalising the parent dir after creating it and ensuring it
    // is a descendant of the canonical root.
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create dir {}", parent.display()))?;
        let canon_root = std::fs::canonicalize(root)
            .with_context(|| format!("failed to canonicalize root {}", root.display()))?;
        let canon_parent = std::fs::canonicalize(parent)
            .with_context(|| format!("failed to canonicalize {}", parent.display()))?;
        if !canon_parent.starts_with(&canon_root) {
            bail!(
                "refusing to write {} — resolved outside fetch root",
                target.display()
            );
        }
    }

    std::fs::write(&target, content)
        .with_context(|| format!("failed to write materialised file {}", target.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- unit tests for the sandbox path validators (pure, no network) ----

    // T-096-09: path-traversal component is rejected.
    #[test]
    fn t096_09_validate_component_rejects_dotdot() {
        assert!(
            validate_component("..").is_err(),
            "T-096-09: `..` must be rejected"
        );
        assert!(
            validate_component("foo/../bar").is_err(),
            "T-096-09: embedded separator must be rejected"
        );
        assert!(
            validate_component("..\\evil").is_err(),
            "T-096-09: backslash separator must be rejected"
        );
    }

    // T-096-10: absolute-looking component is rejected.
    #[test]
    fn t096_10_validate_component_rejects_absolute() {
        assert!(
            validate_component("/etc/passwd").is_err(),
            "T-096-10: leading slash (separator) must be rejected"
        );
        assert!(
            is_windows_drive_prefix("C:\\Windows"),
            "T-096-10: drive prefix must be detected"
        );
        assert!(
            validate_component("C:\\Windows").is_err(),
            "T-096-10: Windows absolute path must be rejected"
        );
    }

    #[test]
    fn validate_component_accepts_normal_names() {
        assert!(validate_component("Cargo.toml").is_ok());
        assert!(validate_component("src").is_ok());
        assert!(validate_component(".gitignore").is_ok());
        assert!(validate_component("a.b.c").is_ok());
    }

    // T-096-09 / T-096-10: write guard rejects traversal / absolute relative paths
    // even if a component validator were somehow bypassed (defence in depth).
    #[test]
    fn write_guard_rejects_traversal_and_absolute() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let trav = Path::new("..").join("escape.txt");
        assert!(
            write_materialised_file(root, &trav, b"x").is_err(),
            "traversal relative path must be rejected by the write guard"
        );

        #[cfg(unix)]
        {
            let abs = Path::new("/tmp/dep-scan-should-not-write.txt");
            assert!(
                write_materialised_file(root, abs, b"x").is_err(),
                "absolute path must be rejected by the write guard"
            );
            assert!(
                !abs.exists(),
                "absolute path target must not have been written"
            );
        }
    }

    #[test]
    fn write_guard_writes_normal_file_under_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = Path::new("src").join("lib.rs");
        write_materialised_file(root, &rel, b"fn main() {}").unwrap();
        let written = root.join(&rel);
        assert!(written.exists());
        assert_eq!(std::fs::read(&written).unwrap(), b"fn main() {}");
    }

    // T-096-20 (optional shell-out parity) is N/A by design: per the resolved
    //   ADR-008 fetch-mechanism decision, dep-scan ships ONLY the pure-Rust gix
    //   path and intentionally omits optional `git` shell-out, so there is no
    //   second path to compare for byte-for-byte parity.
    // T-096-21 (tooling gate) is enforced by the pre-commit pipeline
    //   (cargo test / clippy -D warnings / fmt --check / audit), not a unit test.

    // =====================================================================
    // Behavioral fetch tests against a LOCAL git daemon (no real network).
    //
    // Fixtures are built with the system `git` CLI purely as a test *authoring*
    // tool, then served over `git://127.0.0.1:<port>` by a local `git daemon`.
    // The fetch under test always runs through pure-Rust gix's git:// transport
    // (the `file://` transport would shell out to `git-upload-pack`, which we
    // deliberately avoid).  No test ever connects to a public host — every URL
    // is loopback.
    // =====================================================================

    use std::net::TcpStream;
    use std::path::Path as StdPath;
    use std::process::{Child, Command};

    /// Whether the `git` CLI is available for building / serving fixtures.
    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// A local `git daemon` serving a base directory over loopback.  Killed on
    /// drop.
    struct GitDaemon {
        child: Child,
        port: u16,
    }

    impl GitDaemon {
        /// Start a daemon exporting every repo under `base` (read-only,
        /// upload-pack only), bound to an ephemeral loopback port.
        fn start(base: &StdPath) -> Option<Self> {
            // Pick a free port by binding then releasing it.
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .ok()?
                .local_addr()
                .ok()?
                .port();
            let child = Command::new("git")
                .args([
                    "daemon",
                    "--reuseaddr",
                    "--listen=127.0.0.1",
                    &format!("--port={port}"),
                    &format!("--base-path={}", base.display()),
                    "--export-all",
                    "--informative-errors",
                ])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("HOME", base)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok()?;
            let daemon = GitDaemon { child, port };
            // Wait until the port accepts connections (up to ~5s).
            for _ in 0..100 {
                if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return Some(daemon);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            None
        }

        fn url(&self, repo_name: &str) -> String {
            format!("git://127.0.0.1:{}/{repo_name}", self.port)
        }
    }

    impl Drop for GitDaemon {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn run_git(dir: &StdPath, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("HOME", dir) // isolate from the developer's ~/.gitconfig
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
        assert!(
            status.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
    }

    fn run_git_capture(dir: &StdPath, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A built fixture: a working repo, its `git://` URL, HEAD SHA, the daemon
    /// serving it, and the on-disk path of the served repo.
    struct Fixture {
        _dir: TempDir,
        _daemon: GitDaemon,
        url: String,
        head_sha: String,
        repo_path: PathBuf,
    }

    /// Build a normal repo with the given files committed and serve it over a
    /// local git daemon.  Returns `None` if a daemon could not be started (the
    /// caller then skips the test).
    fn build_repo(files: &[(&str, &[u8])]) -> Option<Fixture> {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("src-repo");
        std::fs::create_dir(&repo).unwrap();
        run_git(&repo, &["init", "-q", "-b", "main"]);
        for (rel, content) in files {
            let p = repo.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, content).unwrap();
        }
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "init"]);
        let head_sha = run_git_capture(&repo, &["rev-parse", "HEAD"]);
        let daemon = GitDaemon::start(dir.path())?;
        let url = daemon.url("src-repo");
        Some(Fixture {
            _dir: dir,
            _daemon: daemon,
            url,
            head_sha,
            repo_path: repo,
        })
    }

    /// Skip-or-unwrap a fixture: prints a skip message and returns from the test
    /// if the daemon could not be started.
    macro_rules! fixture_or_skip {
        ($fx:expr, $tc:expr) => {
            match $fx {
                Some(fx) => fx,
                None => {
                    eprintln!(concat!("skip ", $tc, ": could not start local git daemon"));
                    return;
                }
            }
        };
    }

    fn default_config() -> Config {
        Config::default()
    }

    // ---- T-096-03: fetch tree at a pinned commit SHA ----
    #[test]
    fn t096_03_fetch_at_pinned_sha() {
        if !git_available() {
            eprintln!("skip T-096-03: git CLI not available for fixture authoring");
            return;
        }
        let fx = fixture_or_skip!(
            build_repo(&[
                ("Cargo.toml", b"[package]\nname = \"x\"\n"),
                ("src/lib.rs", b"pub fn f() {}\n"),
            ]),
            "T-096-03"
        );
        let fetcher = VcsFetcher::from_config(&default_config());
        let tree = fetcher
            .fetch(&fx.url, &fx.head_sha)
            .expect("T-096-03: fetch at pinned SHA must succeed");

        let mut paths: Vec<String> = tree
            .files()
            .map(|f| f.path().to_string_lossy().replace('\\', "/"))
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            vec!["Cargo.toml".to_string(), "src/lib.rs".to_string()],
            "T-096-03: tree must contain exactly the committed files"
        );
        let lib = tree
            .files()
            .find(|f| f.path().to_string_lossy().replace('\\', "/") == "src/lib.rs")
            .unwrap();
        assert_eq!(lib.content(), b"pub fn f() {}\n", "T-096-03: blob content");
    }

    // ---- T-096-04: fetched tree is ephemeral, removed on drop ----
    #[test]
    fn t096_04_tree_cleaned_up_on_drop() {
        if !git_available() {
            eprintln!("skip T-096-04");
            return;
        }
        let fx = fixture_or_skip!(build_repo(&[("a.txt", b"hi")]), "T-096-04");
        let fetcher = VcsFetcher::from_config(&default_config());
        let root_path;
        {
            let tree = fetcher.fetch(&fx.url, &fx.head_sha).unwrap();
            root_path = tree.root();
            assert!(
                root_path.exists(),
                "materialisation root must exist while held"
            );
        }
        assert!(
            !root_path.exists(),
            "T-096-04: temp working area must be removed after FetchedTree drop"
        );
    }

    // ---- T-096-05: non-existent ref returns Err naming the ref ----
    #[test]
    fn t096_05_nonexistent_ref_errs() {
        if !git_available() {
            eprintln!("skip T-096-05");
            return;
        }
        let fx = fixture_or_skip!(build_repo(&[("a.txt", b"hi")]), "T-096-05");
        let fetcher = VcsFetcher::from_config(&default_config());
        let err = fetcher
            .fetch(&fx.url, "nonexistent-branch-xyz")
            .expect_err("T-096-05: missing ref must Err");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("nonexistent-branch-xyz"),
            "T-096-05: error must name the ref, got: {msg}"
        );
    }

    // ---- T-096-06: git hooks in the fetched repo are NEVER executed ----
    // The single most critical test in this spec.
    #[test]
    fn t096_06_hooks_never_execute() {
        if !git_available() {
            eprintln!("skip T-096-06");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("src-repo");
        std::fs::create_dir(&repo).unwrap();
        run_git(&repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("a.txt"), b"hi").unwrap();
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "init"]);
        let head = run_git_capture(&repo, &["rev-parse", "HEAD"]);

        // Plant sentinel-writing hooks for every event a careless fetch/checkout
        // could trigger.  If ANY fires, the sentinel file appears.
        let sentinel = dir.path().join("HOOK_FIRED");
        let hooks_dir = repo.join(".git").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        for hook in [
            "pre-receive",
            "post-receive",
            "update",
            "post-update",
            "post-checkout",
            "post-merge",
            "pre-push",
        ] {
            let path = hooks_dir.join(hook);
            std::fs::write(
                &path,
                format!("#!/bin/sh\ntouch '{}'\n", sentinel.display()),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }

        let daemon = match GitDaemon::start(dir.path()) {
            Some(d) => d,
            None => {
                eprintln!("skip T-096-06: could not start local git daemon");
                return;
            }
        };
        let url = daemon.url("src-repo");
        let fetcher = VcsFetcher::from_config(&default_config());
        let _ = fetcher.fetch(&url, &head); // success or failure both acceptable

        assert!(
            !sentinel.exists(),
            "T-096-06: NO git hook may execute during fetch — sentinel was created"
        );
    }

    // ---- T-096-07: submodule callbacks are never triggered ----
    #[test]
    fn t096_07_submodules_never_recursed() {
        if !git_available() {
            eprintln!("skip T-096-07");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("SUBMODULE_FIRED");

        // Build a submodule repo with a sentinel-writing checkout hook.
        let sub = dir.path().join("sub-repo");
        std::fs::create_dir(&sub).unwrap();
        run_git(&sub, &["init", "-q", "-b", "main"]);
        std::fs::write(sub.join("sub.txt"), b"sub").unwrap();
        run_git(&sub, &["add", "-A"]);
        run_git(&sub, &["commit", "-q", "-m", "s"]);

        // Build the parent repo referencing the submodule via a committed
        // .gitmodules + a gitlink (commit) tree entry.
        let parent = dir.path().join("parent-repo");
        std::fs::create_dir(&parent).unwrap();
        run_git(&parent, &["init", "-q", "-b", "main"]);
        std::fs::write(parent.join("top.txt"), b"top").unwrap();
        // -c protocol.file.allow=always permits a local file submodule add.
        run_git(
            &parent,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                sub.to_str().unwrap(),
                "vendor/sub",
            ],
        );
        run_git(&parent, &["add", "-A"]);
        run_git(&parent, &["commit", "-q", "-m", "with submodule"]);
        let head = run_git_capture(&parent, &["rev-parse", "HEAD"]);

        // Plant a post-checkout hook in the submodule that writes the sentinel,
        // so that IF our fetcher recursed and checked it out, we would see it.
        let sub_hook = sub.join(".git").join("hooks").join("post-checkout");
        std::fs::create_dir_all(sub_hook.parent().unwrap()).unwrap();
        std::fs::write(
            &sub_hook,
            format!("#!/bin/sh\ntouch '{}'\n", sentinel.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sub_hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let daemon = match GitDaemon::start(dir.path()) {
            Some(d) => d,
            None => {
                eprintln!("skip T-096-07: could not start local git daemon");
                return;
            }
        };
        let url = daemon.url("parent-repo");
        let fetcher = VcsFetcher::from_config(&default_config());
        let tree = fetcher
            .fetch(&url, &head)
            .expect("parent fetch should succeed");

        assert!(
            !sentinel.exists(),
            "T-096-07: submodule recursion must not occur — sentinel was created"
        );
        // The gitlink entry is recorded as a not-recursed diagnostic, and the
        // submodule's files are NOT in the materialised tree.
        assert!(
            tree.files()
                .all(|f| !f.path().to_string_lossy().contains("sub.txt")),
            "T-096-07: submodule contents must not be materialised"
        );
        assert!(
            tree.diagnostics()
                .iter()
                .any(|d| matches!(d, FetchDiagnostic::SubmoduleNotRecursed(_))),
            "T-096-07: a SubmoduleNotRecursed diagnostic must be recorded, got: {:?}",
            tree.diagnostics()
        );
    }

    // ---- T-096-08: symlink pointing outside the fetch root is not followed ----
    #[test]
    #[cfg(unix)]
    fn t096_08_symlink_outside_root_not_followed() {
        if !git_available() {
            eprintln!("skip T-096-08");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("src-repo");
        std::fs::create_dir(&repo).unwrap();
        run_git(&repo, &["init", "-q", "-b", "main"]);
        // Commit a symlink `evil -> /etc/passwd`.
        std::os::unix::fs::symlink("/etc/passwd", repo.join("evil")).unwrap();
        std::fs::write(repo.join("ok.txt"), b"normal").unwrap();
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "symlink"]);
        let head = run_git_capture(&repo, &["rev-parse", "HEAD"]);

        let daemon = match GitDaemon::start(dir.path()) {
            Some(d) => d,
            None => {
                eprintln!("skip T-096-08: could not start local git daemon");
                return;
            }
        };
        let url = daemon.url("src-repo");
        let fetcher = VcsFetcher::from_config(&default_config());
        let tree = fetcher.fetch(&url, &head).expect("fetch should succeed");

        // The symlink must NOT be followed: no file in the tree may contain the
        // contents of /etc/passwd, and the symlink itself is not materialised.
        for f in tree.files() {
            assert!(
                !f.content().windows(5).any(|w| w == b"root:"),
                "T-096-08: symlink target contents must never be exposed"
            );
        }
        assert!(
            !tree.root().join("evil").exists(),
            "T-096-08: symlink must not be materialised on disk"
        );
        assert!(
            tree.diagnostics()
                .iter()
                .any(|d| matches!(d, FetchDiagnostic::SymlinkNotFollowed(_))),
            "T-096-08: a SymlinkNotFollowed diagnostic must be recorded"
        );
    }

    // ---- T-096-09: path-traversal tree entry is rejected (crafted tree) ----
    #[test]
    fn t096_09_path_traversal_tree_entry_rejected() {
        if !git_available() {
            eprintln!("skip T-096-09");
            return;
        }
        // Craft a tree whose entry name is literally `..` using git plumbing,
        // which the porcelain would refuse to create.
        let (_daemon, fx_url, head) = match build_repo_with_crafted_entry("..") {
            Some(t) => t,
            None => {
                eprintln!("skip T-096-09: could not author `..` tree / start daemon");
                return;
            }
        };
        let fetcher = VcsFetcher::from_config(&default_config());
        let res = fetcher.fetch(&fx_url, &head);
        assert!(
            res.is_err(),
            "T-096-09: a `..` tree entry must produce Err, not a write"
        );
        let msg = match res {
            Ok(_) => unreachable!(),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            msg.contains("..") || msg.to_lowercase().contains("travers"),
            "T-096-09: error should mention traversal, got: {msg}"
        );
    }

    // ---- T-096-10: absolute-path tree entry is rejected (crafted tree) ----
    #[test]
    fn t096_10_absolute_path_tree_entry_rejected() {
        if !git_available() {
            eprintln!("skip T-096-10");
            return;
        }
        // git tree entry names are single components — a name with `/` cannot
        // exist in a valid git tree (git mktree rejects it), so the only
        // absolute-looking single-component name an adversary can smuggle into a
        // real tree is a Windows drive-letter prefix like `C:evil`.  Our
        // validator must reject it.  (The `/etc/passwd` leading-slash case is
        // covered by the validate_component unit test, since it can never appear
        // as a real tree entry.)
        let (_daemon, fx_url, head) = match build_repo_with_crafted_entry("C:evil") {
            Some(t) => t,
            None => {
                eprintln!("skip T-096-10: could not author `C:` tree / start daemon");
                return;
            }
        };
        let fetcher = VcsFetcher::from_config(&default_config());
        let res = fetcher.fetch(&fx_url, &head);
        assert!(
            res.is_err(),
            "T-096-10: an absolute-looking (drive-prefix) tree entry must produce Err"
        );
    }

    /// Build a repo whose root tree contains a single blob entry with the
    /// adversarial `name`, using `git mktree` / `commit-tree` plumbing so we can
    /// author names the porcelain would reject, and serve it over a daemon.
    /// Returns `(daemon, git_url, commit_sha)`, or `None` if git refused to
    /// author the name (e.g. a `/`-bearing name — invalid in a git tree) or a
    /// daemon could not start.
    fn build_repo_with_crafted_entry(name: &str) -> Option<(GitDaemon, String, String)> {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("src-repo");
        std::fs::create_dir(&repo).unwrap();
        run_git(&repo, &["init", "-q", "-b", "main"]);

        // Create a blob object by hashing a small file (avoids stdin plumbing).
        std::fs::write(repo.join("payload"), b"crafted-blob-content\n").unwrap();
        let blob = run_git_capture(&repo, &["hash-object", "-w", "payload"]);
        // mktree input: "<mode> blob <sha>\t<name>"
        let mktree_input = format!("100644 blob {blob}\t{name}\n");
        let out = Command::new("git")
            .args(["mktree"])
            .current_dir(&repo)
            .env("HOME", dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(mktree_input.as_bytes())?;
                child.wait_with_output()
            })
            .expect("git mktree failed to spawn");
        if !out.status.success() {
            // git refused this name (e.g. it contains a slash); the behavioural
            // contract for such names is covered by the validate_component unit
            // tests instead.
            return None;
        }
        let tree_sha = String::from_utf8_lossy(&out.stdout).trim().to_string();

        // commit-tree the crafted tree, then point main at it so the daemon
        // serves it under the default refspec.
        let commit = run_git_capture(&repo, &["commit-tree", &tree_sha, "-m", "crafted"]);
        run_git(&repo, &["update-ref", "refs/heads/main", &commit]);

        // Keep `dir` alive for the lifetime of the daemon by leaking it: these
        // are short-lived test fixtures and the daemon (killed on drop) holds
        // the only handle to the served path.
        let dir = Box::leak(Box::new(dir));
        let daemon = GitDaemon::start(dir.path())?;
        let url = daemon.url("src-repo");
        Some((daemon, url, commit))
    }

    // ---- T-096-11: zero-byte file does not panic ----
    #[test]
    fn t096_11_zero_byte_file_ok() {
        if !git_available() {
            eprintln!("skip T-096-11");
            return;
        }
        let fx = fixture_or_skip!(
            build_repo(&[("empty", b""), ("nonempty", b"x")]),
            "T-096-11"
        );
        let fetcher = VcsFetcher::from_config(&default_config());
        let tree = fetcher.fetch(&fx.url, &fx.head_sha).unwrap();
        let empty = tree
            .files()
            .find(|f| f.path().to_string_lossy() == "empty")
            .expect("T-096-11: empty file must be present in tree");
        assert_eq!(empty.content().len(), 0, "T-096-11: empty file size 0");
    }

    // ---- T-096-12: very large file is capped, not read into memory ----
    #[test]
    fn t096_12_large_blob_capped() {
        if !git_available() {
            eprintln!("skip T-096-12");
            return;
        }
        // Use a tiny cap so we don't actually create a 50 MB fixture.
        let mut cfg = default_config();
        cfg.vcs.max_blob_bytes = 8; // 8-byte cap
        let fx = fixture_or_skip!(
            build_repo(&[
                ("big", b"this blob is larger than eight bytes"),
                ("small", b"ok")
            ]),
            "T-096-12"
        );
        let fetcher = VcsFetcher::from_config(&cfg);
        let tree = fetcher.fetch(&fx.url, &fx.head_sha).unwrap();

        assert!(
            tree.files().all(|f| f.path().to_string_lossy() != "big"),
            "T-096-12: oversized blob must be skipped, not materialised"
        );
        assert!(
            tree.files().any(|f| f.path().to_string_lossy() == "small"),
            "T-096-12: under-cap blob must still be present"
        );
        assert!(
            tree.diagnostics()
                .iter()
                .any(|d| matches!(d, FetchDiagnostic::BlobTooLarge { .. })),
            "T-096-12: a BlobTooLarge diagnostic must be recorded"
        );
    }

    // ---- T-096-13: non-routable address fails with a clear error, no panic ----
    #[test]
    fn t096_13_network_failure_errs() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737), guaranteed non-routable.
        let mut cfg = default_config();
        cfg.vcs.fetch_timeout_secs = 3;
        let fetcher = VcsFetcher::from_config(&cfg);
        let res = fetcher.fetch("https://192.0.2.1/repo.git", "main");
        assert!(
            res.is_err(),
            "T-096-13: fetch from a non-routable host must Err"
        );
    }

    // ---- T-096-14: fetch timeout is enforced — does not hang indefinitely ----
    #[test]
    fn t096_14_timeout_enforced_on_stalling_server() {
        use std::io::Read;
        use std::net::TcpListener;

        // A TCP server that accepts the connection but never sends a byte.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let accepter = std::thread::spawn(move || {
            // Accept one connection and then stall (read forever / hold open).
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                // Block reading; never reply.  Returns when the client hangs up.
                let _ = sock.read(&mut buf);
                std::thread::sleep(Duration::from_secs(2));
            }
        });

        let mut cfg = default_config();
        cfg.vcs.fetch_timeout_secs = 2; // short, finite budget
        let fetcher = VcsFetcher::from_config(&cfg);

        let start = Instant::now();
        let res = fetcher.fetch(&format!("http://127.0.0.1:{port}/repo.git"), "main");
        let elapsed = start.elapsed();

        assert!(res.is_err(), "T-096-14: stalling fetch must Err, not hang");
        // Hard bound is timeout + 5s grace; assert we return well before any
        // "indefinite" hang.  10s is a generous ceiling for a 2s budget.
        assert!(
            elapsed < Duration::from_secs(10),
            "T-096-14: fetch must return within a finite, bounded time (took {elapsed:?})"
        );
        let _ = accepter.join();
    }

    // ---- T-096-16: host not on allow list rejected before any TCP ----
    #[test]
    fn t096_16_host_not_allowed_rejected_pre_connect() {
        let mut cfg = default_config();
        cfg.vcs.allowed_hosts = vec!["github.com".to_string()];
        let fetcher = VcsFetcher::from_config(&cfg);
        // Point at a host that, if contacted, would block for the full timeout.
        // The policy check must short-circuit before any socket is opened, so
        // this returns ~instantly with a policy error.
        let start = Instant::now();
        let res = fetcher.fetch("https://evil.example.com/repo.git", "main");
        let elapsed = start.elapsed();
        assert!(res.is_err(), "T-096-16: disallowed host must Err");
        let msg = format!("{:#}", res.unwrap_err());
        assert!(
            msg.contains("evil.example.com") && msg.contains("policy"),
            "T-096-16: error must be a policy rejection naming the host, got: {msg}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "T-096-16: policy rejection must short-circuit before any network I/O (took {elapsed:?})"
        );
    }

    // ---- T-096-17: host on deny list rejected before any TCP ----
    #[test]
    fn t096_17_host_denied_rejected_pre_connect() {
        let mut cfg = default_config();
        cfg.vcs.denied_hosts = vec!["evil.example.com".to_string()];
        let fetcher = VcsFetcher::from_config(&cfg);
        let start = Instant::now();
        let res = fetcher.fetch("https://evil.example.com/repo.git", "main");
        let elapsed = start.elapsed();
        assert!(res.is_err(), "T-096-17: denied host must Err");
        assert!(
            elapsed < Duration::from_secs(2),
            "T-096-17: deny rejection must short-circuit before network I/O"
        );
    }

    // ---- T-096-18: fetch is read-only — source repo unchanged ----
    #[test]
    fn t096_18_source_repo_unchanged() {
        if !git_available() {
            eprintln!("skip T-096-18");
            return;
        }
        let fx = fixture_or_skip!(build_repo(&[("a.txt", b"hi")]), "T-096-18");
        // Snapshot the source repo's objects + refs before the fetch.
        let before = snapshot_dir(&fx.repo_path);
        let fetcher = VcsFetcher::from_config(&default_config());
        let _tree = fetcher.fetch(&fx.url, &fx.head_sha).unwrap();
        let after = snapshot_dir(&fx.repo_path);
        assert_eq!(
            before, after,
            "T-096-18: fetch must not modify the source repository"
        );
    }

    /// Recursively snapshot (relative path -> bytes) of a directory tree.
    fn snapshot_dir(root: &StdPath) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        let mut map = std::collections::BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if meta.is_dir() {
                    stack.push(path);
                } else if meta.is_file() {
                    let rel = path.strip_prefix(root).unwrap().to_path_buf();
                    if let Ok(bytes) = std::fs::read(&path) {
                        map.insert(rel, bytes);
                    }
                }
            }
        }
        map
    }

    // ---- T-096-19: fetch works with NO `git` binary on PATH ----
    #[test]
    fn t096_19_works_without_system_git() {
        if !git_available() {
            eprintln!("skip T-096-19: need git to build the fixture");
            return;
        }
        // The daemon (a `git` process) is spawned here, BEFORE we strip PATH.
        let fx = fixture_or_skip!(
            build_repo(&[("a.txt", b"hi"), ("b.txt", b"bye")]),
            "T-096-19"
        );

        // Run the fetch with PATH pointing at an empty dir so no `git` binary is
        // resolvable.  The pure-Rust gix git:// transport must still succeed.
        let empty_dir = tempfile::tempdir().unwrap();
        let original_path = std::env::var_os("PATH");
        // SAFETY: single-threaded test; restored immediately after the fetch.
        unsafe {
            std::env::set_var("PATH", empty_dir.path());
        }
        let result = std::panic::catch_unwind(|| {
            assert!(
                which_git_on_path().is_none(),
                "precondition: no git should be resolvable on the stripped PATH"
            );
            let fetcher = VcsFetcher::from_config(&default_config());
            fetcher.fetch(&fx.url, &fx.head_sha)
        });
        // Restore PATH no matter what.
        unsafe {
            match original_path {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
        }
        let tree = result
            .expect("T-096-19: fetch must not panic without git on PATH")
            .expect("T-096-19: pure-Rust fetch must succeed without a git binary");
        assert_eq!(
            tree.len(),
            2,
            "T-096-19: fetch without git must still produce the tree"
        );
    }

    /// Resolve `git` on the current PATH, if any.
    fn which_git_on_path() -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            for name in ["git", "git.exe"] {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        None
    }
}

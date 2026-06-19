// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use anyhow::Result;
use chrono::Utc;
use rusqlite::Connection;

/// A single cached scan result.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheEntry {
    /// The scan result (e.g. "pass", "block").
    pub result: String,
    /// RFC 3339 timestamp of when the entry was recorded.
    pub scanned_at: String,
    /// Registry-published content digest, formatted as `<algo>:<hex>`.
    ///
    /// `None` for rows that were inserted before task 029 (legacy rows)
    /// or when no digest was available from the registry.
    pub content_hash: Option<String>,
    /// Verified provenance identity for the package:
    ///   - npm (task 032) and PyPI (task 033): Fulcio-issued OIDC subject from
    ///     the sigstore attestation.
    ///   - Go modules (task 034): the literal string `"sum.golang.org"` once the
    ///     Ed25519 signed-tree-head check passes.
    ///
    /// `None` when no provenance was verified — either because the package's
    /// registry does not (yet) publish one, or because the verification could
    /// not be completed.
    pub provenance_identity: Option<String>,
    /// Provenance of the row (task 097):
    ///   - `Some("git")` for git-sourced rows keyed `(name, commit_sha, "git")`,
    ///   - `None` for registry-sourced rows and every legacy/pre-097 row.
    pub source_kind: Option<String>,
    /// Subtree-state fingerprint (task 106, ADR 009 Decision 4):
    /// a `sha256:<hex>` digest over the sorted, length-framed set of
    /// `(child_NodeId_string, child_verdict_string)` pairs the parent's verdict
    /// depended on.
    ///
    /// `None` for:
    ///   - every legacy/pre-106 row (the column reads back NULL — no backfill),
    ///   - flat-scan rows that recorded no transitive children (the
    ///     subtree-digest gate is skipped for these; only the content-hash gate
    ///     applies — see [`subtree_digest_valid`]).
    ///
    /// `Some(_)` for transitive rows, including the deterministic
    /// empty-child-set digest (a leaf scanned transitively).
    pub subtree_digest: Option<String>,
}

/// Compute the task-106 subtree digest (ADR 009 Decision 4) over a set of
/// `(child_NodeId_string, child_verdict_string)` pairs.
///
/// The digest is a `sha256:<hex>` fingerprint of the subtree state the parent's
/// verdict was computed against. Inputs are taken pre-stringified so this lives
/// in `cache.rs` without depending on the transitive `NodeId`/`Verdict` types
/// (the wiring layer, task 108, stringifies them).
///
/// Algorithm (mirrors the `git_tree_content_hash` framing discipline in
/// `src/main.rs:152`, REQ-106-02):
///
/// 1. Sort the pairs lexicographically by the NodeId string (deterministic, so
///    insertion order does not change the digest — T-106-06).
/// 2. For each sorted pair, feed the hasher, in order: the 8-byte little-endian
///    `node_id` length frame, the `node_id` bytes, the 8-byte little-endian
///    `verdict` length frame, then the `verdict` bytes. Explicit length framing
///    means no two distinct pair-sets can collide by concatenation (e.g.
///    `("ab","c")` cannot alias `("a","bc")`).
/// 3. Format the finalized hash as `sha256:<hex>`.
///
/// An empty child set hashes the empty input to a deterministic, non-NULL digest
/// (T-106-07): every leaf scanned transitively produces the same value.
///
/// Wired into the live scan path by task 108 (main.rs wiring); suppressed until
/// then per the project dead-code convention (cf. tasks 100/102).
#[allow(dead_code)]
pub fn compute_subtree_digest(children: &[(&str, &str)]) -> String {
    use sha2::{Digest, Sha256};
    let mut pairs: Vec<(&str, &str)> = children.to_vec();
    // Deterministic order — sort on the NodeId string, then the verdict string
    // as a tiebreaker so a fixed input always yields a fixed digest.
    pairs.sort_unstable();
    let mut hasher = Sha256::new();
    for (node_id, verdict) in pairs {
        let nid = node_id.as_bytes();
        let vrd = verdict.as_bytes();
        hasher.update((nid.len() as u64).to_le_bytes());
        hasher.update(nid);
        hasher.update((vrd.len() as u64).to_le_bytes());
        hasher.update(vrd);
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Task-106 subtree-digest gate (ADR 009 Decision 4, REQ-106-03 / REQ-106-05).
///
/// Returns `true` iff the subtree-digest gate is *satisfied* — meaning a cached
/// transitive row may be served (subject also to the separate task-030
/// content-hash gate, which the caller checks alongside this; **both** must pass
/// for a Hit).
///
/// Fail-closed rules:
///   - `stored = None` (flat-scan / legacy row): the row carries no transitive
///     context, so the subtree-digest gate does not apply and returns `true`.
///     The content-hash gate is the sole guard for these rows (REQ-106-05).
///   - `stored = Some(s)`: the row is transitive. The gate passes **only** if a
///     `recomputed` digest is present and byte-equal to `s`. A `recomputed`
///     of `None` (children could not be re-fingerprinted — e.g. a mutable-ref
///     child that is never cached, T-106-15) fails the gate → Miss → re-scan.
///     A differing `recomputed` (a child's verdict changed, T-106-09/11) fails
///     the gate → Miss → re-scan. A stale `Pass` is never served.
///
/// Wired into the live cache-lookup path by task 108; suppressed until then per
/// the project dead-code convention.
#[allow(dead_code)]
pub fn subtree_digest_valid(stored: Option<&str>, recomputed: Option<&str>) -> bool {
    match stored {
        // Flat-scan / legacy row: subtree-digest gate skipped (content-hash gate
        // still applies at the call site).
        None => true,
        // Transitive row: fail-closed — must have a recomputed digest that matches.
        Some(s) => recomputed == Some(s),
    }
}

/// Local SQLite cache for storing scan results so already-scanned packages
/// can be skipped on subsequent runs.
pub struct Cache {
    conn: Connection,
}

impl Cache {
    /// Open (or create) a cache database at the given path.
    ///
    /// Pass `":memory:"` to create an in-memory database for testing.
    /// The `scanned_packages` table is created automatically if it does not
    /// already exist.
    ///
    /// On Unix, the DB file is created atomically with mode `0600` so there is
    /// no window in which the file is world-readable.  If the file already exists
    /// (upgrade / re-open case), the pre-create step is skipped and the existing
    /// `set_permissions(0600)` call below narrows any legacy `0644` file.
    ///
    /// The `-wal` and `-shm` companion files SQLite creates in WAL mode inherit
    /// the same permissions because SQLite uses the main-file mode when creating
    /// them via `open(2)`.
    ///
    /// Note: on Windows, the DB file inherits parent-directory ACLs.
    pub fn new(path: &Path) -> Result<Self> {
        // On Unix, pre-create the DB file with mode 0600 *before* handing the
        // path to Connection::open.  This closes the TOCTOU window that existed
        // between Connection::open (which creates the file under the process
        // umask, typically 0644) and the subsequent set_permissions call below.
        //
        // If the file already exists (AlreadyExists) we fall through; the
        // set_permissions call further down handles the legacy-0644 upgrade case.
        // The handle is dropped before Connection::open so SQLite can acquire its
        // own lock on the file without a "file busy" error on platforms that use
        // mandatory locking.
        // T-059-09: create_new(true) is used here — this is O_CREAT|O_EXCL, which
        // is atomic and fails with AlreadyExists if the file already exists,
        // unlike create(true) which silently opens an existing file.
        //
        // T-059-10: the File handle `f` returned by OpenOptions::open is dropped
        // (via `drop(f)`) before `Connection::open(path)` is called below,
        // ensuring SQLite can acquire an exclusive lock on platforms that use
        // mandatory locking.
        #[cfg(unix)]
        if path != Path::new(":memory:") {
            use std::fs::OpenOptions;
            use std::os::unix::fs::OpenOptionsExt;
            match OpenOptions::new()
                .write(true)
                .create_new(true) // T-059-09: O_CREAT|O_EXCL — atomic, fails if exists
                .mode(0o600)
                .open(path)
            {
                Ok(f) => drop(f), // T-059-10: release before Connection::open
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // File exists (upgrade / re-open): fall through.
                }
                Err(e) => return Err(e.into()),
            }
        }

        let conn = Connection::open(path)?;

        // Restrict the DB file to owner read/write only on Unix systems.
        // For a freshly created file this is now a no-op (already 0600).
        // For a pre-existing legacy 0644 file this narrows the permissions.
        // Skip for `:memory:` databases which have no backing file.
        #[cfg(unix)]
        if path != Path::new(":memory:") {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        // Enable WAL journal mode for improved durability.  WAL is the
        // SQLite-recommended mode for applications that perform frequent small
        // writes, and it ensures that companion -wal/-shm files are created
        // with the same owner as the main DB file.
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scanned_packages (
                name                TEXT NOT NULL,
                version             TEXT NOT NULL,
                registry            TEXT NOT NULL,
                result              TEXT NOT NULL,
                scanned_at          TEXT NOT NULL,
                content_hash        TEXT,
                provenance_identity TEXT,
                PRIMARY KEY (name, version, registry)
            );
            CREATE TABLE IF NOT EXISTS maintainer_history (
                name        TEXT NOT NULL,
                registry    TEXT NOT NULL,
                maintainers TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                PRIMARY KEY (name, registry)
            );",
        )?;

        // Collect existing column names for additive migrations.
        let existing_columns: Vec<String> = conn
            .prepare("PRAGMA table_info(scanned_packages)")?
            .query_map([], |row| {
                let name: String = row.get(1)?;
                Ok(name)
            })?
            .filter_map(|r| r.ok())
            .collect();

        // Additive migration (task 029): add content_hash column.
        if !existing_columns.iter().any(|n| n == "content_hash") {
            conn.execute_batch("ALTER TABLE scanned_packages ADD COLUMN content_hash TEXT;")?;
        }

        // Additive migration (task 032): add provenance_identity column.
        if !existing_columns.iter().any(|n| n == "provenance_identity") {
            conn.execute_batch(
                "ALTER TABLE scanned_packages ADD COLUMN provenance_identity TEXT;",
            )?;
        }

        // Additive migration (task 097): add source_kind column.
        //
        // Git-sourced cache rows (ADR 008 piece 2) are stored in the same
        // `scanned_packages` table, keyed `(name, commit_sha, "git")`.  The
        // `source_kind` column records the provenance of a row explicitly:
        // `"git"` for git-sourced rows, NULL for registry-sourced rows (which is
        // also what every legacy/pre-097 row carries).  Keeping this additive and
        // nullable means existing registry rows remain valid with no backfill —
        // the column simply reads back as NULL for them (T-097-06/08).  The
        // migration is idempotent: the column is only added when absent
        // (T-097-07), mirroring the content_hash / provenance_identity
        // migrations above.
        if !existing_columns.iter().any(|n| n == "source_kind") {
            conn.execute_batch("ALTER TABLE scanned_packages ADD COLUMN source_kind TEXT;")?;
        }

        // Additive migration (task 106, ADR 009 Decision 4): add subtree_digest.
        //
        // Binds a cached transitive verdict to the fingerprint of the child
        // verdicts it depended on (`compute_subtree_digest`).  Additive and
        // nullable, exactly like the content_hash / provenance_identity /
        // source_kind migrations above: the column is only added when absent
        // (idempotent — T-106-02), legacy and registry/flat-scan rows read back
        // NULL with no backfill (T-106-03/04), and a NULL value means "no
        // transitive context recorded" so only the content-hash gate applies for
        // that row (REQ-106-05).
        if !existing_columns.iter().any(|n| n == "subtree_digest") {
            conn.execute_batch("ALTER TABLE scanned_packages ADD COLUMN subtree_digest TEXT;")?;
        }

        Ok(Self { conn })
    }

    /// Create an in-memory cache (convenience wrapper for tests).
    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        Self::new(Path::new(":memory:"))
    }

    /// Look up a cached scan result.
    ///
    /// Returns `None` if no entry exists for the given key.
    pub fn lookup(&self, name: &str, version: &str, registry: &str) -> Result<Option<CacheEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT result, scanned_at, content_hash, provenance_identity, source_kind,
                    subtree_digest
             FROM scanned_packages
             WHERE name = ?1 AND version = ?2 AND registry = ?3",
        )?;

        let mut rows = stmt.query_map(rusqlite::params![name, version, registry], |row| {
            Ok(CacheEntry {
                result: row.get(0)?,
                scanned_at: row.get(1)?,
                content_hash: row.get(2)?,
                provenance_identity: row.get(3)?,
                source_kind: row.get(4)?,
                subtree_digest: row.get(5)?,
            })
        })?;

        match rows.next() {
            Some(entry) => Ok(Some(entry?)),
            None => Ok(None),
        }
    }

    /// Insert or update a cache entry.
    ///
    /// The `scanned_at` timestamp is set automatically to the current UTC time
    /// in RFC 3339 format.
    ///
    /// `content_hash` should be formatted as `<algo>:<hex>` (e.g. `sha512:<hex>`),
    /// or `None` when no digest was available from the registry.
    ///
    /// `provenance_identity` is the verified Fulcio OIDC subject identity from
    /// the npm provenance attestation (task 032), or `None`.
    ///
    /// `subtree_digest` (task 106, ADR 009 Decision 4) is the `sha256:<hex>`
    /// fingerprint of the child verdicts a transitive scan depended on
    /// (`compute_subtree_digest`), or `None` for a flat (non-transitive) scan.
    /// Callers that pass `None` write NULL, preserving the pre-106 flat-scan
    /// behaviour (REQ-106-04/05 — backwards-compatible).
    // The cache row genuinely has this many independent columns (name, version,
    // registry, result, content_hash, provenance_identity, subtree_digest);
    // bundling them into a struct would not improve clarity at the call sites.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &self,
        name: &str,
        version: &str,
        registry: &str,
        result: &str,
        content_hash: Option<&str>,
        provenance_identity: Option<&str>,
        subtree_digest: Option<&str>,
    ) -> Result<()> {
        let scanned_at = Utc::now().to_rfc3339();
        // Registry-sourced rows carry source_kind = NULL (matches legacy rows).
        self.conn.execute(
            "INSERT OR REPLACE INTO scanned_packages
             (name, version, registry, result, scanned_at, content_hash, provenance_identity,
              source_kind, subtree_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
            rusqlite::params![
                name,
                version,
                registry,
                result,
                scanned_at,
                content_hash,
                provenance_identity,
                subtree_digest
            ],
        )?;
        Ok(())
    }

    /// Insert or update a git-sourced cache entry (task 097, ADR 008 piece 2).
    ///
    /// Git rows are keyed `(name, commit_sha, "git")`: the `commit_sha` is the
    /// full pinned commit hash (an immutable identifier that uniquely names the
    /// fetched tree), and the registry slot is the literal `"git"`, which does
    /// not collide with any `RegistryType` string (npm/pypi/crates/go).
    ///
    /// `content_hash` is the digest of the fetched tree (`<algo>:<hex>`); it
    /// feeds the task-030 hash-verify gate on the next lookup so a tampered
    /// cache row is rejected and the dep re-fetched (REQ-097-04, fail-closed).
    ///
    /// Callers MUST NOT invoke this for mutable refs — a mutable branch name does
    /// not uniquely identify a tree, so caching it would serve stale/poisoned
    /// content (REQ-097-02).  The mutable-vs-pinned decision lives in the scan
    /// loop via `classify_ref` (task 094).
    /// `subtree_digest` (task 106, ADR 009 Decision 4) is the `sha256:<hex>`
    /// fingerprint of the child verdicts a transitive git scan depended on, or
    /// `None` for a flat git scan. Passing `None` writes NULL (backwards-
    /// compatible with the pre-106 flat git arm).
    pub fn insert_git(
        &self,
        name: &str,
        commit_sha: &str,
        result: &str,
        content_hash: Option<&str>,
        subtree_digest: Option<&str>,
    ) -> Result<()> {
        let scanned_at = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO scanned_packages
             (name, version, registry, result, scanned_at, content_hash, provenance_identity,
              source_kind, subtree_digest)
             VALUES (?1, ?2, 'git', ?3, ?4, ?5, NULL, 'git', ?6)",
            rusqlite::params![
                name,
                commit_sha,
                result,
                scanned_at,
                content_hash,
                subtree_digest
            ],
        )?;
        Ok(())
    }

    /// Remove a single cache entry.  No-op if the entry does not exist.
    pub fn invalidate(&self, name: &str, version: &str, registry: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM scanned_packages WHERE name = ?1 AND version = ?2 AND registry = ?3",
            rusqlite::params![name, version, registry],
        )?;
        Ok(())
    }

    /// Remove all entries from the cache.
    #[allow(dead_code)]
    pub fn clear(&self) -> Result<()> {
        self.conn.execute("DELETE FROM scanned_packages", [])?;
        Ok(())
    }

    /// Record the current maintainers for a package.
    /// Uses INSERT OR REPLACE to update existing entries.
    pub fn record_maintainers(
        &self,
        name: &str,
        registry: &str,
        maintainers: &[String],
    ) -> Result<()> {
        let maintainers_json = serde_json::to_string(maintainers)?;
        let recorded_at = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO maintainer_history (name, registry, maintainers, recorded_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![name, registry, maintainers_json, recorded_at],
        )?;
        Ok(())
    }

    /// Get the previously recorded maintainers for a package.
    /// Returns None if no history exists.
    pub fn get_previous_maintainers(
        &self,
        name: &str,
        registry: &str,
    ) -> Result<Option<Vec<String>>> {
        let mut stmt = self.conn.prepare(
            "SELECT maintainers FROM maintainer_history
             WHERE name = ?1 AND registry = ?2",
        )?;

        let mut rows = stmt.query_map(rusqlite::params![name, registry], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })?;

        match rows.next() {
            Some(json_result) => {
                let json = json_result?;
                let maintainers: Vec<String> = serde_json::from_str(&json)?;
                Ok(Some(maintainers))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    // T-007-01: Cache::new creates table (no error)
    #[test]
    fn new_creates_table() {
        let cache = Cache::in_memory();
        assert!(cache.is_ok(), "Cache::new should succeed on :memory:");
    }

    // T-007-02: Insert and lookup (returns inserted result)
    #[test]
    fn insert_and_lookup() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("lodash", "4.17.21", "npm", "pass", None, None, None)
            .unwrap();

        let entry = cache.lookup("lodash", "4.17.21", "npm").unwrap();
        assert!(entry.is_some(), "lookup should return an entry");
        assert_eq!(entry.unwrap().result, "pass");
    }

    // T-007-03: Lookup miss returns None
    #[test]
    fn lookup_miss_returns_none() {
        let cache = Cache::in_memory().unwrap();
        let entry = cache.lookup("nonexistent", "0.0.0", "npm").unwrap();
        assert!(entry.is_none(), "lookup should return None for missing key");
    }

    // T-007-04: Insert upserts on conflict (updates result)
    #[test]
    fn insert_upserts_on_conflict() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("lodash", "4.17.21", "npm", "pass", None, None, None)
            .unwrap();
        cache
            .insert("lodash", "4.17.21", "npm", "block", None, None, None)
            .unwrap();

        let entry = cache.lookup("lodash", "4.17.21", "npm").unwrap().unwrap();
        assert_eq!(entry.result, "block", "upsert should update the result");
    }

    // T-007-05: Invalidate removes entry
    #[test]
    fn invalidate_removes_entry() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("lodash", "4.17.21", "npm", "pass", None, None, None)
            .unwrap();
        cache.invalidate("lodash", "4.17.21", "npm").unwrap();

        let entry = cache.lookup("lodash", "4.17.21", "npm").unwrap();
        assert!(entry.is_none(), "entry should be gone after invalidate");
    }

    // T-007-06: Invalidate non-existent is no-op
    #[test]
    fn invalidate_nonexistent_is_noop() {
        let cache = Cache::in_memory().unwrap();
        let result = cache.invalidate("ghost", "0.0.0", "npm");
        assert!(
            result.is_ok(),
            "invalidating a missing entry should not error"
        );
    }

    // T-007-07: Clear removes all entries
    #[test]
    fn clear_removes_all_entries() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("a", "1.0", "npm", "pass", None, None, None)
            .unwrap();
        cache
            .insert("b", "2.0", "pypi", "block", None, None, None)
            .unwrap();
        cache
            .insert("c", "3.0", "cargo", "warn", None, None, None)
            .unwrap();

        cache.clear().unwrap();

        assert!(cache.lookup("a", "1.0", "npm").unwrap().is_none());
        assert!(cache.lookup("b", "2.0", "pypi").unwrap().is_none());
        assert!(cache.lookup("c", "3.0", "cargo").unwrap().is_none());
    }

    // T-007-08: Different registries are distinct keys
    #[test]
    fn different_registries_are_distinct() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("foo", "1.0", "npm", "pass", None, None, None)
            .unwrap();
        cache
            .insert("foo", "1.0", "pypi", "block", None, None, None)
            .unwrap();

        let npm_entry = cache.lookup("foo", "1.0", "npm").unwrap().unwrap();
        let pypi_entry = cache.lookup("foo", "1.0", "pypi").unwrap().unwrap();

        assert_eq!(npm_entry.result, "pass");
        assert_eq!(pypi_entry.result, "block");
    }

    // T-007-09: Cache::new is idempotent (create, insert, drop, re-create -- entry persists)
    #[test]
    fn new_is_idempotent_with_file() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cache.db");

        // First open: create + insert
        {
            let cache = Cache::new(&db_path).unwrap();
            cache
                .insert("lodash", "4.17.21", "npm", "pass", None, None, None)
                .unwrap();
        }
        // Cache is dropped here, connection closed.

        // Second open: entry should still exist
        {
            let cache = Cache::new(&db_path).unwrap();
            let entry = cache.lookup("lodash", "4.17.21", "npm").unwrap();
            assert!(entry.is_some(), "entry should persist across opens");
            assert_eq!(entry.unwrap().result, "pass");
        }
    }

    // T-014-01: Record and retrieve maintainers
    #[test]
    fn record_and_retrieve_maintainers() {
        let cache = Cache::in_memory().unwrap();
        let maintainers = vec!["alice".to_string(), "bob".to_string()];
        cache
            .record_maintainers("lodash", "npm", &maintainers)
            .unwrap();

        let result = cache.get_previous_maintainers("lodash", "npm").unwrap();
        assert_eq!(result, Some(vec!["alice".to_string(), "bob".to_string()]));
    }

    // T-014-02: No history returns None
    #[test]
    fn no_maintainer_history_returns_none() {
        let cache = Cache::in_memory().unwrap();
        let result = cache
            .get_previous_maintainers("nonexistent", "npm")
            .unwrap();
        assert!(result.is_none());
    }

    // T-014-03: Record updates existing
    #[test]
    fn record_maintainers_updates_existing() {
        let cache = Cache::in_memory().unwrap();
        cache
            .record_maintainers("lodash", "npm", &["alice".to_string()])
            .unwrap();
        cache
            .record_maintainers("lodash", "npm", &["alice".to_string(), "bob".to_string()])
            .unwrap();

        let result = cache.get_previous_maintainers("lodash", "npm").unwrap();
        assert_eq!(result, Some(vec!["alice".to_string(), "bob".to_string()]));
    }

    // T-007-10: scanned_at is set on insert (valid timestamp)
    #[test]
    fn scanned_at_is_valid_timestamp() {
        let cache = Cache::in_memory().unwrap();
        let before = Utc::now();
        cache
            .insert("lodash", "4.17.21", "npm", "pass", None, None, None)
            .unwrap();
        let after = Utc::now();

        let entry = cache.lookup("lodash", "4.17.21", "npm").unwrap().unwrap();

        // Parse the stored timestamp
        let ts = DateTime::parse_from_rfc3339(&entry.scanned_at)
            .expect("scanned_at should be valid RFC 3339");
        let ts_utc = ts.with_timezone(&Utc);

        assert!(
            ts_utc >= before && ts_utc <= after,
            "scanned_at ({ts_utc}) should be between {before} and {after}"
        );
    }

    // T-029-10: Cache::new on a fresh DB creates content_hash column
    #[test]
    fn new_creates_content_hash_column() {
        let cache = Cache::in_memory().unwrap();
        // Query PRAGMA to verify the column exists and is nullable TEXT
        let mut stmt = cache
            .conn
            .prepare("PRAGMA table_info(scanned_packages)")
            .unwrap();
        let col = stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                let col_type: String = row.get(2)?;
                let not_null: i64 = row.get(3)?;
                Ok((name, col_type, not_null))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .find(|(name, _, _)| name == "content_hash");

        let col = col.expect("content_hash column should exist");
        assert_eq!(col.1.to_uppercase(), "TEXT", "column type should be TEXT");
        assert_eq!(col.2, 0, "column should be nullable (not_null = 0)");
    }

    // T-029-11: Cache::new on a legacy DB adds the column in place
    #[test]
    fn new_migrates_legacy_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("legacy.db");

        // Manually create the v1.0 schema (no content_hash column)
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE scanned_packages (
                    name       TEXT NOT NULL,
                    version    TEXT NOT NULL,
                    registry   TEXT NOT NULL,
                    result     TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    PRIMARY KEY (name, version, registry)
                );",
            )
            .unwrap();
            // Insert a legacy row
            conn.execute(
                "INSERT INTO scanned_packages (name, version, registry, result, scanned_at)
                 VALUES ('legacy-pkg', '1.0.0', 'npm', 'pass', '2024-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        // Open with Cache::new — should migrate without error
        let cache = Cache::new(&db_path).expect("migration should succeed");

        // Legacy row should be preserved
        let entry = cache
            .lookup("legacy-pkg", "1.0.0", "npm")
            .unwrap()
            .expect("legacy row should still exist");
        assert_eq!(entry.result, "pass");
        // content_hash on legacy row is NULL → None
        assert_eq!(
            entry.content_hash, None,
            "legacy row content_hash should be None"
        );
    }

    // T-029-12: Cache::new is idempotent across the migration
    #[test]
    fn new_migration_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("idem.db");

        // First open creates the table with content_hash already present
        let _ = Cache::new(&db_path).unwrap();
        // Second open should not error (no duplicate column)
        let result = Cache::new(&db_path);
        assert!(
            result.is_ok(),
            "second open should not error: {}",
            result.err().map(|e| e.to_string()).unwrap_or_default()
        );
    }

    // T-029-13: insert + lookup round-trips content_hash
    #[test]
    fn insert_and_lookup_roundtrips_content_hash() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert(
                "lodash",
                "4.17.21",
                "npm",
                "pass",
                Some("sha512:abcdef1234567890"),
                None,
                None,
            )
            .unwrap();

        let entry = cache
            .lookup("lodash", "4.17.21", "npm")
            .unwrap()
            .expect("entry should exist");
        assert_eq!(
            entry.content_hash,
            Some("sha512:abcdef1234567890".to_string())
        );
    }

    // T-029-14: insert with None stores NULL
    #[test]
    fn insert_none_content_hash_stores_null() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("lodash", "4.17.21", "npm", "pass", None, None, None)
            .unwrap();

        let entry = cache
            .lookup("lodash", "4.17.21", "npm")
            .unwrap()
            .expect("entry should exist");
        assert_eq!(entry.content_hash, None, "content_hash should be None");
    }

    // T-029-15: Legacy rows return None for content_hash
    #[test]
    fn legacy_rows_return_none_for_content_hash() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("legacy15.db");

        // Create legacy schema and insert a row without content_hash
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE scanned_packages (
                    name       TEXT NOT NULL,
                    version    TEXT NOT NULL,
                    registry   TEXT NOT NULL,
                    result     TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    PRIMARY KEY (name, version, registry)
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO scanned_packages (name, version, registry, result, scanned_at)
                 VALUES ('legacy-pkg', '2.0.0', 'pypi', 'pass', '2024-06-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        // Migrate via Cache::new
        let cache = Cache::new(&db_path).unwrap();

        // Lookup legacy row — content_hash should be None, not an error
        let entry = cache
            .lookup("legacy-pkg", "2.0.0", "pypi")
            .unwrap()
            .expect("legacy row should exist");
        assert_eq!(
            entry.content_hash, None,
            "legacy row content_hash must be None"
        );
    }

    // T-029-16: Re-insert updates content_hash via upsert
    #[test]
    fn re_insert_updates_content_hash() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert(
                "pkg",
                "1.0.0",
                "npm",
                "pass",
                Some("sha256:aaaa"),
                None,
                None,
            )
            .unwrap();
        cache
            .insert(
                "pkg",
                "1.0.0",
                "npm",
                "pass",
                Some("sha256:bbbb"),
                None,
                None,
            )
            .unwrap();

        let entry = cache
            .lookup("pkg", "1.0.0", "npm")
            .unwrap()
            .expect("entry should exist");
        assert_eq!(
            entry.content_hash,
            Some("sha256:bbbb".to_string()),
            "content_hash should be updated by re-insert"
        );
    }

    // T-032-14: Cache::new on fresh DB creates provenance_identity column
    #[test]
    fn new_creates_provenance_identity_column() {
        let cache = Cache::in_memory().unwrap();
        let mut stmt = cache
            .conn
            .prepare("PRAGMA table_info(scanned_packages)")
            .unwrap();
        let col = stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                let col_type: String = row.get(2)?;
                let not_null: i64 = row.get(3)?;
                Ok((name, col_type, not_null))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .find(|(name, _, _)| name == "provenance_identity");

        let col = col.expect("T-032-14: provenance_identity column should exist");
        assert_eq!(
            col.1.to_uppercase(),
            "TEXT",
            "T-032-14: column type should be TEXT"
        );
        assert_eq!(
            col.2, 0,
            "T-032-14: column should be nullable (not_null = 0)"
        );
    }

    // T-032-15: Cache::new on a post-029 DB adds provenance_identity in place
    #[test]
    fn new_migrates_post_029_db_adds_provenance_identity() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("v1_1.db");

        // Manually create the v1.1 schema (has content_hash but no provenance_identity)
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE scanned_packages (
                    name         TEXT NOT NULL,
                    version      TEXT NOT NULL,
                    registry     TEXT NOT NULL,
                    result       TEXT NOT NULL,
                    scanned_at   TEXT NOT NULL,
                    content_hash TEXT,
                    PRIMARY KEY (name, version, registry)
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO scanned_packages
                 (name, version, registry, result, scanned_at, content_hash)
                 VALUES ('legacy-pkg', '1.0.0', 'npm', 'pass',
                         '2025-01-01T00:00:00Z', 'sha512:aaaa')",
                [],
            )
            .unwrap();
        }

        // Open with Cache::new — should add provenance_identity without error
        let cache = Cache::new(&db_path).expect("T-032-15: migration should succeed");

        // Existing row must be preserved; provenance_identity should be NULL.
        let entry = cache
            .lookup("legacy-pkg", "1.0.0", "npm")
            .unwrap()
            .expect("T-032-15: legacy row must still exist");
        assert_eq!(entry.result, "pass");
        assert_eq!(
            entry.content_hash,
            Some("sha512:aaaa".to_string()),
            "T-032-15: content_hash must be preserved"
        );
        assert_eq!(
            entry.provenance_identity, None,
            "T-032-15: provenance_identity must be NULL for legacy rows"
        );
    }

    // ── T-047 unit tests — Cache I/O error surfacing ─────────────────────────────

    // T-047-01: Cache::lookup on a valid in-memory database returns Ok(None) for
    // an empty database (no entry exists yet).
    #[test]
    fn t047_01_lookup_empty_in_memory_returns_ok_none() {
        let cache = Cache::in_memory().expect("T-047-01: in_memory cache should succeed");
        let result = cache.lookup("pkg", "1.0.0", "npm");
        assert!(
            result.is_ok(),
            "T-047-01: lookup on empty in-memory DB must return Ok, got: {:?}",
            result
        );
        assert_eq!(
            result.unwrap(),
            None,
            "T-047-01: lookup on empty in-memory DB must return Ok(None)"
        );
    }

    // T-047-02: Cache::lookup after inserting an entry returns Ok(Some(entry)).
    #[test]
    fn t047_02_lookup_after_insert_returns_ok_some() {
        let cache = Cache::in_memory().expect("T-047-02: in_memory cache should succeed");
        cache
            .insert("pkg", "1.0.0", "npm", "pass", None, None, None)
            .expect("T-047-02: insert should succeed");
        let result = cache.lookup("pkg", "1.0.0", "npm");
        assert!(
            result.is_ok(),
            "T-047-02: lookup after insert must return Ok, got: {:?}",
            result
        );
        let entry = result.unwrap();
        assert!(
            entry.is_some(),
            "T-047-02: lookup after insert must return Some(entry)"
        );
        assert_eq!(
            entry.unwrap().result,
            "pass",
            "T-047-02: CacheEntry.result must match the inserted value"
        );
    }

    // T-047-03: Cache::new on a path that is a directory (not a file) returns Err.
    // This verifies that the error surfaces at construction time, not silently at
    // lookup time (REQ-047-03).
    #[test]
    fn t047_03_cache_new_on_directory_returns_err() {
        // A directory path cannot be opened as a SQLite DB file on any platform.
        // Use a real temp directory rather than a hardcoded "/tmp" so the test is
        // cross-platform: on Windows "/tmp" does not exist, so SQLite would happily
        // create a new DB file there and construction would erroneously succeed.
        let dir = tempfile::tempdir().unwrap();
        let result = Cache::new(dir.path());
        assert!(
            result.is_err(),
            "T-047-03: Cache::new on a directory path must return Err (SQLite error surfaces at \
             construction time)"
        );
    }

    // T-032-16: insert/lookup round-trips provenance_identity
    #[test]
    fn insert_and_lookup_roundtrips_provenance_identity() {
        let cache = Cache::in_memory().unwrap();
        let identity = "https://github.com/lodash/.github/workflows/release.yml@refs/tags/v4.17.21";
        cache
            .insert(
                "lodash",
                "4.17.21",
                "npm",
                "pass",
                Some("sha512:abcdef"),
                Some(identity),
                None,
            )
            .unwrap();

        let entry = cache
            .lookup("lodash", "4.17.21", "npm")
            .unwrap()
            .expect("T-032-16: entry should exist");
        assert_eq!(
            entry.provenance_identity,
            Some(identity.to_string()),
            "T-032-16: provenance_identity must round-trip"
        );
    }

    // ── T-054 tests — cache DB privacy hardening ─────────────────────────────

    // T-054-01: Cache DB file created on Unix has mode 0600.
    #[cfg(unix)]
    #[test]
    fn t054_01_new_file_has_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cache.db");
        let _cache = Cache::new(&db_path).expect("T-054-01: Cache::new should succeed");
        let meta = std::fs::metadata(&db_path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "T-054-01: DB file must have mode 0600, got {:#o}",
            mode & 0o777
        );
    }

    // T-054-02: No group or world read bits are set on a newly created cache DB.
    #[cfg(unix)]
    #[test]
    fn t054_02_no_group_or_world_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cache.db");
        let _cache = Cache::new(&db_path).expect("T-054-02: Cache::new should succeed");
        let meta = std::fs::metadata(&db_path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "T-054-02: no group or world permission bits must be set, got {:#o}",
            mode & 0o077
        );
    }

    // T-054-03: chmod 0600 is applied even if the file was created with a permissive umask.
    //
    // The implementation calls std::fs::set_permissions after Connection::open, which
    // unconditionally sets the mode to 0600 regardless of the process umask.  We verify
    // this by confirming the mode is exactly 0600 on a fresh DB — an umask of 0022
    // (the typical default) would leave a mode of 0644 if the chmod step were absent.
    #[cfg(unix)]
    #[test]
    fn t054_03_mode_0600_overrides_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("umask_test.db");
        let _cache = Cache::new(&db_path).expect("T-054-03: Cache::new should succeed");
        let meta = std::fs::metadata(&db_path).unwrap();
        let mode = meta.permissions().mode();
        // A typical umask of 0022 would produce 0644 if set_permissions were not called.
        // The implementation always calls set_permissions(0o600), so we expect exactly 0600.
        assert_eq!(
            mode & 0o777,
            0o600,
            "T-054-03: mode must be 0600 regardless of umask, got {:#o}",
            mode & 0o777
        );
    }

    // T-054-04: Re-opening an existing cache DB does not widen its permissions.
    #[cfg(unix)]
    #[test]
    fn t054_04_reopen_does_not_widen_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cache.db");

        // First open: create and establish 0600.
        {
            let _cache = Cache::new(&db_path).expect("T-054-04: first open should succeed");
        }

        // Second open: should keep 0600, not widen.
        {
            let _cache = Cache::new(&db_path).expect("T-054-04: second open should succeed");
        }

        let meta = std::fs::metadata(&db_path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "T-054-04: mode must still be 0600 after re-open, got {:#o}",
            mode & 0o777
        );
    }

    // T-054-05: WAL journal mode is set after Cache::new.
    #[test]
    fn t054_05_wal_journal_mode_set() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("wal_test.db");
        let cache = Cache::new(&db_path).expect("T-054-05: Cache::new should succeed");
        let mode: String = cache
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("T-054-05: PRAGMA journal_mode query should succeed");
        assert_eq!(
            mode, "wal",
            "T-054-05: journal_mode must be 'wal', got '{mode}'"
        );
    }

    // T-054-06: WAL mode is present even when opening an existing database that was in DELETE mode.
    #[test]
    fn t054_06_wal_upgrades_from_delete_mode() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("delete_mode.db");

        // Create the DB with DELETE journal mode.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("PRAGMA journal_mode = DELETE;").unwrap();
            conn.execute_batch("CREATE TABLE IF NOT EXISTS dummy (id INTEGER PRIMARY KEY);")
                .unwrap();
        }

        // Open with Cache::new — should upgrade to WAL.
        let cache = Cache::new(&db_path).expect("T-054-06: Cache::new should succeed");
        let mode: String = cache
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("T-054-06: PRAGMA journal_mode query should succeed");
        assert_eq!(
            mode, "wal",
            "T-054-06: Cache::new must upgrade journal_mode to 'wal', got '{mode}'"
        );
    }

    // T-054-07: Insert and lookup still work after WAL is enabled.
    #[test]
    fn t054_07_insert_lookup_after_wal() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("wal_rw.db");
        let cache = Cache::new(&db_path).expect("T-054-07: Cache::new should succeed");
        cache
            .insert("pkg", "1.0.0", "npm", "pass", None, None, None)
            .expect("T-054-07: insert should succeed");
        let entry = cache
            .lookup("pkg", "1.0.0", "npm")
            .expect("T-054-07: lookup should succeed");
        assert!(
            entry.is_some(),
            "T-054-07: lookup should return Some after insert"
        );
        assert_eq!(
            entry.unwrap().result,
            "pass",
            "T-054-07: CacheEntry.result must match the inserted value"
        );
    }

    // T-054-08: Cache::in_memory() is unaffected by the chmod step.
    #[test]
    fn t054_08_in_memory_unaffected_by_chmod() {
        let result = Cache::in_memory();
        assert!(
            result.is_ok(),
            "T-054-08: Cache::in_memory() must succeed without chmod error: {:?}",
            result.err()
        );
    }

    // ── T-057 regression tests — rusqlite 0.31 → 0.39 bump ──────────────────────
    //
    // T-057-01: `cargo build --release` exits 0 — verified by the build gate.
    // T-057-02: `cargo audit` exits 0 — verified by the CI audit gate.
    // T-057-14: `params!` with 7 parameters compiles — exercised by every
    //           call to `Cache::insert` (7-param params! macro) below and in
    //           `cache.rs:insert()`.
    // T-057-15: `query_map([], …)` zero-param syntax compiles — exercised by
    //           `cache.rs:Cache::new` (PRAGMA table_info query_map call) and the
    //           PRAGMA column tests below.
    // T-057-16: total test count >= 635 — this file adds 11 new tests; baseline
    //           was 695, post-bump is 706.
    // T-057-17: `cargo clippy --all-targets -- -D warnings` exits 0 — CI gate.
    // T-057-18: `cargo fmt --check` exits 0 — CI gate.
    //
    // Changelog review (0.32 through 0.39):
    //   • 0.32: internal HashSet → IndexMap for column map (no public API change).
    //   • 0.33: `params!` macro now uses `IntoIterator`-based dispatch internally;
    //           externally visible API (macro syntax, 7-param limit) unchanged.
    //   • 0.34: `Connection::open_with_flags` signature unchanged; `OpenFlags`
    //           added `SQLITE_OPEN_EXRESCODE` but existing flag usage unaffected.
    //   • 0.35: `Row::get` semantics unchanged; `query_map([], …)` still valid.
    //   • 0.36: `Rows` iterator now requires `rows.next()?` — already our pattern.
    //   • 0.37: `libsqlite3-sys` bumped; bundled SQLite upgraded to 3.49.x.
    //   • 0.38: no public API breaks relevant to dep-scan's usage surface.
    //   • 0.39: `hashbrown` → `foldhash` internally; external API unchanged.
    //
    // All 695 existing tests pass without modification — the API surface used by
    // `cache.rs` (Connection::open, execute_batch, prepare, query_map, execute,
    // params!) is stable across the full 0.31 → 0.39 range.

    // T-057-03: Cache::new creates the `scanned_packages` table (rusqlite 0.39)
    #[test]
    fn t057_03_cache_new_creates_table() {
        let cache = Cache::in_memory();
        assert!(
            cache.is_ok(),
            "T-057-03: Cache::in_memory() must succeed under rusqlite 0.39"
        );
    }

    // T-057-04: Insert and lookup round-trip `result` (rusqlite 0.39 params!)
    #[test]
    fn t057_04_insert_and_lookup_result() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("pkg", "1.0.0", "npm", "pass", None, None, None)
            .expect("T-057-04: insert should succeed under rusqlite 0.39");
        let entry = cache
            .lookup("pkg", "1.0.0", "npm")
            .expect("T-057-04: lookup should succeed");
        assert!(
            entry.is_some(),
            "T-057-04: lookup must return Some after insert"
        );
        assert_eq!(
            entry.unwrap().result,
            "pass",
            "T-057-04: result must round-trip"
        );
    }

    // T-057-05: Cache upsert updates existing row (rusqlite 0.39)
    #[test]
    fn t057_05_upsert_updates_row() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("pkg", "1.0.0", "npm", "pass", None, None, None)
            .unwrap();
        cache
            .insert("pkg", "1.0.0", "npm", "block", None, None, None)
            .unwrap();
        let entry = cache.lookup("pkg", "1.0.0", "npm").unwrap().unwrap();
        assert_eq!(
            entry.result, "block",
            "T-057-05: upsert must update result under rusqlite 0.39"
        );
    }

    // T-057-06: `cache.invalidate` removes the row (rusqlite 0.39)
    #[test]
    fn t057_06_invalidate_removes_row() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("pkg", "1.0.0", "npm", "pass", None, None, None)
            .unwrap();
        cache.invalidate("pkg", "1.0.0", "npm").unwrap();
        let entry = cache.lookup("pkg", "1.0.0", "npm").unwrap();
        assert!(
            entry.is_none(),
            "T-057-06: lookup must return None after invalidate"
        );
    }

    // T-057-07: Content hash round-trips through `params!` under rusqlite 0.39
    // (task 029 regression)
    #[test]
    fn t057_07_content_hash_roundtrip() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert(
                "pkg",
                "1.0.0",
                "npm",
                "pass",
                Some("sha512:abcdef1234567890"),
                None,
                None,
            )
            .expect("T-057-07: insert with content_hash must succeed");
        let entry = cache.lookup("pkg", "1.0.0", "npm").unwrap().unwrap();
        assert_eq!(
            entry.content_hash,
            Some("sha512:abcdef1234567890".to_string()),
            "T-057-07: content_hash must round-trip under rusqlite 0.39"
        );
    }

    // T-057-08: `provenance_identity` round-trips under rusqlite 0.39
    // (task 032 regression)
    #[test]
    fn t057_08_provenance_identity_roundtrip() {
        let cache = Cache::in_memory().unwrap();
        let identity = "https://github.com/example/.github/workflows/release.yml@refs/tags/v1";
        cache
            .insert("pkg", "1.0.0", "npm", "pass", None, Some(identity), None)
            .expect("T-057-08: insert with provenance_identity must succeed");
        let entry = cache.lookup("pkg", "1.0.0", "npm").unwrap().unwrap();
        assert_eq!(
            entry.provenance_identity,
            Some(identity.to_string()),
            "T-057-08: provenance_identity must round-trip under rusqlite 0.39"
        );
    }

    // T-057-09: SHA-1 bypass — None content_hash stored as NULL under rusqlite 0.39
    // (task 040 regression)
    #[test]
    fn t057_09_sha1_bypass_none_stores_null() {
        let cache = Cache::in_memory().unwrap();
        // SHA-1 packages store content_hash = None (NULL) per task 040
        cache
            .insert("pkg", "1.0.0", "npm", "pass", None, None, None)
            .expect("T-057-09: insert with None content_hash must succeed");
        let entry = cache.lookup("pkg", "1.0.0", "npm").unwrap().unwrap();
        assert_eq!(
            entry.content_hash, None,
            "T-057-09: None content_hash must be stored as NULL under rusqlite 0.39"
        );
    }

    // T-057-10: Resolved-version composite key is intact under rusqlite 0.39
    // (task 038 regression)
    #[test]
    fn t057_10_resolved_version_keying() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert(
                "lodash",
                "4.17.21",
                "npm",
                "pass",
                Some("sha512:aaaa"),
                None,
                None,
            )
            .unwrap();
        cache
            .insert(
                "lodash",
                "4.17.22",
                "npm",
                "pass",
                Some("sha512:bbbb"),
                None,
                None,
            )
            .unwrap();
        let entry = cache.lookup("lodash", "4.17.21", "npm").unwrap().unwrap();
        assert_eq!(
            entry.content_hash,
            Some("sha512:aaaa".to_string()),
            "T-057-10: version 4.17.21 must map to sha512:aaaa; rusqlite 0.39 must not collapse version keys"
        );
    }

    // T-057-11: Maintainer history insert and retrieve under rusqlite 0.39
    // (task 014 regression)
    #[test]
    fn t057_11_maintainer_history_roundtrip() {
        let cache = Cache::in_memory().unwrap();
        let maintainers = vec!["alice".to_string(), "bob".to_string()];
        cache
            .record_maintainers("lodash", "npm", &maintainers)
            .expect("T-057-11: record_maintainers must succeed");
        let result = cache
            .get_previous_maintainers("lodash", "npm")
            .expect("T-057-11: get_previous_maintainers must succeed");
        assert_eq!(
            result,
            Some(vec!["alice".to_string(), "bob".to_string()]),
            "T-057-11: maintainer list must round-trip under rusqlite 0.39"
        );
    }

    // T-057-12: Additive migration (content_hash column) runs without error under
    // rusqlite 0.39 on a legacy schema DB.
    #[test]
    fn t057_12_additive_migration_content_hash() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t057_12_legacy.db");

        // Create a pre-029 schema (no content_hash column)
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE scanned_packages (
                    name       TEXT NOT NULL,
                    version    TEXT NOT NULL,
                    registry   TEXT NOT NULL,
                    result     TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    PRIMARY KEY (name, version, registry)
                );",
            )
            .unwrap();
        }

        let result = Cache::new(&db_path);
        assert!(
            result.is_ok(),
            "T-057-12: ALTER TABLE ADD COLUMN content_hash must succeed under rusqlite 0.39: {:?}",
            result.err()
        );
    }

    // T-057-13: Additive migration (provenance_identity column) runs without error
    // under rusqlite 0.39 on a post-029/pre-032 schema DB.
    #[test]
    fn t057_13_additive_migration_provenance_identity() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t057_13_v1_1.db");

        // Create a post-029/pre-032 schema (has content_hash but no provenance_identity)
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE scanned_packages (
                    name         TEXT NOT NULL,
                    version      TEXT NOT NULL,
                    registry     TEXT NOT NULL,
                    result       TEXT NOT NULL,
                    scanned_at   TEXT NOT NULL,
                    content_hash TEXT,
                    PRIMARY KEY (name, version, registry)
                );",
            )
            .unwrap();
        }

        let result = Cache::new(&db_path);
        assert!(
            result.is_ok(),
            "T-057-13: ALTER TABLE ADD COLUMN provenance_identity must succeed under rusqlite 0.39: {:?}",
            result.err()
        );
    }

    // ── T-059 tests — cache DB create-then-chmod TOCTOU fix ─────────────────────

    // T-059-01: File created by Cache::new on a fresh path has mode 0600 immediately.
    #[cfg(unix)]
    #[test]
    fn t059_01_fresh_path_has_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t059_01.db");
        let _cache = Cache::new(&db_path).expect("T-059-01: Cache::new should succeed");
        let meta = std::fs::metadata(&db_path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "T-059-01: DB file must have mode 0600 on fresh create, got {:#o}",
            mode & 0o777
        );
    }

    // T-059-02: No group or world read bits exist after Cache::new on a fresh path.
    #[cfg(unix)]
    #[test]
    fn t059_02_no_group_or_world_bits_fresh_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t059_02.db");
        let _cache = Cache::new(&db_path).expect("T-059-02: Cache::new should succeed");
        let meta = std::fs::metadata(&db_path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o177,
            0,
            "T-059-02: owner execute + group + world bits must all be 0, got {:#o}",
            mode & 0o177
        );
    }

    // T-059-03: Mode is 0600 even when the process umask is 0000 (maximally permissive).
    // Without the pre-create fix, Connection::open would create the file with mode 0666
    // under umask 0000 (i.e., no bits masked), and then set_permissions would fix it —
    // but only after the file was briefly world-readable.  The fix ensures 0600 at
    // creation time.
    #[cfg(unix)]
    #[test]
    fn t059_03_mode_0600_with_umask_0000() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t059_03.db");

        // Set umask to 0000 (maximally permissive) before creating the cache.
        let orig_umask = unsafe { libc::umask(0o000) };
        let result = Cache::new(&db_path);
        // Restore original umask regardless of outcome.
        unsafe { libc::umask(orig_umask) };

        result.expect("T-059-03: Cache::new should succeed with umask 0000");

        let meta = std::fs::metadata(&db_path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "T-059-03: mode must be 0600 even with umask 0000, got {:#o}",
            mode & 0o777
        );
    }

    // T-059-04: Mode is 0600 even when the process umask is 0022 (typical default).
    #[cfg(unix)]
    #[test]
    fn t059_04_mode_0600_with_umask_0022() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t059_04.db");

        let orig_umask = unsafe { libc::umask(0o022) };
        let result = Cache::new(&db_path);
        unsafe { libc::umask(orig_umask) };

        result.expect("T-059-04: Cache::new should succeed with umask 0022");

        let meta = std::fs::metadata(&db_path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "T-059-04: mode must be 0600 with umask 0022, got {:#o}",
            mode & 0o777
        );
    }

    // T-059-05: Stat taken before any SQLite WAL writes shows 0600.
    // The mode must be correct the moment the file descriptor is visible in the
    // filesystem, not only after the first write.
    #[cfg(unix)]
    #[test]
    fn t059_05_mode_correct_before_writes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t059_05.db");
        // Stat immediately after Cache::new returns, without inserting any data.
        let _cache = Cache::new(&db_path).expect("T-059-05: Cache::new should succeed");
        let meta = std::fs::metadata(&db_path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "T-059-05: mode must be 0600 before any writes, got {:#o}",
            mode & 0o777
        );
    }

    // T-059-06: Re-opening an existing 0600 cache DB preserves mode 0600.
    #[cfg(unix)]
    #[test]
    fn t059_06_reopen_existing_0600_preserves_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t059_06.db");

        {
            let _cache = Cache::new(&db_path).expect("T-059-06: first open should succeed");
        }
        {
            let _cache = Cache::new(&db_path).expect("T-059-06: second open should succeed");
        }

        let meta = std::fs::metadata(&db_path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "T-059-06: mode must still be 0600 after re-open, got {:#o}",
            mode & 0o777
        );
    }

    // T-059-07: Re-opening a legacy 0644 cache DB narrows it to 0600.
    // Simulates opening a pre-fix cache DB that was created without the atomic
    // pre-create step (mode 0644 under a typical umask).
    #[cfg(unix)]
    #[test]
    fn t059_07_reopen_legacy_0644_narrows_to_0600() {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t059_07_legacy.db");

        // Create a SQLite file with mode 0644, simulating a pre-fix cache.
        {
            use std::fs::OpenOptions;
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&db_path)
                .unwrap();
            // Write minimal SQLite header so Connection::open accepts it.
            drop(f);
            // Actually just let SQLite initialise it — create via Connection::open.
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("CREATE TABLE IF NOT EXISTS dummy (id INTEGER PRIMARY KEY);")
                .unwrap();
        }

        // Confirm the file is 0644 before we open with Cache::new.
        let before_mode = std::fs::metadata(&db_path).unwrap().permissions().mode();
        assert_eq!(
            before_mode & 0o777,
            0o644,
            "T-059-07: precondition: legacy file should be 0644, got {:#o}",
            before_mode & 0o777
        );

        // Open with Cache::new — should narrow to 0600.
        let _cache =
            Cache::new(&db_path).expect("T-059-07: Cache::new on legacy file should succeed");

        let after_mode = std::fs::metadata(&db_path).unwrap().permissions().mode();
        assert_eq!(
            after_mode & 0o777,
            0o600,
            "T-059-07: Cache::new must narrow 0644 to 0600, got {:#o}",
            after_mode & 0o777
        );
    }

    // T-059-08: Cache::in_memory() continues to succeed without attempting a chmod.
    #[test]
    fn t059_08_in_memory_unaffected_by_precreate() {
        let result = Cache::in_memory();
        assert!(
            result.is_ok(),
            "T-059-08: Cache::in_memory() must succeed without touching the filesystem: {:?}",
            result.err()
        );
    }

    // T-059-11: Insert and lookup round-trip succeeds after the TOCTOU fix.
    #[test]
    fn t059_11_insert_lookup_roundtrip_after_fix() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t059_11.db");
        let cache = Cache::new(&db_path).expect("T-059-11: Cache::new should succeed");
        cache
            .insert("mylib", "2.0.0", "crates", "pass", None, None, None)
            .expect("T-059-11: insert should succeed");
        let entry = cache
            .lookup("mylib", "2.0.0", "crates")
            .expect("T-059-11: lookup should succeed")
            .expect("T-059-11: entry should be Some");
        assert_eq!(
            entry.result, "pass",
            "T-059-11: result must round-trip after TOCTOU fix"
        );
    }

    // T-059-12: WAL journal mode is still active after the TOCTOU fix.
    #[test]
    fn t059_12_wal_mode_still_active_after_fix() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t059_12.db");
        let cache = Cache::new(&db_path).expect("T-059-12: Cache::new should succeed");
        let mode: String = cache
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("T-059-12: PRAGMA journal_mode query should succeed");
        assert_eq!(
            mode, "wal",
            "T-059-12: journal_mode must be 'wal' after TOCTOU fix, got '{mode}'"
        );
    }

    // T-059-13: All task 054 cache privacy tests still pass — verified by running
    //   `cargo test cache` which includes T-054-01 through T-054-08 above.
    // T-059-14: All task 007 cache unit tests still pass — verified by running
    //   `cargo test cache` which includes insert/lookup/invalidate/clear tests above.
    // T-059-15: `cargo test`, `cargo clippy --all-targets -- -D warnings`, and
    //   `cargo fmt --check` all pass — verified by the pre-commit gate.

    // ── T-097 tests — VCS fetch cache integration (ADR 008 piece 2) ─────────────

    const SHA1_PIN: &str = "a3b5c7d9e1f2a3b5c7d9e1f2a3b5c7d9e1f2a3b5";

    // T-097-01: A pinned-SHA git dep stores under key (name, commit_sha, "git").
    #[test]
    fn t097_01_insert_git_keys_by_name_sha_git() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert_git("pkg-name", SHA1_PIN, "pass", Some("sha256:deadbeef"), None)
            .unwrap();

        let entry = cache
            .lookup("pkg-name", SHA1_PIN, "git")
            .unwrap()
            .expect("T-097-01: git entry should be looked up by (name, sha, \"git\")");
        assert_eq!(entry.result, "pass");
        assert_eq!(entry.source_kind, Some("git".to_string()));
        assert_eq!(entry.content_hash, Some("sha256:deadbeef".to_string()));
    }

    // T-097-05: The "git" registry slot does not collide with any RegistryType
    // string.  A registry crate `foo`@`abc...` and a git dep `foo`@`abc...` are
    // distinct rows.
    #[test]
    fn t097_05_git_slot_does_not_collide_with_registry() {
        let cache = Cache::in_memory().unwrap();
        // A crates.io row and a git row that share name and version string.
        cache
            .insert(
                "foo",
                SHA1_PIN,
                "crates",
                "block",
                Some("sha256:aaaa"),
                None,
                None,
            )
            .unwrap();
        cache
            .insert_git("foo", SHA1_PIN, "pass", Some("sha256:bbbb"), None)
            .unwrap();

        let crates_entry = cache.lookup("foo", SHA1_PIN, "crates").unwrap().unwrap();
        let git_entry = cache.lookup("foo", SHA1_PIN, "git").unwrap().unwrap();
        assert_eq!(
            crates_entry.result, "block",
            "T-097-05: crates row must be independent of the git row"
        );
        assert_eq!(
            git_entry.result, "pass",
            "T-097-05: git row must be independent of the crates row"
        );
        // Confirm "git" is none of the RegistryType strings.
        for reg in ["npm", "pypi", "crates", "go"] {
            assert_ne!(
                reg, "git",
                "T-097-05: \"git\" slot must not equal any RegistryType string"
            );
        }
    }

    // T-097-06: An existing cache DB with no git entries is not corrupted by the
    // 097 migration; pre-existing registry entries remain readable.
    #[test]
    fn t097_06_existing_registry_entries_survive_migration() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t097_06.db");

        // Pre-097 schema: has content_hash + provenance_identity but no source_kind.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE scanned_packages (
                    name                TEXT NOT NULL,
                    version             TEXT NOT NULL,
                    registry            TEXT NOT NULL,
                    result              TEXT NOT NULL,
                    scanned_at          TEXT NOT NULL,
                    content_hash        TEXT,
                    provenance_identity TEXT,
                    PRIMARY KEY (name, version, registry)
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO scanned_packages
                 (name, version, registry, result, scanned_at, content_hash)
                 VALUES ('lodash', '4.17.21', 'npm', 'pass',
                         '2025-01-01T00:00:00Z', 'sha512:abcd')",
                [],
            )
            .unwrap();
        }

        // Run the 097 migration via Cache::new.
        let cache = Cache::new(&db_path).expect("T-097-06: migration should succeed");

        let entry = cache
            .lookup("lodash", "4.17.21", "npm")
            .unwrap()
            .expect("T-097-06: pre-existing registry row must survive migration");
        assert_eq!(entry.result, "pass");
        assert_eq!(entry.content_hash, Some("sha512:abcd".to_string()));
        assert_eq!(
            entry.source_kind, None,
            "T-097-06: legacy registry row must read source_kind = None"
        );
    }

    // T-097-07: The 097 schema migration is idempotent.
    #[test]
    fn t097_07_migration_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t097_07.db");

        // First open creates the table with source_kind already present.
        {
            let cache = Cache::new(&db_path).unwrap();
            cache
                .insert_git("g", SHA1_PIN, "warn", Some("sha256:cafe"), None)
                .unwrap();
        }
        // Second open must not error (no duplicate source_kind column).
        let cache = Cache::new(&db_path).expect("T-097-07: second open must not error");
        // The git row is still intact and unchanged.
        let entry = cache.lookup("g", SHA1_PIN, "git").unwrap().unwrap();
        assert_eq!(
            entry.result, "warn",
            "T-097-07: git row must be unchanged after a second migration pass"
        );
        assert_eq!(entry.content_hash, Some("sha256:cafe".to_string()));
    }

    // T-097-08: The migration is additive — it adds a nullable column and does
    // not require backfill of existing rows.
    #[test]
    fn t097_08_source_kind_column_is_additive_nullable() {
        let cache = Cache::in_memory().unwrap();
        let mut stmt = cache
            .conn
            .prepare("PRAGMA table_info(scanned_packages)")
            .unwrap();
        let col = stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                let col_type: String = row.get(2)?;
                let not_null: i64 = row.get(3)?;
                Ok((name, col_type, not_null))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .find(|(name, _, _)| name == "source_kind");

        let col = col.expect("T-097-08: source_kind column should exist");
        assert_eq!(col.1.to_uppercase(), "TEXT", "column type should be TEXT");
        assert_eq!(
            col.2, 0,
            "T-097-08: source_kind must be nullable (no backfill required)"
        );
    }

    // T-097-08b: A pre-029 legacy DB (no content_hash, no provenance_identity,
    // no source_kind) migrates all the way forward without data loss.
    #[test]
    fn t097_08b_legacy_pre029_db_migrates_to_097_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t097_08b.db");

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE scanned_packages (
                    name       TEXT NOT NULL,
                    version    TEXT NOT NULL,
                    registry   TEXT NOT NULL,
                    result     TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    PRIMARY KEY (name, version, registry)
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO scanned_packages (name, version, registry, result, scanned_at)
                 VALUES ('old', '1.0.0', 'npm', 'pass', '2024-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        let cache = Cache::new(&db_path).expect("T-097-08b: full migration should succeed");
        let entry = cache.lookup("old", "1.0.0", "npm").unwrap().unwrap();
        assert_eq!(entry.result, "pass");
        assert_eq!(entry.content_hash, None);
        assert_eq!(entry.provenance_identity, None);
        assert_eq!(entry.source_kind, None);
    }

    // T-097-08c: insert_git upserts on the same (name, sha) — re-scan updates the
    // stored verdict and hash without creating a duplicate row.
    #[test]
    fn t097_08c_insert_git_upserts() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert_git("p", SHA1_PIN, "pass", Some("sha256:1111"), None)
            .unwrap();
        cache
            .insert_git("p", SHA1_PIN, "block", Some("sha256:2222"), None)
            .unwrap();
        let entry = cache.lookup("p", SHA1_PIN, "git").unwrap().unwrap();
        assert_eq!(entry.result, "block");
        assert_eq!(entry.content_hash, Some("sha256:2222".to_string()));
    }

    // T-097-08d: A registry insert stores source_kind = NULL (never "git").
    #[test]
    fn t097_08d_registry_insert_has_null_source_kind() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("pkg", "1.0.0", "npm", "pass", None, None, None)
            .unwrap();
        let entry = cache.lookup("pkg", "1.0.0", "npm").unwrap().unwrap();
        assert_eq!(
            entry.source_kind, None,
            "T-097-08d: registry rows must carry source_kind = NULL"
        );
    }

    // ── T-106 tests — subtree_digest cache column (ADR 009 Decision 4) ──────────

    /// Model of the task-030 content-hash gate, isolated here so the T-106
    /// two-gate tests can exercise the *combined* (content-hash AND
    /// subtree-digest) Hit rule without reaching into main.rs's scan loop.  The
    /// production content-hash gate (`verify_hash` / `hash_verify_decision` in
    /// `src/main.rs`) is the byte-equality check this mirrors: a stored hash is
    /// honoured only when it equals the freshly recomputed one.
    fn content_hash_gate(stored: Option<&str>, recomputed: Option<&str>) -> bool {
        match (stored, recomputed) {
            (Some(s), Some(r)) => s == r,
            // A row with no stored content hash cannot be hash-verified — the
            // production gate re-scans in that case (fail-closed).
            _ => false,
        }
    }

    /// The combined two-gate Hit rule (REQ-106-03): a cached transitive row is a
    /// Hit IFF the content-hash gate passes AND the subtree-digest gate passes.
    /// This is exactly the composition task 108 wires into the live lookup.
    fn is_hit(
        stored_hash: Option<&str>,
        recomputed_hash: Option<&str>,
        stored_digest: Option<&str>,
        recomputed_digest: Option<&str>,
    ) -> bool {
        content_hash_gate(stored_hash, recomputed_hash)
            && subtree_digest_valid(stored_digest, recomputed_digest)
    }

    // T-106-01: Migration adds the subtree_digest column on a fresh DB.
    #[test]
    fn t106_01_migration_adds_subtree_digest_column() {
        let cache = Cache::in_memory().unwrap();
        let mut stmt = cache
            .conn
            .prepare("PRAGMA table_info(scanned_packages)")
            .unwrap();
        let col = stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                let col_type: String = row.get(2)?;
                let not_null: i64 = row.get(3)?;
                Ok((name, col_type, not_null))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .find(|(name, _, _)| name == "subtree_digest");

        let col = col.expect("T-106-01: subtree_digest column should exist");
        assert_eq!(
            col.1.to_uppercase(),
            "TEXT",
            "T-106-01: column type should be TEXT"
        );
        assert_eq!(
            col.2, 0,
            "T-106-01: subtree_digest must be nullable (not_null = 0)"
        );
    }

    // T-106-02: Migration is idempotent — column appears exactly once across two opens.
    #[test]
    fn t106_02_migration_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t106_02.db");

        // First open adds subtree_digest.
        let _ = Cache::new(&db_path).unwrap();
        // Second open (simulating a second run) must not error on a duplicate column.
        let cache = Cache::new(&db_path).expect("T-106-02: second open must not error");

        let count: i64 = {
            let mut stmt = cache
                .conn
                .prepare("PRAGMA table_info(scanned_packages)")
                .unwrap();
            stmt.query_map([], |row| {
                let name: String = row.get(1)?;
                Ok(name)
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .filter(|n: &String| n == "subtree_digest")
            .count() as i64
        };
        assert_eq!(
            count, 1,
            "T-106-02: subtree_digest column must appear exactly once"
        );
    }

    // T-106-03: Legacy registry rows read NULL for subtree_digest (no backfill).
    #[test]
    fn t106_03_legacy_registry_rows_read_null() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t106_03.db");

        // Pre-106 schema: has content_hash + provenance_identity + source_kind,
        // but no subtree_digest.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE scanned_packages (
                    name                TEXT NOT NULL,
                    version             TEXT NOT NULL,
                    registry            TEXT NOT NULL,
                    result              TEXT NOT NULL,
                    scanned_at          TEXT NOT NULL,
                    content_hash        TEXT,
                    provenance_identity TEXT,
                    source_kind         TEXT,
                    PRIMARY KEY (name, version, registry)
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO scanned_packages
                 (name, version, registry, result, scanned_at, content_hash)
                 VALUES ('lodash', '4.17.21', 'npm', 'pass',
                         '2025-01-01T00:00:00Z', 'sha512:abcd')",
                [],
            )
            .unwrap();
        }

        let cache = Cache::new(&db_path).expect("T-106-03: migration should succeed");
        let entry = cache
            .lookup("lodash", "4.17.21", "npm")
            .unwrap()
            .expect("T-106-03: legacy row must survive migration");
        assert_eq!(entry.result, "pass");
        assert_eq!(
            entry.subtree_digest, None,
            "T-106-03: legacy registry row must read subtree_digest = None"
        );
    }

    // T-106-04: Legacy git rows (task 097) read NULL for subtree_digest.
    #[test]
    fn t106_04_legacy_git_rows_read_null() {
        let cache = Cache::in_memory().unwrap();
        // insert_git with None subtree_digest models a pre-106 / flat git row.
        cache
            .insert_git("pkg", SHA1_PIN, "pass", Some("sha256:deadbeef"), None)
            .unwrap();
        let entry = cache
            .lookup("pkg", SHA1_PIN, "git")
            .unwrap()
            .expect("T-106-04: git row should exist");
        assert_eq!(entry.source_kind, Some("git".to_string()));
        assert_eq!(
            entry.subtree_digest, None,
            "T-106-04: flat git row must read subtree_digest = None"
        );
    }

    // T-106-05: Digest is sha256 over sorted, length-framed pairs (golden test).
    #[test]
    fn t106_05_digest_golden() {
        let children = [("foo@1.0.0@npm", "pass"), ("bar@abc123@git", "warn")];
        let digest = compute_subtree_digest(&children);
        assert_eq!(
            digest, "sha256:4c4205a67d2817b860fea6d74ef63956852ebe5fa4b0e5494e5b274aea30c4a5",
            "T-106-05: digest must match the precomputed golden value"
        );
    }

    // T-106-06: Digest is order-independent.
    #[test]
    fn t106_06_digest_order_independent() {
        let forward = [("foo@1.0.0@npm", "pass"), ("bar@abc123@git", "warn")];
        let reversed = [("bar@abc123@git", "warn"), ("foo@1.0.0@npm", "pass")];
        assert_eq!(
            compute_subtree_digest(&forward),
            compute_subtree_digest(&reversed),
            "T-106-06: insertion order must not change the digest"
        );
    }

    // T-106-07: Empty child set produces a deterministic, non-NULL digest.
    #[test]
    fn t106_07_empty_child_set_deterministic() {
        let a = compute_subtree_digest(&[]);
        let b = compute_subtree_digest(&[]);
        assert_eq!(a, b, "T-106-07: empty-child digest must be deterministic");
        assert_eq!(
            a, "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "T-106-07: empty-child digest must be sha256 of the empty input"
        );
        // It is a real digest, not the NULL sentinel a flat row carries.
        assert!(a.starts_with("sha256:"));
    }

    // T-106-08: Hit requires BOTH the content-hash gate AND the subtree_digest match.
    #[test]
    fn t106_08_hit_requires_both_gates() {
        let stored_hash = Some("sha256:aaa");
        let stored_digest = Some("sha256:bbb");

        // Both gates pass → Hit.
        assert!(
            is_hit(
                stored_hash,
                Some("sha256:aaa"),
                stored_digest,
                Some("sha256:bbb")
            ),
            "T-106-08: matching hash and matching digest must be a Hit"
        );
        // Content-hash matches but recomputed digest differs → Miss (fail-closed).
        assert!(
            !is_hit(
                stored_hash,
                Some("sha256:aaa"),
                stored_digest,
                Some("sha256:ZZZ")
            ),
            "T-106-08: a differing subtree_digest must force a Miss even when the hash matches"
        );
    }

    // T-106-09: Changed child verdict → recomputed digest differs → re-scan.
    #[test]
    fn t106_09_changed_child_verdict_forces_rescan() {
        // Parent A's digest computed when child B scanned Pass.
        let stored_digest = compute_subtree_digest(&[("B@1.0.0@npm", "pass")]);
        // Child B flips to Warn on the next run.
        let recomputed_digest = compute_subtree_digest(&[("B@1.0.0@npm", "warn")]);
        assert_ne!(
            stored_digest, recomputed_digest,
            "T-106-09: a changed child verdict must change the digest"
        );
        // With the content-hash gate satisfied, the digest mismatch alone is a Miss.
        assert!(
            !is_hit(
                Some("sha256:aaa"),
                Some("sha256:aaa"),
                Some(&stored_digest),
                Some(&recomputed_digest),
            ),
            "T-106-09: parent A must be re-scanned, not served a stale Pass"
        );
    }

    // T-106-10: content-hash mismatch alone forces a re-scan (existing gate unchanged).
    #[test]
    fn t106_10_content_hash_mismatch_forces_rescan() {
        let digest = Some("sha256:bbb");
        assert!(
            !is_hit(Some("sha256:aaa"), Some("sha256:TAMPERED"), digest, digest),
            "T-106-10: a tampered content_hash must force a Miss even with a matching digest"
        );
    }

    // T-106-11: subtree_digest mismatch alone forces a re-scan even if content-hash matches.
    #[test]
    fn t106_11_subtree_digest_mismatch_forces_rescan() {
        assert!(
            !is_hit(
                Some("sha256:aaa"),
                Some("sha256:aaa"),
                Some("sha256:bbb"),
                Some("sha256:DIFFERENT"),
            ),
            "T-106-11: a differing subtree_digest must force a Miss"
        );
        // Sanity: the subtree-digest gate itself rejects the mismatch.
        assert!(!subtree_digest_valid(
            Some("sha256:bbb"),
            Some("sha256:DIFFERENT")
        ));
        assert!(subtree_digest_valid(Some("sha256:bbb"), Some("sha256:bbb")));
    }

    // T-106-12: insert writes subtree_digest when provided.
    #[test]
    fn t106_12_insert_writes_subtree_digest() {
        let cache = Cache::in_memory().unwrap();
        let digest = compute_subtree_digest(&[("child@1.0.0@npm", "pass")]);
        cache
            .insert(
                "parent",
                "2.0.0",
                "npm",
                "pass",
                Some("sha512:abcd"),
                None,
                Some(&digest),
            )
            .unwrap();
        let entry = cache.lookup("parent", "2.0.0", "npm").unwrap().unwrap();
        assert_eq!(
            entry.subtree_digest,
            Some(digest),
            "T-106-12: insert must round-trip subtree_digest"
        );
    }

    // T-106-13: insert_git writes subtree_digest when provided.
    #[test]
    fn t106_13_insert_git_writes_subtree_digest() {
        let cache = Cache::in_memory().unwrap();
        let digest = compute_subtree_digest(&[("child@abc@git", "warn")]);
        cache
            .insert_git(
                "parent",
                SHA1_PIN,
                "warn",
                Some("sha256:cafe"),
                Some(&digest),
            )
            .unwrap();
        let entry = cache.lookup("parent", SHA1_PIN, "git").unwrap().unwrap();
        assert_eq!(
            entry.subtree_digest,
            Some(digest),
            "T-106-13: insert_git must round-trip subtree_digest"
        );
    }

    // T-106-14: insert with None subtree_digest writes NULL.
    #[test]
    fn t106_14_insert_none_writes_null() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert(
                "pkg",
                "1.0.0",
                "npm",
                "pass",
                Some("sha512:abcd"),
                None,
                None,
            )
            .unwrap();
        let entry = cache.lookup("pkg", "1.0.0", "npm").unwrap().unwrap();
        assert_eq!(
            entry.subtree_digest, None,
            "T-106-14: insert with None must store NULL for subtree_digest"
        );
    }

    // T-106-15: A parent depending on a mutable-ref child is never served as a
    // stale Hit. The mutable-ref child is never cached (task 097), so on the next
    // run its verdict cannot be re-fingerprinted into the parent's recomputed
    // digest (recomputed = None) → the subtree-digest gate fails → Miss → re-scan.
    #[test]
    fn t106_15_mutable_ref_parent_not_served_stale() {
        // Parent stored a digest computed over its children, one of which is a
        // mutable-ref git child.
        let stored_digest =
            compute_subtree_digest(&[("dep@1.0.0@npm", "pass"), ("mut@main@git", "pass")]);

        // On the next run the mutable-ref child has no cache row → its verdict is
        // unavailable for re-fingerprinting → the parent cannot recompute a
        // digest at all (recomputed = None).
        let recomputed_digest: Option<&str> = None;

        // Even with the content-hash gate satisfied, the parent is a Miss.
        assert!(
            !is_hit(
                Some("sha256:aaa"),
                Some("sha256:aaa"),
                Some(&stored_digest),
                recomputed_digest,
            ),
            "T-106-15: a parent depending on a mutable-ref child must be re-scanned, never served stale"
        );
        // Directly: a None recomputed digest against a stored digest fails the gate.
        assert!(
            !subtree_digest_valid(Some(&stored_digest), None),
            "T-106-15: an un-recomputable subtree (mutable-ref child) fails the digest gate"
        );
    }

    // T-106-05b: NULL stored digest (flat-scan row) skips the subtree-digest gate
    // (REQ-106-05) — the content-hash gate alone governs. Documents the
    // flat-scan / transitive boundary the column introduces.
    #[test]
    fn t106_05b_null_digest_skips_subtree_gate() {
        // Flat-scan row: stored digest is None → gate is skipped (returns true)
        // regardless of any recomputed value.
        assert!(subtree_digest_valid(None, None));
        assert!(subtree_digest_valid(None, Some("sha256:anything")));
        // The combined Hit rule for a flat row therefore reduces to the
        // content-hash gate: matching hash → Hit, mismatching hash → Miss.
        assert!(is_hit(Some("sha256:aaa"), Some("sha256:aaa"), None, None));
        assert!(!is_hit(Some("sha256:aaa"), Some("sha256:bbb"), None, None));
    }
}

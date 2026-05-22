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
    /// Verified Fulcio OIDC subject identity from the npm provenance attestation
    /// (task 032). `None` when no valid attestation was found or the package is
    /// not from npm.
    pub provenance_identity: Option<String>,
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
    pub fn new(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
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
            "SELECT result, scanned_at, content_hash, provenance_identity
             FROM scanned_packages
             WHERE name = ?1 AND version = ?2 AND registry = ?3",
        )?;

        let mut rows = stmt.query_map(rusqlite::params![name, version, registry], |row| {
            Ok(CacheEntry {
                result: row.get(0)?,
                scanned_at: row.get(1)?,
                content_hash: row.get(2)?,
                provenance_identity: row.get(3)?,
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
    pub fn insert(
        &self,
        name: &str,
        version: &str,
        registry: &str,
        result: &str,
        content_hash: Option<&str>,
        provenance_identity: Option<&str>,
    ) -> Result<()> {
        let scanned_at = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO scanned_packages
             (name, version, registry, result, scanned_at, content_hash, provenance_identity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                name,
                version,
                registry,
                result,
                scanned_at,
                content_hash,
                provenance_identity
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
            .insert("lodash", "4.17.21", "npm", "pass", None, None)
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
            .insert("lodash", "4.17.21", "npm", "pass", None, None)
            .unwrap();
        cache
            .insert("lodash", "4.17.21", "npm", "block", None, None)
            .unwrap();

        let entry = cache.lookup("lodash", "4.17.21", "npm").unwrap().unwrap();
        assert_eq!(entry.result, "block", "upsert should update the result");
    }

    // T-007-05: Invalidate removes entry
    #[test]
    fn invalidate_removes_entry() {
        let cache = Cache::in_memory().unwrap();
        cache
            .insert("lodash", "4.17.21", "npm", "pass", None, None)
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
        cache.insert("a", "1.0", "npm", "pass", None, None).unwrap();
        cache
            .insert("b", "2.0", "pypi", "block", None, None)
            .unwrap();
        cache
            .insert("c", "3.0", "cargo", "warn", None, None)
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
            .insert("foo", "1.0", "npm", "pass", None, None)
            .unwrap();
        cache
            .insert("foo", "1.0", "pypi", "block", None, None)
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
                .insert("lodash", "4.17.21", "npm", "pass", None, None)
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
            .insert("lodash", "4.17.21", "npm", "pass", None, None)
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
            .insert("lodash", "4.17.21", "npm", "pass", None, None)
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
            .insert("pkg", "1.0.0", "npm", "pass", Some("sha256:aaaa"), None)
            .unwrap();
        cache
            .insert("pkg", "1.0.0", "npm", "pass", Some("sha256:bbbb"), None)
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
}

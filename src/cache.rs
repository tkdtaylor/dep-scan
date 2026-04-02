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
                name       TEXT NOT NULL,
                version    TEXT NOT NULL,
                registry   TEXT NOT NULL,
                result     TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
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
            "SELECT result, scanned_at FROM scanned_packages
             WHERE name = ?1 AND version = ?2 AND registry = ?3",
        )?;

        let mut rows = stmt.query_map(rusqlite::params![name, version, registry], |row| {
            Ok(CacheEntry {
                result: row.get(0)?,
                scanned_at: row.get(1)?,
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
    pub fn insert(&self, name: &str, version: &str, registry: &str, result: &str) -> Result<()> {
        let scanned_at = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO scanned_packages (name, version, registry, result, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![name, version, registry, result, scanned_at],
        )?;
        Ok(())
    }

    /// Remove a single cache entry.  No-op if the entry does not exist.
    #[allow(dead_code)]
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
        cache.insert("lodash", "4.17.21", "npm", "pass").unwrap();

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
        cache.insert("lodash", "4.17.21", "npm", "pass").unwrap();
        cache.insert("lodash", "4.17.21", "npm", "block").unwrap();

        let entry = cache.lookup("lodash", "4.17.21", "npm").unwrap().unwrap();
        assert_eq!(entry.result, "block", "upsert should update the result");
    }

    // T-007-05: Invalidate removes entry
    #[test]
    fn invalidate_removes_entry() {
        let cache = Cache::in_memory().unwrap();
        cache.insert("lodash", "4.17.21", "npm", "pass").unwrap();
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
        cache.insert("a", "1.0", "npm", "pass").unwrap();
        cache.insert("b", "2.0", "pypi", "block").unwrap();
        cache.insert("c", "3.0", "cargo", "warn").unwrap();

        cache.clear().unwrap();

        assert!(cache.lookup("a", "1.0", "npm").unwrap().is_none());
        assert!(cache.lookup("b", "2.0", "pypi").unwrap().is_none());
        assert!(cache.lookup("c", "3.0", "cargo").unwrap().is_none());
    }

    // T-007-08: Different registries are distinct keys
    #[test]
    fn different_registries_are_distinct() {
        let cache = Cache::in_memory().unwrap();
        cache.insert("foo", "1.0", "npm", "pass").unwrap();
        cache.insert("foo", "1.0", "pypi", "block").unwrap();

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
            cache.insert("lodash", "4.17.21", "npm", "pass").unwrap();
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
        cache.insert("lodash", "4.17.21", "npm", "pass").unwrap();
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
}

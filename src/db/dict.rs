//! Path-dictionary import, query, delete, and export.

use std::path::Path;

use rusqlite::params;

use super::{
    helpers::{collect_rows, new_id, normalize_path, now},
    types::Database,
};

impl Database {
    /// Bulk-import dictionary paths in a single transaction.
    ///
    /// # Arguments
    /// - `paths`: Raw path list.
    ///
    /// # Returns
    /// Number of processed items, including duplicate inputs.
    ///
    /// # Errors
    /// Returns an error if the transactional write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.import_dict_paths(&["admin".into()])?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_dict_paths(&self, paths: &[String]) -> anyhow::Result<usize> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let mut count = 0usize;
        {
            let mut insert = tx.prepare(
                "INSERT OR IGNORE INTO dict_paths (id, path, enabled, created_at)
                 VALUES (?1, ?2, 1, ?3)",
            )?;
            for path in paths {
                let normalized = normalize_path(path);
                if normalized.is_empty() {
                    continue;
                }
                insert.execute(params![new_id(), normalized, now()])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// List enabled dictionary paths.
    ///
    /// # Arguments
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Normalized path list.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.list_dict_paths(10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_dict_paths(&self, limit: usize) -> anyhow::Result<Vec<String>> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare("SELECT path FROM dict_paths WHERE enabled = 1 ORDER BY path LIMIT ?1")?;
        collect_rows(&mut stmt, [limit as i64], |row| Ok(row.get(0)?))
    }

    /// Query dictionary paths by optional keyword.
    ///
    /// # Arguments
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Single-column table rows.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.query_dict_paths(Some("admin"), 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_dict_paths(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_simple("dict_paths", "path", keyword, limit)
    }

    /// Delete one dictionary path.
    ///
    /// # Arguments
    /// - `path`: Raw or normalized path.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.delete_dict_path("admin")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_dict_path(&self, path: &str) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM dict_paths WHERE path = ?1",
            [normalize_path(path)],
        )?;
        Ok(())
    }

    /// Export dictionary paths as CSV.
    ///
    /// # Arguments
    /// - `file`: Output CSV path.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the query or file write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.export_dict_paths(&dir.path().join("paths.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_dict_paths(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(file, "SELECT path FROM dict_paths ORDER BY path", &["path"])
    }
}

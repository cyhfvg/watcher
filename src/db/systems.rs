//! Business-system CRUD and export.

use std::path::Path;

use rusqlite::{OptionalExtension, Row, params};

use super::{
    helpers::{collect_rows, new_id, now},
    types::Database,
};

/// Summary SQL used by `system query`.
pub(crate) const SYSTEM_SUMMARY_SQL: &str = "
    SELECT
        s.name,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id) AS names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id) AS ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id) AS ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id) AS urls,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id AND d.is_baseline = 1) AS baseline_names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id AND i.is_baseline = 1) AS baseline_ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id AND p.is_baseline = 1) AS baseline_ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id AND u.is_baseline = 1) AS baseline_urls,
        s.created_at
    FROM systems s
    WHERE s.name LIKE ?1
    ORDER BY s.name
    LIMIT ?2";

/// Summary SQL used by `system export`.
pub(crate) const SYSTEM_EXPORT_SQL: &str = "
    SELECT
        s.name,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id) AS names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id) AS ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id) AS ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id) AS urls,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id AND d.is_baseline = 1) AS baseline_names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id AND i.is_baseline = 1) AS baseline_ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id AND p.is_baseline = 1) AS baseline_ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id AND u.is_baseline = 1) AS baseline_urls,
        s.created_at
    FROM systems s
    ORDER BY s.name";

/// Map a system-summary row to CLI table columns.
///
/// # Arguments
/// - `row`: System-summary query row.
///
/// # Returns
/// String columns for name, counts, and created-at.
///
/// # Errors
/// Returns an error if a column cannot be read.
///
/// # Examples
/// ```text
/// collect_rows(&mut stmt, params, map_system_summary)
/// ```
pub(crate) fn map_system_summary(row: &Row<'_>) -> anyhow::Result<Vec<String>> {
    Ok(vec![
        row.get::<_, String>(0)?,
        row.get::<_, i64>(1)?.to_string(),
        row.get::<_, i64>(2)?.to_string(),
        row.get::<_, i64>(3)?.to_string(),
        row.get::<_, i64>(4)?.to_string(),
        row.get::<_, i64>(5)?.to_string(),
        row.get::<_, i64>(6)?.to_string(),
        row.get::<_, i64>(7)?.to_string(),
        row.get::<_, i64>(8)?.to_string(),
        row.get::<_, String>(9)?,
    ])
}

impl Database {
    /// Insert a business system and return its id, or return the existing id.
    ///
    /// # Arguments
    /// - `name`: Business system name.
    ///
    /// # Returns
    /// System primary key.
    ///
    /// # Errors
    /// Returns an error if the name is empty or the database write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let id = db.upsert_system("core")?;
    /// assert!(!id.is_empty());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_system(&self, name: &str) -> anyhow::Result<String> {
        let name = name.trim();
        anyhow::ensure!(!name.is_empty(), "system name must not be empty");
        let conn = self.conn()?;
        if let Some(id) = conn
            .query_row("SELECT id FROM systems WHERE name = ?1", [name], |row| {
                row.get(0)
            })
            .optional()?
        {
            return Ok(id);
        }
        let id = new_id();
        conn.execute(
            "INSERT INTO systems (id, name, created_at) VALUES (?1, ?2, ?3)",
            params![id, name, now()],
        )?;
        Ok(id)
    }

    /// Rename a business system and return the affected row count.
    ///
    /// # Arguments
    /// - `old_name`: Previous name.
    /// - `new_name`: New name.
    ///
    /// # Returns
    /// Number of updated rows.
    ///
    /// # Errors
    /// Returns an error if the name is empty or `UPDATE` fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// # db.upsert_system("core")?;
    /// assert_eq!(db.rename_system("core", "core-renamed")?, 1);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn rename_system(&self, old_name: &str, new_name: &str) -> anyhow::Result<usize> {
        let old_name = old_name.trim();
        let new_name = new_name.trim();
        anyhow::ensure!(!old_name.is_empty(), "old system name must not be empty");
        anyhow::ensure!(!new_name.is_empty(), "new system name must not be empty");
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE systems SET name = ?1 WHERE name = ?2",
            params![new_name, old_name],
        )?;
        Ok(changed)
    }

    /// Delete a business system by name. Child assets are removed by foreign-key cascade.
    ///
    /// # Arguments
    /// - `name`: Business system name.
    ///
    /// # Returns
    /// Number of deleted rows.
    ///
    /// # Errors
    /// Returns an error if the name is empty or `DELETE` fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// # db.upsert_system("core")?;
    /// assert_eq!(db.delete_system("core")?, 1);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_system(&self, name: &str) -> anyhow::Result<usize> {
        let name = name.trim();
        anyhow::ensure!(!name.is_empty(), "system name must not be empty");
        let conn = self.conn()?;
        Ok(conn.execute("DELETE FROM systems WHERE name = ?1", [name])?)
    }

    /// Query business systems and asset counts by keyword.
    ///
    /// # Arguments
    /// - `keyword`: Optional name keyword.
    /// - `limit`: Maximum number of rows to return.
    ///
    /// # Returns
    /// Table rows, each with name, counts, and created-at.
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
    /// # db.upsert_system("core")?;
    /// let rows = db.query_systems(Some("core"), 10)?;
    /// assert_eq!(rows[0][0], "core");
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_systems(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let conn = self.conn()?;
        let mut stmt = conn.prepare(SYSTEM_SUMMARY_SQL)?;
        collect_rows(
            &mut stmt,
            params![pattern, limit as i64],
            map_system_summary,
        )
    }

    /// Export business systems and asset counts as CSV.
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
    /// db.export_systems(&dir.path().join("systems.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_systems(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            SYSTEM_EXPORT_SQL,
            &[
                "system",
                "names",
                "ips",
                "ports",
                "urls",
                "baseline_names",
                "baseline_ips",
                "baseline_ports",
                "baseline_urls",
                "created_at",
            ],
        )
    }
}

//! Application log writes, queries, export, and cleanup.

use std::path::Path;

use anyhow::Context;
use rusqlite::params;

use crate::{local_time, models::LogRow};

use super::{
    helpers::{collect_rows, map_log, new_id, now},
    types::Database,
};

impl Database {
    /// Write one application log row.
    ///
    /// # Arguments
    /// - `level`: Log level.
    /// - `target`: Log target.
    /// - `message`: Message.
    /// - `fields`: Optional structured fields.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.add_log("INFO", "watcher::test", "hello", None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn add_log(
        &self,
        level: &str,
        target: &str,
        message: &str,
        fields: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO logs (id, created_at, level, target, message, fields)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![new_id(), now(), level, target, message, fields],
        )?;
        Ok(())
    }

    /// Query application logs by level and keyword, newest first.
    ///
    /// # Arguments
    /// - `level`: Optional level.
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Log rows.
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
    /// let _ = db.query_logs(Some("INFO"), None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_logs(
        &self,
        level: Option<&str>,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<LogRow>> {
        let level = level.map(|value| value.to_ascii_uppercase());
        let pattern = keyword
            .map(|value| format!("%{value}%"))
            .unwrap_or_else(|| "%".to_string());
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, created_at, level, target, message, fields
             FROM logs
             WHERE (?1 IS NULL OR level = ?1)
               AND (message LIKE ?2 OR COALESCE(fields, '') LIKE ?2 OR target LIKE ?2)
             ORDER BY created_at DESC
             LIMIT ?3",
        )?;
        collect_rows(
            &mut stmt,
            params![level.as_deref(), pattern, limit as i64],
            map_log,
        )
    }

    /// Export application logs as CSV.
    ///
    /// # Arguments
    /// - `file`: Output CSV path.
    /// - `level`: Optional level.
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
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
    /// db.export_logs(&dir.path().join("logs.csv"), None, None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_logs(
        &self,
        file: &Path,
        level: Option<&str>,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<()> {
        let mut writer = csv::Writer::from_path(file)
            .with_context(|| format!("failed to create {}", file.display()))?;
        writer.write_record(["created_at", "level", "target", "message", "fields"])?;
        for row in self.query_logs(level, keyword, limit)? {
            writer.write_record([
                local_time::rfc3339_to_local(&row.created_at),
                row.level,
                row.target,
                row.message,
                row.fields.unwrap_or_default(),
            ])?;
        }
        writer.flush()?;
        Ok(())
    }

    /// Clear application logs and return the deleted row count.
    ///
    /// # Arguments
    /// - `before`: Delete only logs older than this timestamp; `None` means all logs.
    ///
    /// # Returns
    /// Number of deleted rows.
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
    /// let _ = db.clear_logs(None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn clear_logs(&self, before: Option<&str>) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        let deleted = match before {
            Some(before) => conn.execute("DELETE FROM logs WHERE created_at < ?1", [before])?,
            None => conn.execute("DELETE FROM logs", [])?,
        };
        Ok(deleted)
    }
}

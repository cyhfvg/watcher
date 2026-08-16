//! CLI asset queries.

use rusqlite::params;

use super::{
    helpers::{bool_text, collect_rows},
    types::Database,
};

impl Database {
    /// Query URLs by keyword.
    ///
    /// # Arguments
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
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
    /// let _ = db.query_urls(None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_urls(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_joined("urls", "url", keyword, limit)
    }

    /// Query baseline URLs.
    ///
    /// # Arguments
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
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
    /// let _ = db.query_baseline_urls(None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_baseline_urls(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_baseline_joined("urls", "url", keyword, limit)
    }

    /// Query ports by keyword.
    ///
    /// # Arguments
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
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
    /// let _ = db.query_ports(None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_ports(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT s.name, COALESCE(i.ip, '-'), p.port, p.state, COALESCE(p.service, '-'), COALESCE(p.scheme, '-'), p.is_baseline
             FROM ports p
             JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE CAST(p.port AS TEXT) LIKE ?1 OR COALESCE(i.ip, '') LIKE ?1
             ORDER BY s.name, i.ip, p.port LIMIT ?2",
        )?;
        collect_rows(&mut stmt, params![pattern, limit as i64], |row| {
            Ok(vec![
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?.to_string(),
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                bool_text(row.get::<_, i64>(6)? == 1).to_string(),
            ])
        })
    }

    /// Query baseline ports.
    ///
    /// # Arguments
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
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
    /// let _ = db.query_baseline_ports(None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_baseline_ports(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT s.name, COALESCE(i.ip, '-'), p.port, p.state, COALESCE(p.service, '-'), COALESCE(p.scheme, '-')
             FROM ports p
             JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE p.is_baseline = 1 AND (CAST(p.port AS TEXT) LIKE ?1 OR COALESCE(i.ip, '') LIKE ?1 OR s.name LIKE ?1)
             ORDER BY s.name, i.ip, p.port LIMIT ?2",
        )?;
        collect_rows(&mut stmt, params![pattern, limit as i64], |row| {
            Ok(vec![
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?.to_string(),
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ])
        })
    }

    /// Query IPs by keyword.
    ///
    /// # Arguments
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
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
    /// let _ = db.query_ips(None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_ips(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_joined("ip_addresses", "ip", keyword, limit)
    }

    /// Query baseline IPs.
    ///
    /// # Arguments
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
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
    /// let _ = db.query_baseline_ips(None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_baseline_ips(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_baseline_joined("ip_addresses", "ip", keyword, limit)
    }

    /// Query domain names by keyword.
    ///
    /// # Arguments
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
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
    /// let _ = db.query_names(None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_names(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_joined("domains", "name", keyword, limit)
    }

    /// Query baseline domain names.
    ///
    /// # Arguments
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
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
    /// let _ = db.query_baseline_names(None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_baseline_names(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_baseline_joined("domains", "name", keyword, limit)
    }

    /// Run a joined system/value query on an asset table.
    ///
    /// # Arguments
    /// - `table`: Table name.
    /// - `column`: Value column name.
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    ///
    /// # Examples
    /// ```text
    /// self.query_joined("urls", "url", None, 10)?;
    /// ```
    pub(crate) fn query_joined(
        &self,
        table: &str,
        column: &str,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let sql = format!(
            "SELECT s.name, t.{column}, t.is_baseline FROM {table} t JOIN systems s ON s.id = t.system_id WHERE t.{column} LIKE ?1 ORDER BY s.name, t.{column} LIMIT ?2"
        );
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&sql)?;
        collect_rows(&mut stmt, params![pattern, limit as i64], |row| {
            Ok(vec![
                row.get(0)?,
                row.get(1)?,
                bool_text(row.get::<_, i64>(2)? == 1).to_string(),
            ])
        })
    }

    /// Run a joined query of baseline rows on an asset table.
    ///
    /// # Arguments
    /// - `table`: Table name.
    /// - `column`: Value column name.
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    ///
    /// # Examples
    /// ```text
    /// self.query_baseline_joined("urls", "url", None, 10)?;
    /// ```
    pub(crate) fn query_baseline_joined(
        &self,
        table: &str,
        column: &str,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let sql = format!(
            "SELECT s.name, t.{column} FROM {table} t JOIN systems s ON s.id = t.system_id WHERE t.is_baseline = 1 AND (t.{column} LIKE ?1 OR s.name LIKE ?1) ORDER BY s.name, t.{column} LIMIT ?2"
        );
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&sql)?;
        collect_rows(&mut stmt, params![pattern, limit as i64], |row| {
            Ok(vec![row.get(0)?, row.get(1)?])
        })
    }

    /// Run a simple query on a non-system table.
    ///
    /// # Arguments
    /// - `table`: Table name.
    /// - `column`: Column name.
    /// - `keyword`: Optional keyword.
    /// - `limit`: Maximum number of rows.
    ///
    /// # Returns
    /// Table rows.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    ///
    /// # Examples
    /// ```text
    /// self.query_simple("dict_paths", "path", None, 10)?;
    /// ```
    pub(crate) fn query_simple(
        &self,
        table: &str,
        column: &str,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let sql = format!(
            "SELECT {column} FROM {table} WHERE {column} LIKE ?1 ORDER BY {column} LIMIT ?2"
        );
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&sql)?;
        collect_rows(&mut stmt, params![pattern, limit as i64], |row| {
            Ok(vec![row.get(0)?])
        })
    }

    /// Delete rows from a table by exact value.
    ///
    /// # Arguments
    /// - `table`: Table name.
    /// - `column`: Column name.
    /// - `value`: Exact value.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    ///
    /// # Examples
    /// ```text
    /// self.delete_by_value("urls", "url", value)?;
    /// ```
    pub(crate) fn delete_by_value(
        &self,
        table: &str,
        column: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        let sql = format!("DELETE FROM {table} WHERE {column} = ?1");
        conn.execute(&sql, [value])?;
        Ok(())
    }

    /// Delete rows by business system and exact value, returning the affected row count.
    ///
    /// # Arguments
    /// - `table`: Table name.
    /// - `column`: Column name.
    /// - `system`: Business system name.
    /// - `value`: Exact value.
    ///
    /// # Returns
    /// Number of deleted rows.
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    ///
    /// # Examples
    /// ```text
    /// self.delete_by_system_value("urls", "url", system, value)?;
    /// ```
    pub(crate) fn delete_by_system_value(
        &self,
        table: &str,
        column: &str,
        system: &str,
        value: &str,
    ) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        let sql = format!(
            "DELETE FROM {table} WHERE system_id = (SELECT id FROM systems WHERE name = ?1) AND {column} = ?2"
        );
        Ok(conn.execute(&sql, params![system, value])?)
    }

    /// Set the baseline flag by primary key.
    ///
    /// # Arguments
    /// - `table`: Table name.
    /// - `id`: Primary key.
    /// - `is_baseline`: Whether the asset is baseline.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```text
    /// self.set_baseline_by_id("domains", id, true)?;
    /// ```
    pub(crate) fn set_baseline_by_id(
        &self,
        table: &str,
        id: &str,
        is_baseline: bool,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        let sql = format!("UPDATE {table} SET is_baseline = ?1 WHERE id = ?2");
        conn.execute(&sql, params![is_baseline as i64, id])?;
        Ok(())
    }

    /// Set the baseline flag by business system and exact value.
    ///
    /// # Arguments
    /// - `table`: Table name.
    /// - `column`: Column name.
    /// - `system`: Business system name.
    /// - `value`: Exact value.
    /// - `is_baseline`: Whether the asset is baseline.
    ///
    /// # Returns
    /// Number of updated rows.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```text
    /// self.set_baseline_by_system_value("urls", "url", system, value, true)?;
    /// ```
    pub(crate) fn set_baseline_by_system_value(
        &self,
        table: &str,
        column: &str,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        let sql = format!(
            "UPDATE {table} SET is_baseline = ?1 WHERE system_id = (SELECT id FROM systems WHERE name = ?2) AND {column} = ?3"
        );
        Ok(conn.execute(&sql, params![is_baseline as i64, system, value])?)
    }
}

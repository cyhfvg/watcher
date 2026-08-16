//! CLI asset export.

use std::path::Path;

use anyhow::Context;

use super::types::Database;

impl Database {
    /// Export URLs as CSV.
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
    /// db.export_urls(&dir.path().join("urls.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_urls(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, u.url, u.source, COALESCE(u.status_code, ''), u.value_score, CASE WHEN u.is_baseline = 1 THEN 'true' ELSE 'false' END
             FROM urls u JOIN systems s ON s.id = u.system_id ORDER BY s.name, u.url",
            &["system", "url", "source", "status_code", "value_score", "baseline"],
        )
    }

    /// Export baseline URLs as CSV.
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
    /// db.export_baseline_urls(&dir.path().join("urls.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_baseline_urls(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, u.url, u.source, COALESCE(u.status_code, ''), u.value_score
             FROM urls u JOIN systems s ON s.id = u.system_id
             WHERE u.is_baseline = 1
             ORDER BY s.name, u.url",
            &["system", "url", "source", "status_code", "value_score"],
        )
    }

    /// Export ports as CSV.
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
    /// db.export_ports(&dir.path().join("ports.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_ports(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, COALESCE(i.ip, ''), p.port, p.state, COALESCE(p.service, ''), COALESCE(p.scheme, ''), CASE WHEN p.is_baseline = 1 THEN 'true' ELSE 'false' END
             FROM ports p JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id ORDER BY s.name, i.ip, p.port",
            &["system", "ip", "port", "state", "service", "scheme", "baseline"],
        )
    }

    /// Export baseline ports as CSV.
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
    /// db.export_baseline_ports(&dir.path().join("ports.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_baseline_ports(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, COALESCE(i.ip, ''), p.port, p.state, COALESCE(p.service, ''), COALESCE(p.scheme, '')
             FROM ports p JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE p.is_baseline = 1
             ORDER BY s.name, i.ip, p.port",
            &["system", "ip", "port", "state", "service", "scheme"],
        )
    }

    /// Export IPs as CSV.
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
    /// db.export_ips(&dir.path().join("ips.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_ips(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, i.ip, i.source, CASE WHEN i.is_baseline = 1 THEN 'true' ELSE 'false' END FROM ip_addresses i JOIN systems s ON s.id = i.system_id ORDER BY s.name, i.ip",
            &["system", "ip", "source", "baseline"],
        )
    }

    /// Export baseline IPs as CSV.
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
    /// db.export_baseline_ips(&dir.path().join("ips.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_baseline_ips(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, i.ip, i.source
             FROM ip_addresses i JOIN systems s ON s.id = i.system_id
             WHERE i.is_baseline = 1
             ORDER BY s.name, i.ip",
            &["system", "ip", "source"],
        )
    }

    /// Export domain names as CSV.
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
    /// db.export_names(&dir.path().join("names.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_names(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, d.name, COALESCE(d.bind_ip, ''), CASE WHEN d.is_baseline = 1 THEN 'true' ELSE 'false' END FROM domains d JOIN systems s ON s.id = d.system_id ORDER BY s.name, d.name",
            &["system", "name", "bind_ip", "baseline"],
        )
    }

    /// Export baseline domain names as CSV.
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
    /// db.export_baseline_names(&dir.path().join("names.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_baseline_names(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, d.name, COALESCE(d.bind_ip, '')
             FROM domains d JOIN systems s ON s.id = d.system_id
             WHERE d.is_baseline = 1
             ORDER BY s.name, d.name",
            &["system", "name", "bind_ip"],
        )
    }

    /// Export a fixed query as CSV.
    ///
    /// # Arguments
    /// - `file`: Output path.
    /// - `sql`: Query SQL.
    /// - `headers`: CSV headers.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the query or file write fails.
    ///
    /// # Examples
    /// ```text
    /// self.export_query(file, sql, &["col"])?;
    /// ```
    pub(crate) fn export_query(
        &self,
        file: &Path,
        sql: &str,
        headers: &[&str],
    ) -> anyhow::Result<()> {
        let mut writer = csv::Writer::from_path(file)
            .with_context(|| format!("failed to create {}", file.display()))?;
        writer.write_record(headers)?;
        let conn = self.conn()?;
        let mut stmt = conn.prepare(sql)?;
        let column_count = stmt.column_count();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let mut record = Vec::with_capacity(column_count);
            for index in 0..column_count {
                let value = row
                    .get_ref(index)?
                    .as_str()
                    .map(str::to_string)
                    .or_else(|_| row.get::<_, i64>(index).map(|v| v.to_string()))
                    .unwrap_or_default();
                record.push(value);
            }
            writer.write_record(record)?;
        }
        writer.flush()?;
        Ok(())
    }
}

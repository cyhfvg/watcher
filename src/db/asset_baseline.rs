//! Asset baseline marking.

use rusqlite::params;

use super::types::Database;

impl Database {
    /// Mark a domain as baseline or non-baseline by primary key.
    ///
    /// # Arguments
    /// - `id`: Domain primary key.
    /// - `is_baseline`: Whether the asset is baseline.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let id = db.upsert_domain_for_system("core", "example.com", None)?; db.set_domain_baseline_by_id(&id, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_domain_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("domains", id, is_baseline)
    }

    /// Mark an IP as baseline or non-baseline by primary key.
    ///
    /// # Arguments
    /// - `id`: IP primary key.
    /// - `is_baseline`: Whether the asset is baseline.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let id = db.upsert_ip_for_system("core", "10.0.0.1", "imported")?; db.set_ip_baseline_by_id(&id, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_ip_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("ip_addresses", id, is_baseline)
    }

    /// Mark a port as baseline or non-baseline by primary key.
    ///
    /// # Arguments
    /// - `id`: Port primary key.
    /// - `is_baseline`: Whether the asset is baseline.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let id = db.upsert_port_for_system("core", None, 80, "imported")?; db.set_port_baseline_by_id(&id, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_port_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("ports", id, is_baseline)
    }

    /// Mark a URL as baseline or non-baseline by primary key.
    ///
    /// # Arguments
    /// - `id`: URL primary key.
    /// - `is_baseline`: Whether the asset is baseline.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let id = db.upsert_url_for_system("core", "https://example.com", "imported")?; db.set_url_baseline_by_id(&id, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_url_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("urls", id, is_baseline)
    }

    /// Mark the given URL as baseline or non-baseline for a business system.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `value`: URL.
    /// - `is_baseline`: Whether the asset is baseline.
    ///
    /// # Returns
    /// Number of updated rows.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.upsert_url_for_system("core", "https://example.com", "imported")?; let _ = db.set_url_baseline_for_system("core", "https://example.com", true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_url_baseline_for_system(
        &self,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        self.set_baseline_by_system_value("urls", "url", system, value, is_baseline)
    }

    /// Mark a port as baseline or non-baseline by business system and optional IP.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `ip`: Optional bound IP.
    /// - `port`: Port number.
    /// - `is_baseline`: Whether the asset is baseline.
    ///
    /// # Returns
    /// Number of updated rows.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.upsert_port_for_system("core", Some("10.0.0.1"), 443, "imported")?; let _ = db.set_port_baseline_for_system("core", Some("10.0.0.1"), 443, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_port_baseline_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        port: u16,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "UPDATE ports
             SET is_baseline = ?1
             WHERE system_id = (SELECT id FROM systems WHERE name = ?2)
               AND port = ?3
               AND (?4 IS NULL OR ip_id IN (
                   SELECT id FROM ip_addresses
                   WHERE system_id = ports.system_id AND ip = ?4
               ))",
            params![is_baseline as i64, system, port, ip],
        )?)
    }

    /// Mark the given IP as baseline or non-baseline for a business system.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `value`: IP address.
    /// - `is_baseline`: Whether the asset is baseline.
    ///
    /// # Returns
    /// Number of updated rows.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.upsert_ip_for_system("core", "10.0.0.1", "imported")?; let _ = db.set_ip_baseline_for_system("core", "10.0.0.1", true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_ip_baseline_for_system(
        &self,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        self.set_baseline_by_system_value("ip_addresses", "ip", system, value, is_baseline)
    }

    /// Mark the given domain as baseline or non-baseline for a business system.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `value`: Domain name.
    /// - `is_baseline`: Whether the asset is baseline.
    ///
    /// # Returns
    /// Number of updated rows.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.upsert_domain_for_system("core", "example.com", None)?; let _ = db.set_name_baseline_for_system("core", "example.com", true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_name_baseline_for_system(
        &self,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        self.set_baseline_by_system_value("domains", "name", system, value, is_baseline)
    }
}

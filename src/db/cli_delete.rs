//! CLI asset deletion.

use rusqlite::params;

use super::types::Database;

impl Database {
    /// Delete a URL by exact value.
    ///
    /// # Arguments
    /// - `value`: URL.
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
    /// db.delete_url("https://example.com")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_url(&self, value: &str) -> anyhow::Result<()> {
        self.delete_by_value("urls", "url", value)
    }

    /// Delete a URL by business system and exact value.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `value`: URL.
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
    /// let _ = db.delete_url_for_system("core", "https://example.com")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_url_for_system(&self, system: &str, value: &str) -> anyhow::Result<usize> {
        self.delete_by_system_value("urls", "url", system, value)
    }

    /// Delete a port number from every system/IP.
    ///
    /// # Arguments
    /// - `value`: Port number.
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
    /// db.delete_port(80)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_port(&self, value: u16) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM ports WHERE port = ?1", [value])?;
        Ok(())
    }

    /// Delete a port by business system, optional IP, and exact port number.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `ip`: Optional bound IP.
    /// - `port`: Port number.
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
    /// let _ = db.delete_port_for_system("core", None, 80)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_port_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        port: u16,
    ) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "DELETE FROM ports
             WHERE system_id = (SELECT id FROM systems WHERE name = ?1)
               AND port = ?2
               AND (?3 IS NULL OR ip_id IN (
                   SELECT id FROM ip_addresses
                   WHERE system_id = ports.system_id AND ip = ?3
               ))",
            params![system, port, ip],
        )?)
    }

    /// Delete an IP by exact value.
    ///
    /// # Arguments
    /// - `value`: IP address.
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
    /// db.delete_ip("10.0.0.1")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_ip(&self, value: &str) -> anyhow::Result<()> {
        self.delete_by_value("ip_addresses", "ip", value)
    }

    /// Delete an IP by business system and exact value.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `value`: IP address.
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
    /// let _ = db.delete_ip_for_system("core", "10.0.0.1")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_ip_for_system(&self, system: &str, value: &str) -> anyhow::Result<usize> {
        self.delete_by_system_value("ip_addresses", "ip", system, value)
    }

    /// Delete a domain name by exact value.
    ///
    /// # Arguments
    /// - `value`: Domain name.
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
    /// db.delete_name("example.com")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_name(&self, value: &str) -> anyhow::Result<()> {
        self.delete_by_value("domains", "name", value)
    }

    /// Delete a domain name by business system and exact value.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `value`: Domain name.
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
    /// let _ = db.delete_name_for_system("core", "example.com")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_name_for_system(&self, system: &str, value: &str) -> anyhow::Result<usize> {
        self.delete_by_system_value("domains", "name", system, value)
    }
}

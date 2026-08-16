//! Domain/IP/URL/port asset writes and baseline marking.

use rusqlite::{OptionalExtension, params};

use super::{
    helpers::{new_id, now},
    types::Database,
};

impl Database {
    /// Insert or update a domain asset by business-system name.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `name`: Domain name.
    /// - `bind_ip`: Optional bound IP.
    ///
    /// # Returns
    /// Domain primary key.
    ///
    /// # Errors
    /// Returns an error if the system or domain write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.upsert_domain_for_system("core", "example.com", None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_domain_for_system(
        &self,
        system: &str,
        name: &str,
        bind_ip: Option<&str>,
    ) -> anyhow::Result<String> {
        let system_id = self.upsert_system(system)?;
        self.upsert_domain(&system_id, name, bind_ip)
    }

    /// Insert or update a baseline domain asset by business-system name.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `name`: Domain name.
    /// - `bind_ip`: Optional bound IP.
    ///
    /// # Returns
    /// Domain primary key.
    ///
    /// # Errors
    /// Returns an error if the write or baseline mark fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.upsert_baseline_domain_for_system("core", "example.com", None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_baseline_domain_for_system(
        &self,
        system: &str,
        name: &str,
        bind_ip: Option<&str>,
    ) -> anyhow::Result<String> {
        let id = self.upsert_domain_for_system(system, name, bind_ip)?;
        self.set_domain_baseline_by_id(&id, true)?;
        Ok(id)
    }

    /// Insert or update a domain asset by system id.
    ///
    /// # Arguments
    /// - `system_id`: Business-system primary key.
    /// - `name`: Domain name.
    /// - `bind_ip`: Optional bound IP.
    ///
    /// # Returns
    /// Domain primary key.
    ///
    /// # Errors
    /// Returns an error if the domain name is empty or the write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let id = db.upsert_system("core")?; let _ = db.upsert_domain(&id, "example.com", None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_domain(
        &self,
        system_id: &str,
        name: &str,
        bind_ip: Option<&str>,
    ) -> anyhow::Result<String> {
        let name = name.trim().trim_end_matches('.');
        anyhow::ensure!(!name.is_empty(), "domain name must not be empty");
        let conn = self.conn()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM domains WHERE system_id = ?1 AND name = ?2",
                params![system_id, name],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => {
                conn.execute(
                    "UPDATE domains SET bind_ip = COALESCE(?1, bind_ip), updated_at = ?2 WHERE id = ?3",
                    params![bind_ip, now(), id],
                )?;
                Ok(id)
            }
            None => {
                let id = new_id();
                conn.execute(
                    "INSERT INTO domains (id, system_id, name, bind_ip, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                    params![id, system_id, name, bind_ip, now()],
                )?;
                Ok(id)
            }
        }
    }

    /// Insert or update an IP asset by business-system name.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `ip`: IP address.
    /// - `source`: Source tag.
    ///
    /// # Returns
    /// IP primary key.
    ///
    /// # Errors
    /// Returns an error if the system or IP write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.upsert_ip_for_system("core", "10.0.0.1", "imported")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_ip_for_system(
        &self,
        system: &str,
        ip: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let system_id = self.upsert_system(system)?;
        self.upsert_ip(&system_id, ip, source)
    }

    /// Insert or update a baseline IP asset by business-system name.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `ip`: IP address.
    /// - `source`: Source tag.
    ///
    /// # Returns
    /// IP primary key.
    ///
    /// # Errors
    /// Returns an error if the write or baseline mark fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.upsert_baseline_ip_for_system("core", "10.0.0.1", "imported")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_baseline_ip_for_system(
        &self,
        system: &str,
        ip: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let id = self.upsert_ip_for_system(system, ip, source)?;
        self.set_ip_baseline_by_id(&id, true)?;
        Ok(id)
    }

    /// Insert or update an IP asset by system id.
    ///
    /// # Arguments
    /// - `system_id`: Business-system primary key.
    /// - `ip`: IP address.
    /// - `source`: Source tag.
    ///
    /// # Returns
    /// IP primary key.
    ///
    /// # Errors
    /// Returns an error if the IP is empty or the write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let id = db.upsert_system("core")?; let _ = db.upsert_ip(&id, "10.0.0.1", "imported")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_ip(&self, system_id: &str, ip: &str, source: &str) -> anyhow::Result<String> {
        let ip = ip.trim();
        anyhow::ensure!(!ip.is_empty(), "ip must not be empty");
        let conn = self.conn()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM ip_addresses WHERE system_id = ?1 AND ip = ?2",
                params![system_id, ip],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => {
                conn.execute(
                    "UPDATE ip_addresses SET source = CASE WHEN source = 'resolved' THEN ?1 ELSE source END, updated_at = ?2 WHERE id = ?3",
                    params![source, now(), id],
                )?;
                Ok(id)
            }
            None => {
                let id = new_id();
                conn.execute(
                    "INSERT INTO ip_addresses (id, system_id, ip, source, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                    params![id, system_id, ip, source, now()],
                )?;
                Ok(id)
            }
        }
    }

    /// Insert or update a URL asset by business-system name.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `url`: URL.
    /// - `source`: Source tag.
    ///
    /// # Returns
    /// URL primary key.
    ///
    /// # Errors
    /// Returns an error if the system or URL write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.upsert_url_for_system("core", "https://example.com", "imported")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_url_for_system(
        &self,
        system: &str,
        url: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let system_id = self.upsert_system(system)?;
        self.upsert_url(&system_id, url, source, None, 0)
    }

    /// Insert or update a baseline URL asset by business-system name.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `url`: URL.
    /// - `source`: Source tag.
    ///
    /// # Returns
    /// URL primary key.
    ///
    /// # Errors
    /// Returns an error if the write or baseline mark fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.upsert_baseline_url_for_system("core", "https://example.com", "imported")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_baseline_url_for_system(
        &self,
        system: &str,
        url: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let id = self.upsert_url_for_system(system, url, source)?;
        self.set_url_baseline_by_id(&id, true)?;
        Ok(id)
    }

    /// Insert or update a URL asset by system id.
    ///
    /// # Arguments
    /// - `system_id`: Business-system primary key.
    /// - `url`: URL.
    /// - `source`: Source tag.
    /// - `status_code`: Optional HTTP status code.
    /// - `value_score`: Value score.
    ///
    /// # Returns
    /// URL primary key.
    ///
    /// # Errors
    /// Returns an error if the URL is empty or the write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let id = db.upsert_system("core")?; let _ = db.upsert_url(&id, "https://example.com", "imported", None, 0)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_url(
        &self,
        system_id: &str,
        url: &str,
        source: &str,
        status_code: Option<u16>,
        value_score: i64,
    ) -> anyhow::Result<String> {
        let url = url.trim();
        anyhow::ensure!(!url.is_empty(), "url must not be empty");
        let conn = self.conn()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM urls WHERE system_id = ?1 AND url = ?2",
                params![system_id, url],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => {
                conn.execute(
                    "UPDATE urls
                     SET source = CASE WHEN source = 'imported' THEN source ELSE ?1 END,
                         status_code = COALESCE(?2, status_code),
                         value_score = MAX(value_score, ?3),
                         updated_at = ?4
                     WHERE id = ?5",
                    params![source, status_code, value_score, now(), id],
                )?;
                Ok(id)
            }
            None => {
                let id = new_id();
                conn.execute(
                    "INSERT INTO urls (id, system_id, url, source, status_code, value_score, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                    params![id, system_id, url, source, status_code, value_score, now()],
                )?;
                Ok(id)
            }
        }
    }

    /// Insert or update a port asset by business-system name.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `ip`: Optional bound IP.
    /// - `port`: Port number.
    /// - `source`: Source tag.
    ///
    /// # Returns
    /// Port primary key.
    ///
    /// # Errors
    /// Returns an error if the system or port write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.upsert_port_for_system("core", Some("10.0.0.1"), 443, "imported")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_port_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        port: u16,
        source: &str,
    ) -> anyhow::Result<String> {
        let system_id = self.upsert_system(system)?;
        let ip_id = match ip {
            Some(ip) if !ip.trim().is_empty() => Some(self.upsert_ip(&system_id, ip, source)?),
            _ => None,
        };
        self.upsert_port(&system_id, ip_id.as_deref(), port, source)
    }

    /// Insert or update a baseline port asset by business-system name.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `ip`: Optional bound IP.
    /// - `port`: Port number.
    /// - `source`: Source tag.
    ///
    /// # Returns
    /// Port primary key.
    ///
    /// # Errors
    /// Returns an error if the write or baseline mark fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.upsert_baseline_port_for_system("core", Some("10.0.0.1"), 443, "imported")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_baseline_port_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        port: u16,
        source: &str,
    ) -> anyhow::Result<String> {
        let id = self.upsert_port_for_system(system, ip, port, source)?;
        self.set_port_baseline_by_id(&id, true)?;
        Ok(id)
    }

    /// Insert or update a port by system id and optional IP id.
    ///
    /// # Arguments
    /// - `system_id`: Business-system primary key.
    /// - `ip_id`: Optional IP primary key.
    /// - `port`: Port number.
    /// - `source`: Source tag.
    ///
    /// # Returns
    /// Port primary key.
    ///
    /// # Errors
    /// Returns an error if the write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let sid = db.upsert_system("core")?; let _ = db.upsert_port(&sid, None, 80, "imported")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_port(
        &self,
        system_id: &str,
        ip_id: Option<&str>,
        port: u16,
        source: &str,
    ) -> anyhow::Result<String> {
        let conn = self.conn()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM ports WHERE system_id = ?1 AND ((ip_id IS NULL AND ?2 IS NULL) OR ip_id = ?2) AND port = ?3",
                params![system_id, ip_id, port],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => Ok(id),
            None => {
                let id = new_id();
                conn.execute(
                    "INSERT INTO ports (id, system_id, ip_id, port, source, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    params![id, system_id, ip_id, port, source, now()],
                )?;
                Ok(id)
            }
        }
    }
}

//! Bulk port import.

use rusqlite::{OptionalExtension, params};

use super::{
    helpers::{ensure_system_in_tx, new_id, now, trimmed_opt},
    types::Database,
};

impl Database {
    /// Bulk-import baseline ports for one business system and an optional IP.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `ip`: Optional bound IP.
    /// - `ports`: Port list.
    /// - `source`: Source tag.
    ///
    /// # Returns
    /// Number of processed items.
    ///
    /// # Errors
    /// Returns an error if the system name is empty or the write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.import_baseline_ports_for_system("core", None, &[80, 443], "manual")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_baseline_ports_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        ports: &[u16],
        source: &str,
    ) -> anyhow::Result<usize> {
        let system = system.trim();
        anyhow::ensure!(!system.is_empty(), "system name must not be empty");
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let system_id = ensure_system_in_tx(&tx, system)?;
        let ip_id = if let Some(ip) = trimmed_opt(ip) {
            tx.execute(
                "INSERT INTO ip_addresses (id, system_id, ip, source, is_baseline, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
                 ON CONFLICT(system_id, ip) DO UPDATE SET
                    source = CASE WHEN ip_addresses.source = 'resolved' THEN excluded.source ELSE ip_addresses.source END,
                    is_baseline = 1,
                    updated_at = excluded.updated_at",
                params![new_id(), system_id, ip, source, now()],
            )?;
            Some(tx.query_row(
                "SELECT id FROM ip_addresses WHERE system_id = ?1 AND ip = ?2",
                params![system_id, ip],
                |row| row.get::<_, String>(0),
            )?)
        } else {
            None
        };
        let mut count = 0usize;
        {
            let mut select_port = tx.prepare(
                "SELECT id FROM ports
                 WHERE system_id = ?1
                   AND ((ip_id IS NULL AND ?2 IS NULL) OR ip_id = ?2)
                   AND port = ?3",
            )?;
            let mut insert_port = tx.prepare(
                "INSERT INTO ports (id, system_id, ip_id, port, source, is_baseline, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
            )?;
            let mut mark_port_baseline =
                tx.prepare("UPDATE ports SET is_baseline = 1, last_seen = ?1 WHERE id = ?2")?;
            for port in ports {
                if let Some(id) = select_port
                    .query_row(params![system_id, ip_id.as_deref(), *port], |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()?
                {
                    mark_port_baseline.execute(params![now(), id])?;
                } else {
                    insert_port.execute(params![
                        new_id(),
                        system_id,
                        ip_id.as_deref(),
                        *port,
                        source,
                        now()
                    ])?;
                }
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// Bulk-import non-baseline ports for one business system and an optional IP.
    ///
    /// # Arguments
    /// - `system`: Business system name.
    /// - `ip`: Optional bound IP.
    /// - `ports`: Port list.
    /// - `source`: Source tag.
    ///
    /// # Returns
    /// Number of processed items.
    ///
    /// # Errors
    /// Returns an error if the system name is empty or the write fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.import_ports_for_system("core", Some("10.0.0.1"), &[8080], "manual")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_ports_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        ports: &[u16],
        source: &str,
    ) -> anyhow::Result<usize> {
        let system = system.trim();
        anyhow::ensure!(!system.is_empty(), "system name must not be empty");
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let system_id = ensure_system_in_tx(&tx, system)?;
        let ip_id = if let Some(ip) = trimmed_opt(ip) {
            tx.execute(
                "INSERT INTO ip_addresses (id, system_id, ip, source, is_baseline, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)
                 ON CONFLICT(system_id, ip) DO UPDATE SET
                    source = CASE WHEN ip_addresses.source = 'resolved' THEN excluded.source ELSE ip_addresses.source END,
                    updated_at = excluded.updated_at",
                params![new_id(), system_id, ip, source, now()],
            )?;
            Some(tx.query_row(
                "SELECT id FROM ip_addresses WHERE system_id = ?1 AND ip = ?2",
                params![system_id, ip],
                |row| row.get::<_, String>(0),
            )?)
        } else {
            None
        };
        let mut count = 0usize;
        {
            let mut select_port = tx.prepare(
                "SELECT id FROM ports
                 WHERE system_id = ?1
                   AND ((ip_id IS NULL AND ?2 IS NULL) OR ip_id = ?2)
                   AND port = ?3",
            )?;
            let mut insert_port = tx.prepare(
                "INSERT INTO ports (id, system_id, ip_id, port, source, is_baseline, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?6)",
            )?;
            let mut touch_port = tx.prepare("UPDATE ports SET last_seen = ?1 WHERE id = ?2")?;
            for port in ports {
                if let Some(id) = select_port
                    .query_row(params![system_id, ip_id.as_deref(), *port], |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()?
                {
                    touch_port.execute(params![now(), id])?;
                } else {
                    insert_port.execute(params![
                        new_id(),
                        system_id,
                        ip_id.as_deref(),
                        *port,
                        source,
                        now()
                    ])?;
                }
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }
}

//! Paged alert, vulnerability, and batch inventory queries.

use rusqlite::params;

use crate::models::{Alert, AssetPage, AssetQuery, BatchRow, Vulnerability};

use super::{
    helpers::collect_rows,
    inventory::{count_rows, like_pattern},
    types::Database,
};

impl Database {
    /// List alerts for one batch, optionally restricted to a business system.
    ///
    /// When `batch_id` is `None`, the latest batch is used. If no batch exists,
    /// an empty page is returned.
    ///
    /// # Arguments
    /// - `batch_id`: Optional batch id. `None` selects the latest batch.
    /// - `query`: Optional exact system name, keyword, limit, and offset.
    ///
    /// # Returns
    /// One page of matching [`Alert`] rows, newest last.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # use watcher::models::AssetQuery;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let page = db.list_alerts_filtered(None, &AssetQuery::default())?;
    /// assert!(page.items.is_empty());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_alerts_filtered(
        &self,
        batch_id: Option<&str>,
        query: &AssetQuery,
    ) -> anyhow::Result<AssetPage<Alert>> {
        let query = query.clone().sanitized();
        let Some(batch_id) = self.resolve_batch_id(batch_id)? else {
            return Ok(AssetPage::empty(&query));
        };
        let pattern = like_pattern(query.keyword.as_deref());
        let conn = self.conn()?;
        let total = count_rows(
            &conn,
            "SELECT COUNT(*)
             FROM alerts a
             LEFT JOIN systems s ON s.id = a.system_id
             WHERE a.batch_id = ?1
               AND (?2 IS NULL OR s.name = ?2)
               AND (?3 = '%' OR COALESCE(s.name, '') LIKE ?3 OR a.kind LIKE ?3 OR a.subject LIKE ?3 OR a.severity LIKE ?3)",
            params![batch_id, query.system, pattern],
        )?;
        let mut stmt = conn.prepare(
            "SELECT a.id, a.batch_id, a.system_id, s.name, a.kind, a.severity, a.subject, a.old_value, a.new_value, a.details, a.created_at
             FROM alerts a
             LEFT JOIN systems s ON s.id = a.system_id
             WHERE a.batch_id = ?1
               AND (?2 IS NULL OR s.name = ?2)
               AND (?3 = '%' OR COALESCE(s.name, '') LIKE ?3 OR a.kind LIKE ?3 OR a.subject LIKE ?3 OR a.severity LIKE ?3)
             ORDER BY a.created_at
             LIMIT ?4 OFFSET ?5",
        )?;
        let items = collect_rows(
            &mut stmt,
            params![
                batch_id,
                query.system,
                pattern,
                query.limit as i64,
                query.offset as i64
            ],
            |row| {
                let created_at: String = row.get(10)?;
                Ok(Alert {
                    id: row.get(0)?,
                    batch_id: row.get(1)?,
                    system_id: row.get(2)?,
                    system_name: row.get(3)?,
                    kind: row.get(4)?,
                    severity: row.get(5)?,
                    subject: row.get(6)?,
                    old_value: row.get(7)?,
                    new_value: row.get(8)?,
                    details: row.get(9)?,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_at)?
                        .with_timezone(&chrono::Utc),
                })
            },
        )?;
        Ok(AssetPage::new(items, total, query.offset, query.limit))
    }

    /// List vulnerabilities for one batch, optionally restricted to a business system.
    ///
    /// When `batch_id` is `None`, the latest batch is used. If no batch exists,
    /// an empty page is returned.
    ///
    /// # Arguments
    /// - `batch_id`: Optional batch id. `None` selects the latest batch.
    /// - `query`: Optional exact system name, keyword, limit, and offset.
    ///
    /// # Returns
    /// One page of matching [`Vulnerability`] rows, newest last.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # use watcher::models::AssetQuery;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let page = db.list_vulnerabilities_filtered(None, &AssetQuery::default())?;
    /// assert!(page.items.is_empty());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_vulnerabilities_filtered(
        &self,
        batch_id: Option<&str>,
        query: &AssetQuery,
    ) -> anyhow::Result<AssetPage<Vulnerability>> {
        let query = query.clone().sanitized();
        let Some(batch_id) = self.resolve_batch_id(batch_id)? else {
            return Ok(AssetPage::empty(&query));
        };
        let pattern = like_pattern(query.keyword.as_deref());
        let conn = self.conn()?;
        let total = count_rows(
            &conn,
            "SELECT COUNT(*)
             FROM vulnerabilities v
             JOIN systems s ON s.id = v.system_id
             WHERE v.batch_id = ?1
               AND (?2 IS NULL OR s.name = ?2)
               AND (?3 = '%' OR s.name LIKE ?3 OR v.url LIKE ?3 OR v.poc LIKE ?3 OR v.severity LIKE ?3)",
            params![batch_id, query.system, pattern],
        )?;
        let mut stmt = conn.prepare(
            "SELECT v.id, v.batch_id, v.system_id, s.name, v.url, v.poc, v.severity, v.evidence, v.created_at
             FROM vulnerabilities v
             JOIN systems s ON s.id = v.system_id
             WHERE v.batch_id = ?1
               AND (?2 IS NULL OR s.name = ?2)
               AND (?3 = '%' OR s.name LIKE ?3 OR v.url LIKE ?3 OR v.poc LIKE ?3 OR v.severity LIKE ?3)
             ORDER BY v.created_at
             LIMIT ?4 OFFSET ?5",
        )?;
        let items = collect_rows(
            &mut stmt,
            params![
                batch_id,
                query.system,
                pattern,
                query.limit as i64,
                query.offset as i64
            ],
            |row| {
                let created_at: String = row.get(8)?;
                Ok(Vulnerability {
                    id: row.get(0)?,
                    batch_id: row.get(1)?,
                    system_id: row.get(2)?,
                    system_name: row.get(3)?,
                    url: row.get(4)?,
                    poc: row.get(5)?,
                    severity: row.get(6)?,
                    evidence: row.get(7)?,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_at)?
                        .with_timezone(&chrono::Utc),
                })
            },
        )?;
        Ok(AssetPage::new(items, total, query.offset, query.limit))
    }

    /// List monitoring batches as a bounded page.
    ///
    /// # Arguments
    /// - `query`: Limit and offset. System/keyword filters are ignored.
    ///
    /// # Returns
    /// One page of [`BatchRow`] values, newest first.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # use watcher::models::AssetQuery;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let page = db.list_batches_page(&AssetQuery { limit: 20, ..AssetQuery::default() })?;
    /// assert!(page.items.is_empty());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_batches_page(&self, query: &AssetQuery) -> anyhow::Result<AssetPage<BatchRow>> {
        let query = query.clone().sanitize(20);
        let conn = self.conn()?;
        let total = count_rows(&conn, "SELECT COUNT(*) FROM batches", [])?;
        let mut stmt = conn.prepare(
            "SELECT id, status, started_at, ended_at, report_zip
             FROM batches
             ORDER BY started_at DESC
             LIMIT ?1 OFFSET ?2",
        )?;
        let items = collect_rows(
            &mut stmt,
            params![query.limit as i64, query.offset as i64],
            |row| {
                Ok(BatchRow {
                    id: row.get(0)?,
                    status: row.get(1)?,
                    started_at: row.get(2)?,
                    ended_at: row.get(3)?,
                    report_zip: row.get(4)?,
                })
            },
        )?;
        Ok(AssetPage::new(items, total, query.offset, query.limit))
    }
}

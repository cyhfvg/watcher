//! Filtered inventory queries for live ports, web services, and URL status.

use rusqlite::params;

use crate::models::{
    AssetPage, AssetQuery, DomainAsset, IpAsset, PortAsset, SystemSummary, UrlAsset,
};

use super::{
    helpers::{collect_rows, map_ip, map_port, map_url},
    types::Database,
};

impl Database {
    /// List business-system summaries matching an inventory query.
    ///
    /// # Arguments
    /// - `query`: Optional exact system name, keyword, limit, and offset.
    ///
    /// # Returns
    /// One page of [`SystemSummary`] rows ordered by name.
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
    /// # db.upsert_system("core")?;
    /// let page = db.list_system_summaries(&AssetQuery::default())?;
    /// assert_eq!(page.items[0].name, "core");
    /// assert_eq!(page.total, 1);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_system_summaries(
        &self,
        query: &AssetQuery,
    ) -> anyhow::Result<AssetPage<SystemSummary>> {
        let query = query.clone().sanitized();
        let pattern = like_pattern(query.keyword.as_deref());
        let conn = self.conn()?;
        let total = count_rows(
            &conn,
            "SELECT COUNT(*) FROM systems s
             WHERE (?1 IS NULL OR s.name = ?1)
               AND (?2 = '%' OR s.name LIKE ?2)",
            params![query.system, pattern],
        )?;
        let mut stmt = conn.prepare(
            "SELECT
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
             WHERE (?1 IS NULL OR s.name = ?1)
               AND (?2 = '%' OR s.name LIKE ?2)
             ORDER BY s.name
             LIMIT ?3 OFFSET ?4",
        )?;
        let items = collect_rows(
            &mut stmt,
            params![
                query.system,
                pattern,
                query.limit as i64,
                query.offset as i64
            ],
            map_system_summary_row,
        )?;
        Ok(AssetPage::new(items, total, query.offset, query.limit))
    }

    /// List currently open TCP ports matching an inventory query.
    ///
    /// # Arguments
    /// - `query`: Optional exact system name, keyword, limit, and offset.
    ///
    /// # Returns
    /// One page of open [`PortAsset`] rows.
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
    /// let page = db.list_open_ports_filtered(&AssetQuery::default())?;
    /// assert!(!page.has_more);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_open_ports_filtered(
        &self,
        query: &AssetQuery,
    ) -> anyhow::Result<AssetPage<PortAsset>> {
        self.list_ports_filtered(query, false)
    }

    /// List open ports identified as HTTP(S) web services.
    ///
    /// # Arguments
    /// - `query`: Optional exact system name, keyword, limit, and offset.
    ///
    /// # Returns
    /// One page of web [`PortAsset`] rows.
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
    /// let _ = db.list_web_services_filtered(&AssetQuery::default())?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_web_services_filtered(
        &self,
        query: &AssetQuery,
    ) -> anyhow::Result<AssetPage<PortAsset>> {
        self.list_ports_filtered(query, true)
    }

    /// List URLs whose latest status is HTTP 2xx or 3xx.
    ///
    /// # Arguments
    /// - `query`: Optional exact system name, keyword, limit, and offset.
    ///
    /// # Returns
    /// One page of live [`UrlAsset`] rows.
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
    /// let _ = db.list_live_urls_filtered(&AssetQuery::default())?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_live_urls_filtered(
        &self,
        query: &AssetQuery,
    ) -> anyhow::Result<AssetPage<UrlAsset>> {
        self.list_urls_filtered(query, true)
    }

    /// List URL assets matching an inventory query, including unprobed and failed URLs.
    ///
    /// # Arguments
    /// - `query`: Optional exact system name, keyword, limit, and offset.
    /// - `live_only`: When true, keep only HTTP 2xx/3xx URLs.
    ///
    /// # Returns
    /// One page of matching [`UrlAsset`] rows.
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
    /// let _ = db.list_urls_filtered(&AssetQuery::default(), false)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_urls_filtered(
        &self,
        query: &AssetQuery,
        live_only: bool,
    ) -> anyhow::Result<AssetPage<UrlAsset>> {
        let query = query.clone().sanitized();
        let pattern = like_pattern(query.keyword.as_deref());
        let live = i64::from(live_only);
        let conn = self.conn()?;
        let total = count_rows(
            &conn,
            "SELECT COUNT(*)
             FROM urls u
             JOIN systems s ON s.id = u.system_id
             WHERE (?1 IS NULL OR s.name = ?1)
               AND (?2 = '%' OR s.name LIKE ?2 OR u.url LIKE ?2 OR CAST(COALESCE(u.status_code, '') AS TEXT) LIKE ?2)
               AND (?3 = 0 OR (u.status_code BETWEEN 200 AND 399))",
            params![query.system, pattern, live],
        )?;
        let mut stmt = conn.prepare(
            "SELECT u.id, u.system_id, s.name, u.url, u.source, u.status_code, u.value_score, u.is_baseline
             FROM urls u
             JOIN systems s ON s.id = u.system_id
             WHERE (?1 IS NULL OR s.name = ?1)
               AND (?2 = '%' OR s.name LIKE ?2 OR u.url LIKE ?2 OR CAST(COALESCE(u.status_code, '') AS TEXT) LIKE ?2)
               AND (?3 = 0 OR (u.status_code BETWEEN 200 AND 399))
             ORDER BY s.name, u.url
             LIMIT ?4 OFFSET ?5",
        )?;
        let items = collect_rows(
            &mut stmt,
            params![
                query.system,
                pattern,
                live,
                query.limit as i64,
                query.offset as i64
            ],
            |row| Ok(map_url(row)?),
        )?;
        Ok(AssetPage::new(items, total, query.offset, query.limit))
    }

    /// List IP assets matching an inventory query.
    ///
    /// # Arguments
    /// - `query`: Optional exact system name, keyword, limit, and offset.
    ///
    /// # Returns
    /// One page of matching [`IpAsset`] rows, including resolved IPs.
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
    /// let _ = db.list_ips_filtered(&AssetQuery::default())?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_ips_filtered(&self, query: &AssetQuery) -> anyhow::Result<AssetPage<IpAsset>> {
        let query = query.clone().sanitized();
        let pattern = like_pattern(query.keyword.as_deref());
        let conn = self.conn()?;
        let total = count_rows(
            &conn,
            "SELECT COUNT(*)
             FROM ip_addresses i
             JOIN systems s ON s.id = i.system_id
             WHERE (?1 IS NULL OR s.name = ?1)
               AND (?2 = '%' OR s.name LIKE ?2 OR i.ip LIKE ?2 OR i.source LIKE ?2)",
            params![query.system, pattern],
        )?;
        let mut stmt = conn.prepare(
            "SELECT i.id, i.system_id, s.name, i.ip, i.source, i.is_baseline
             FROM ip_addresses i
             JOIN systems s ON s.id = i.system_id
             WHERE (?1 IS NULL OR s.name = ?1)
               AND (?2 = '%' OR s.name LIKE ?2 OR i.ip LIKE ?2 OR i.source LIKE ?2)
             ORDER BY s.name, i.ip
             LIMIT ?3 OFFSET ?4",
        )?;
        let items = collect_rows(
            &mut stmt,
            params![
                query.system,
                pattern,
                query.limit as i64,
                query.offset as i64
            ],
            |row| Ok(map_ip(row)?),
        )?;
        Ok(AssetPage::new(items, total, query.offset, query.limit))
    }

    /// List domain assets matching an inventory query.
    ///
    /// # Arguments
    /// - `query`: Optional exact system name, keyword, limit, and offset.
    ///
    /// # Returns
    /// One page of matching [`DomainAsset`] rows.
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
    /// let _ = db.list_domains_filtered(&AssetQuery::default())?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_domains_filtered(
        &self,
        query: &AssetQuery,
    ) -> anyhow::Result<AssetPage<DomainAsset>> {
        let query = query.clone().sanitized();
        let pattern = like_pattern(query.keyword.as_deref());
        let conn = self.conn()?;
        let total = count_rows(
            &conn,
            "SELECT COUNT(*)
             FROM domains d
             JOIN systems s ON s.id = d.system_id
             WHERE (?1 IS NULL OR s.name = ?1)
               AND (?2 = '%' OR s.name LIKE ?2 OR d.name LIKE ?2 OR COALESCE(d.bind_ip, '') LIKE ?2)",
            params![query.system, pattern],
        )?;
        let mut stmt = conn.prepare(
            "SELECT d.id, d.system_id, s.name, d.name, d.bind_ip, d.is_baseline
             FROM domains d
             JOIN systems s ON s.id = d.system_id
             WHERE (?1 IS NULL OR s.name = ?1)
               AND (?2 = '%' OR s.name LIKE ?2 OR d.name LIKE ?2 OR COALESCE(d.bind_ip, '') LIKE ?2)
             ORDER BY s.name, d.name
             LIMIT ?3 OFFSET ?4",
        )?;
        let items = collect_rows(
            &mut stmt,
            params![
                query.system,
                pattern,
                query.limit as i64,
                query.offset as i64
            ],
            |row| {
                Ok(DomainAsset {
                    id: row.get(0)?,
                    system_id: row.get(1)?,
                    system_name: row.get(2)?,
                    name: row.get(3)?,
                    bind_ip: row.get(4)?,
                    is_baseline: row.get::<_, i64>(5)? == 1,
                })
            },
        )?;
        Ok(AssetPage::new(items, total, query.offset, query.limit))
    }

    /// Shared filtered port query for open ports and web services.
    ///
    /// # Arguments
    /// - `query`: Optional exact system name, keyword, limit, and offset.
    /// - `web_only`: When true, keep only open ports marked `is_web`.
    ///
    /// # Returns
    /// One page of matching [`PortAsset`] rows.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    fn list_ports_filtered(
        &self,
        query: &AssetQuery,
        web_only: bool,
    ) -> anyhow::Result<AssetPage<PortAsset>> {
        let query = query.clone().sanitized();
        let pattern = like_pattern(query.keyword.as_deref());
        let web = i64::from(web_only);
        let conn = self.conn()?;
        let total = count_rows(
            &conn,
            "SELECT COUNT(*)
             FROM ports p
             JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE p.state = 'open'
               AND (?1 IS NULL OR s.name = ?1)
               AND (?2 = 0 OR p.is_web = 1)
               AND (
                    ?3 = '%'
                    OR s.name LIKE ?3
                    OR COALESCE(i.ip, '') LIKE ?3
                    OR CAST(p.port AS TEXT) LIKE ?3
                    OR COALESCE(p.service, '') LIKE ?3
                    OR COALESCE(p.fingerprint, '') LIKE ?3
               )",
            params![query.system, web, pattern],
        )?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.system_id, s.name, p.ip_id, i.ip, p.port, p.state, p.service, p.fingerprint, p.is_web, p.scheme, p.is_baseline
             FROM ports p
             JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE p.state = 'open'
               AND (?1 IS NULL OR s.name = ?1)
               AND (?2 = 0 OR p.is_web = 1)
               AND (
                    ?3 = '%'
                    OR s.name LIKE ?3
                    OR COALESCE(i.ip, '') LIKE ?3
                    OR CAST(p.port AS TEXT) LIKE ?3
                    OR COALESCE(p.service, '') LIKE ?3
                    OR COALESCE(p.fingerprint, '') LIKE ?3
               )
             ORDER BY s.name, i.ip, p.port
             LIMIT ?4 OFFSET ?5",
        )?;
        let items = collect_rows(
            &mut stmt,
            params![
                query.system,
                web,
                pattern,
                query.limit as i64,
                query.offset as i64
            ],
            |row| Ok(map_port(row)?),
        )?;
        Ok(AssetPage::new(items, total, query.offset, query.limit))
    }
}

/// Map a system-summary SQL row to [`SystemSummary`].
///
/// # Arguments
/// - `row`: System-summary query row.
///
/// # Returns
/// Typed system summary.
///
/// # Errors
/// Returns an error if a column cannot be read.
fn map_system_summary_row(row: &rusqlite::Row<'_>) -> anyhow::Result<SystemSummary> {
    Ok(SystemSummary {
        name: row.get(0)?,
        names: row.get(1)?,
        ips: row.get(2)?,
        ports: row.get(3)?,
        urls: row.get(4)?,
        baseline_names: row.get(5)?,
        baseline_ips: row.get(6)?,
        baseline_ports: row.get(7)?,
        baseline_urls: row.get(8)?,
        created_at: row.get(9)?,
    })
}

/// Build a SQL `LIKE` pattern from an optional keyword.
///
/// # Arguments
/// - `keyword`: Optional raw keyword.
///
/// # Returns
/// `"%keyword%"` or `"%"` when no keyword is set.
pub(crate) fn like_pattern(keyword: Option<&str>) -> String {
    keyword
        .map(|keyword| format!("%{keyword}%"))
        .unwrap_or_else(|| "%".to_string())
}

/// Run a `COUNT(*)` inventory query.
///
/// # Arguments
/// - `conn`: Open SQLite connection.
/// - `sql`: Count SQL.
/// - `params`: Bind parameters.
///
/// # Returns
/// Matching row count.
///
/// # Errors
/// Returns an error if the count query fails.
pub(crate) fn count_rows(
    conn: &rusqlite::Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> anyhow::Result<i64> {
    Ok(conn.query_row(sql, params, |row| row.get(0))?)
}

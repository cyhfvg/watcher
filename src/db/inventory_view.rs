//! Composed live-inventory views used by MCP and library callers.

use rusqlite::OptionalExtension;

use crate::models::{AssetQuery, LiveInventory, SystemContext};

use super::types::Database;

impl Database {
    /// Assemble confirmed-live ports, web services, and URLs for MCP callers.
    ///
    /// Each nested list is one page. Use the matching `list_*` query with
    /// `next_offset` when `has_more` is true.
    ///
    /// # Arguments
    /// - `query`: Optional exact system name, keyword, limit, and offset
    ///   applied to each nested list.
    ///
    /// # Returns
    /// [`LiveInventory`] snapshot plus paged live/web lists.
    ///
    /// # Errors
    /// Returns an error if any inventory query fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # use watcher::models::AssetQuery;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let inventory = db.live_inventory(&AssetQuery::default())?;
    /// assert!(inventory.live_ports.items.is_empty());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn live_inventory(&self, query: &AssetQuery) -> anyhow::Result<LiveInventory> {
        Ok(LiveInventory {
            snapshot: self.dashboard_snapshot()?,
            systems: self.list_system_summaries(query)?,
            live_ports: self.list_open_ports_filtered(query)?,
            web_services: self.list_web_services_filtered(query)?,
            live_urls: self.list_live_urls_filtered(query)?,
        })
    }

    /// Assemble live, web, and finding context for one business system.
    ///
    /// Nested lists honor `query.limit` / `query.offset`. The system summary
    /// itself is always loaded with offset 0.
    ///
    /// # Arguments
    /// - `system`: Exact business-system name.
    /// - `query`: Page window and optional keyword applied to nested lists.
    ///
    /// # Returns
    /// [`SystemContext`] for the named system.
    ///
    /// # Errors
    /// Returns an error if the system does not exist or a query fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # use watcher::models::AssetQuery;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// # db.upsert_system("core")?;
    /// let context = db.system_context("core", &AssetQuery::default())?;
    /// assert_eq!(context.system.name, "core");
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn system_context(
        &self,
        system: &str,
        query: &AssetQuery,
    ) -> anyhow::Result<SystemContext> {
        let summary_query = AssetQuery {
            system: Some(system.to_string()),
            keyword: None,
            limit: 1,
            offset: 0,
        }
        .sanitized();
        let system = self
            .list_system_summaries(&summary_query)?
            .items
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("business system not found: {system}"))?;
        let page_query = AssetQuery {
            system: Some(system.name.clone()),
            keyword: query.keyword.clone(),
            limit: query.limit,
            offset: query.offset,
        }
        .sanitized();
        Ok(SystemContext {
            names: self.list_domains_filtered(&page_query)?,
            ips: self.list_ips_filtered(&page_query)?,
            live_ports: self.list_open_ports_filtered(&page_query)?,
            web_services: self.list_web_services_filtered(&page_query)?,
            live_urls: self.list_live_urls_filtered(&page_query)?,
            alerts: self.list_alerts_filtered(None, &page_query)?,
            vulnerabilities: self.list_vulnerabilities_filtered(None, &page_query)?,
            system,
        })
    }

    /// Resolve an optional batch id, falling back to the latest batch.
    ///
    /// # Arguments
    /// - `batch_id`: Explicit batch id, or `None` / empty to use the latest.
    ///
    /// # Returns
    /// `Some(id)` when a batch exists, otherwise `None`.
    ///
    /// # Errors
    /// Returns an error if the lookup query fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// assert_eq!(db.resolve_batch_id(None)?, None);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn resolve_batch_id(&self, batch_id: Option<&str>) -> anyhow::Result<Option<String>> {
        if let Some(batch_id) = batch_id.map(str::trim).filter(|value| !value.is_empty()) {
            return Ok(Some(batch_id.to_string()));
        }
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT id FROM batches ORDER BY started_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }
}

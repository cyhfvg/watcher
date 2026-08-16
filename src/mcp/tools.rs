//! Read-only MCP tools over the watcher asset inventory.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use serde::Serialize;

use super::{
    params::{BatchQueryParams, LimitParams, QueryParams, SystemParams},
    server::WatcherMcp,
};

#[tool_router(vis = "pub(crate)")]

impl WatcherMcp {
    /// Return dashboard counters, latest-batch status, and recent alerts.
    ///
    /// # Arguments
    /// none
    ///
    /// # Returns
    /// JSON [`crate::models::DashboardSnapshot`].
    ///
    /// # Errors
    /// Returns a tool error if the snapshot query fails.
    #[tool(
        description = "Return watcher inventory counters, latest monitoring batch status, stage progress, queue counts, and recent alerts."
    )]
    pub fn get_snapshot(&self) -> Result<CallToolResult, McpError> {
        json_result(self.db.dashboard_snapshot())
    }

    /// Return one page of confirmed-live ports, web services, and live URLs.
    ///
    /// # Arguments
    /// - `params`: Optional system, keyword, limit, and offset.
    ///
    /// # Returns
    /// JSON [`crate::models::LiveInventory`] whose nested lists include
    /// `total`, `has_more`, and `next_offset`.
    ///
    /// # Errors
    /// Returns a tool error if an inventory query fails.
    #[tool(
        description = "Return one page of confirmed-live assets: open TCP ports, identified HTTP(S) services, and URLs with 2xx/3xx status. Each nested list includes total, offset, limit, has_more, and next_offset. Default page size is 50, max 200. When has_more is true, call this tool or the matching list_* tool with next_offset instead of raising limit."
    )]
    pub fn get_live_inventory(
        &self,
        Parameters(params): Parameters<QueryParams>,
    ) -> Result<CallToolResult, McpError> {
        json_result(self.db.live_inventory(&params.into_query()))
    }

    /// Return one page of a business system's live assets and findings.
    ///
    /// # Arguments
    /// - `params`: Exact business-system name plus optional page window.
    ///
    /// # Returns
    /// JSON [`crate::models::SystemContext`].
    ///
    /// # Errors
    /// Returns a tool error if the system does not exist or a query fails.
    #[tool(
        description = "Return one page of a business system's domains, IPs, live ports, web services, live URLs, latest alerts, and latest vulnerabilities. Nested lists are paginated (default 50, max 200). Use offset/next_offset to continue."
    )]
    pub fn get_system_context(
        &self,
        Parameters(params): Parameters<SystemParams>,
    ) -> Result<CallToolResult, McpError> {
        let (system, query) = params.into_parts();
        json_result(self.db.system_context(&system, &query))
    }

    /// List one page of business systems and asset counts.
    ///
    /// # Arguments
    /// - `params`: Optional system, keyword, limit, and offset.
    ///
    /// # Returns
    /// JSON [`crate::models::AssetPage`] of [`crate::models::SystemSummary`].
    ///
    /// # Errors
    /// Returns a tool error if the query fails.
    #[tool(
        description = "List one page of business systems with domain, IP, port, URL, and baseline counts. Returns items plus total/has_more/next_offset. Default limit 50, max 200."
    )]
    pub fn list_systems(
        &self,
        Parameters(params): Parameters<QueryParams>,
    ) -> Result<CallToolResult, McpError> {
        json_result(self.db.list_system_summaries(&params.into_query()))
    }

    /// List one page of currently open TCP ports.
    ///
    /// # Arguments
    /// - `params`: Optional system, keyword, limit, and offset.
    ///
    /// # Returns
    /// JSON page of live [`crate::models::PortAsset`].
    ///
    /// # Errors
    /// Returns a tool error if the query fails.
    #[tool(
        description = "List one page of TCP ports currently observed as open. Returns items plus total/has_more/next_offset. Default limit 50, max 200. Use next_offset to continue instead of requesting the whole table."
    )]
    pub fn list_live_ports(
        &self,
        Parameters(params): Parameters<QueryParams>,
    ) -> Result<CallToolResult, McpError> {
        json_result(self.db.list_open_ports_filtered(&params.into_query()))
    }

    /// List one page of open HTTP(S) services and fingerprints.
    ///
    /// # Arguments
    /// - `params`: Optional system, keyword, limit, and offset.
    ///
    /// # Returns
    /// JSON page of web [`crate::models::PortAsset`].
    ///
    /// # Errors
    /// Returns a tool error if the query fails.
    #[tool(
        description = "List one page of open HTTP/HTTPS web services, including scheme, service name, and fingerprint when available. Paginated: default 50, max 200, follow next_offset when has_more is true."
    )]
    pub fn list_web_services(
        &self,
        Parameters(params): Parameters<QueryParams>,
    ) -> Result<CallToolResult, McpError> {
        json_result(self.db.list_web_services_filtered(&params.into_query()))
    }

    /// List one page of URLs with a 2xx/3xx status from the latest probe.
    ///
    /// # Arguments
    /// - `params`: Optional system, keyword, limit, and offset.
    ///
    /// # Returns
    /// JSON page of live [`crate::models::UrlAsset`].
    ///
    /// # Errors
    /// Returns a tool error if the query fails.
    #[tool(
        description = "List one page of URLs whose latest HTTP status is 2xx or 3xx. Paginated: default 50, max 200. Follow next_offset when has_more is true."
    )]
    pub fn list_live_urls(
        &self,
        Parameters(params): Parameters<QueryParams>,
    ) -> Result<CallToolResult, McpError> {
        json_result(self.db.list_live_urls_filtered(&params.into_query()))
    }

    /// List one page of URL assets including unprobed and failed URLs.
    ///
    /// # Arguments
    /// - `params`: Optional system, keyword, limit, and offset.
    ///
    /// # Returns
    /// JSON page of [`crate::models::UrlAsset`].
    ///
    /// # Errors
    /// Returns a tool error if the query fails.
    #[tool(
        description = "Query one page of all known URLs, including unprobed and non-live statuses. Prefer list_live_urls for confirmed-live web assets. Paginated: default 50, max 200."
    )]
    pub fn query_urls(
        &self,
        Parameters(params): Parameters<QueryParams>,
    ) -> Result<CallToolResult, McpError> {
        json_result(self.db.list_urls_filtered(&params.into_query(), false))
    }

    /// List one page of IP assets, including resolved addresses.
    ///
    /// # Arguments
    /// - `params`: Optional system, keyword, limit, and offset.
    ///
    /// # Returns
    /// JSON page of [`crate::models::IpAsset`].
    ///
    /// # Errors
    /// Returns a tool error if the query fails.
    #[tool(
        description = "Query one page of stored IP addresses, including imported, manual, and resolved IPs. Paginated: default 50, max 200."
    )]
    pub fn query_ips(
        &self,
        Parameters(params): Parameters<QueryParams>,
    ) -> Result<CallToolResult, McpError> {
        json_result(self.db.list_ips_filtered(&params.into_query()))
    }

    /// List one page of domain assets.
    ///
    /// # Arguments
    /// - `params`: Optional system, keyword, limit, and offset.
    ///
    /// # Returns
    /// JSON page of [`crate::models::DomainAsset`].
    ///
    /// # Errors
    /// Returns a tool error if the query fails.
    #[tool(
        description = "Query one page of stored domain names and their bound IPs. Paginated: default 50, max 200."
    )]
    pub fn query_names(
        &self,
        Parameters(params): Parameters<QueryParams>,
    ) -> Result<CallToolResult, McpError> {
        json_result(self.db.list_domains_filtered(&params.into_query()))
    }

    /// List one page of alerts for a monitoring batch.
    ///
    /// # Arguments
    /// - `params`: Optional batch id, system, keyword, limit, and offset.
    ///
    /// # Returns
    /// JSON page of [`crate::models::Alert`].
    ///
    /// # Errors
    /// Returns a tool error if the query fails.
    #[tool(
        description = "List one page of DNS, port, and vulnerability alerts. Defaults to the latest monitoring batch. Paginated: default 50, max 200."
    )]
    pub fn list_alerts(
        &self,
        Parameters(params): Parameters<BatchQueryParams>,
    ) -> Result<CallToolResult, McpError> {
        let (batch, query) = params.into_parts();
        json_result(self.db.list_alerts_filtered(batch.as_deref(), &query))
    }

    /// List one page of vulnerability findings for a monitoring batch.
    ///
    /// # Arguments
    /// - `params`: Optional batch id, system, keyword, limit, and offset.
    ///
    /// # Returns
    /// JSON page of [`crate::models::Vulnerability`].
    ///
    /// # Errors
    /// Returns a tool error if the query fails.
    #[tool(
        description = "List one page of lightweight POC findings such as exposed sourcemaps. Defaults to the latest monitoring batch. Paginated: default 50, max 200."
    )]
    pub fn list_vulnerabilities(
        &self,
        Parameters(params): Parameters<BatchQueryParams>,
    ) -> Result<CallToolResult, McpError> {
        let (batch, query) = params.into_parts();
        json_result(
            self.db
                .list_vulnerabilities_filtered(batch.as_deref(), &query),
        )
    }

    /// List one page of recent monitoring batches.
    ///
    /// # Arguments
    /// - `params`: Optional limit and offset. Default page size is 20.
    ///
    /// # Returns
    /// JSON page of [`crate::models::BatchRow`].
    ///
    /// # Errors
    /// Returns a tool error if the query fails.
    #[tool(
        description = "List one page of recent monitoring batches and their status. Default limit 20, max 200. Follow next_offset when has_more is true."
    )]
    pub fn list_batches(
        &self,
        Parameters(params): Parameters<LimitParams>,
    ) -> Result<CallToolResult, McpError> {
        json_result(self.db.list_batches_page(&params.into_query()))
    }
}

/// Serialize a successful inventory result as pretty JSON tool output.
///
/// # Arguments
/// - `result`: Fallible value to serialize.
///
/// # Returns
/// MCP tool success with pretty-printed JSON, or a tool-level error.
///
/// # Errors
/// Returns a protocol error only when JSON serialization fails.
fn json_result<T: Serialize>(result: anyhow::Result<T>) -> Result<CallToolResult, McpError> {
    match result {
        Ok(value) => {
            let text = serde_json::to_string_pretty(&value).map_err(|err| {
                McpError::internal_error(format!("failed to encode inventory json: {err}"), None)
            })?;
            Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(text),
            ]))
        }
        Err(err) => Ok(CallToolResult::error(vec![
            rmcp::model::ContentBlock::text(err.to_string()),
        ])),
    }
}

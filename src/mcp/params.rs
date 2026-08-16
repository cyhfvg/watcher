//! JSON-schema parameter types for watcher MCP tools and prompts.

use rmcp::schemars::{self, JsonSchema};
use serde::Deserialize;

use crate::models::{AssetQuery, DEFAULT_ASSET_QUERY_LIMIT};

/// Shared inventory filter accepted by most MCP tools.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct QueryParams {
    /// Exact business-system name.
    #[serde(default)]
    pub system: Option<String>,
    /// Keyword matched against asset fields.
    #[serde(default)]
    pub keyword: Option<String>,
    /// Page size. Defaults to 50, capped at 200.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Number of matching rows to skip. Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
}

impl QueryParams {
    /// Convert MCP parameters into a sanitized [`AssetQuery`].
    ///
    /// # Arguments
    /// none. Operates on `self`.
    ///
    /// # Returns
    /// Inventory query with empty filters removed and the page window clamped.
    ///
    /// # Examples
    /// ```
    /// # use watcher::mcp::params::QueryParams;
    /// let query = QueryParams {
    ///     system: Some("core".into()),
    ///     keyword: None,
    ///     limit: Some(10),
    ///     offset: Some(20),
    /// }
    /// .into_query();
    /// assert_eq!(query.system.as_deref(), Some("core"));
    /// assert_eq!(query.limit, 10);
    /// assert_eq!(query.offset, 20);
    /// ```
    pub fn into_query(self) -> AssetQuery {
        AssetQuery {
            system: self.system,
            keyword: self.keyword,
            limit: self.limit.map_or(DEFAULT_ASSET_QUERY_LIMIT, |limit| {
                usize::try_from(limit).unwrap_or(DEFAULT_ASSET_QUERY_LIMIT)
            }),
            offset: self
                .offset
                .map_or(0, |offset| usize::try_from(offset).unwrap_or(0)),
        }
        .sanitized()
    }
}

/// Parameters for tools that can target a monitoring batch.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct BatchQueryParams {
    /// Optional batch id. Defaults to the latest batch.
    #[serde(default)]
    pub batch: Option<String>,
    /// Exact business-system name.
    #[serde(default)]
    pub system: Option<String>,
    /// Keyword matched against finding fields.
    #[serde(default)]
    pub keyword: Option<String>,
    /// Page size. Defaults to 50, capped at 200.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Number of matching rows to skip. Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
}

impl BatchQueryParams {
    /// Split batch id from the shared inventory filter.
    ///
    /// # Arguments
    /// none. Operates on `self`.
    ///
    /// # Returns
    /// `(batch_id, query)` where `batch_id` is `None` when the caller wants
    /// the latest batch.
    ///
    /// # Examples
    /// ```
    /// # use watcher::mcp::params::BatchQueryParams;
    /// let (batch, query) = BatchQueryParams {
    ///     batch: Some("abc".into()),
    ///     system: Some("core".into()),
    ///     keyword: None,
    ///     limit: None,
    ///     offset: Some(10),
    /// }
    /// .into_parts();
    /// assert_eq!(batch.as_deref(), Some("abc"));
    /// assert_eq!(query.system.as_deref(), Some("core"));
    /// assert_eq!(query.offset, 10);
    /// ```
    pub fn into_parts(self) -> (Option<String>, AssetQuery) {
        let query = QueryParams {
            system: self.system,
            keyword: self.keyword,
            limit: self.limit,
            offset: self.offset,
        }
        .into_query();
        (self.batch.filter(|value| !value.trim().is_empty()), query)
    }
}

/// Parameters that select one business system and an optional page window.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SystemParams {
    /// Exact business-system name.
    pub system: String,
    /// Keyword matched against nested asset fields.
    #[serde(default)]
    pub keyword: Option<String>,
    /// Page size for nested lists. Defaults to 50, capped at 200.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Number of matching nested rows to skip. Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
}

impl SystemParams {
    /// Split the system name from the nested-list page query.
    ///
    /// # Arguments
    /// none. Operates on `self`.
    ///
    /// # Returns
    /// `(system, query)` used by [`crate::db::Database::system_context`].
    ///
    /// # Examples
    /// ```
    /// # use watcher::mcp::params::SystemParams;
    /// let (system, query) = SystemParams {
    ///     system: "core".into(),
    ///     keyword: None,
    ///     limit: Some(5),
    ///     offset: Some(5),
    /// }
    /// .into_parts();
    /// assert_eq!(system, "core");
    /// assert_eq!(query.limit, 5);
    /// assert_eq!(query.offset, 5);
    /// ```
    pub fn into_parts(self) -> (String, AssetQuery) {
        let query = QueryParams {
            system: Some(self.system.clone()),
            keyword: self.keyword,
            limit: self.limit,
            offset: self.offset,
        }
        .into_query();
        (self.system, query)
    }
}

/// Optional system selector used by MCP prompts.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct OptionalSystemParams {
    /// Exact business-system name. When omitted, all live assets are included.
    #[serde(default)]
    pub system: Option<String>,
}

/// Parameters for listing recent monitoring batches.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct LimitParams {
    /// Page size. Defaults to 20, capped at 200.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Number of batches to skip. Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
}

impl LimitParams {
    /// Convert batch-list parameters into an inventory query.
    ///
    /// # Arguments
    /// none. Operates on `self`.
    ///
    /// # Returns
    /// Query whose default page size is 20.
    ///
    /// # Examples
    /// ```
    /// # use watcher::mcp::params::LimitParams;
    /// let query = LimitParams { limit: None, offset: Some(20) }.into_query();
    /// assert_eq!(query.limit, 20);
    /// assert_eq!(query.offset, 20);
    /// ```
    pub fn into_query(self) -> AssetQuery {
        AssetQuery {
            system: None,
            keyword: None,
            limit: self
                .limit
                .map_or(20, |limit| usize::try_from(limit).unwrap_or(20)),
            offset: self
                .offset
                .map_or(0, |offset| usize::try_from(offset).unwrap_or(0)),
        }
        .sanitize(20)
    }
}

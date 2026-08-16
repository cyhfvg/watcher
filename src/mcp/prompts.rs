//! MCP prompts that turn live watcher inventory into authorized-testing briefs.

use rmcp::{
    ErrorData as McpError,
    handler::server::wrapper::Parameters,
    model::{GetPromptResult, PromptMessage, Role},
    prompt, prompt_router,
};

use crate::models::{LiveInventory, SystemContext};

use super::{params::OptionalSystemParams, server::WatcherMcp};

#[prompt_router(vis = "pub(crate)")]

impl WatcherMcp {
    /// Build an authorized pentest-planning prompt from live assets.
    ///
    /// # Arguments
    /// - `params`: Optional business-system name.
    ///
    /// # Returns
    /// Prompt messages that include the current live inventory JSON.
    ///
    /// # Errors
    /// Returns an MCP error if inventory loading fails.
    #[prompt(
        name = "pentest_live_assets",
        description = "Load watcher's confirmed-live assets and ask the model to plan authorized testing only against those hosts, ports, and URLs."
    )]
    pub fn pentest_live_assets(
        &self,
        Parameters(params): Parameters<OptionalSystemParams>,
    ) -> Result<GetPromptResult, McpError> {
        let text = match params
            .system
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(system) => {
                let context = self
                    .db
                    .system_context(system, &crate::models::AssetQuery::default())
                    .map_err(|err| McpError::invalid_params(err.to_string(), None))?;
                pentest_system_prompt(&context)
            }
            None => {
                let inventory = self
                    .db
                    .live_inventory(&crate::models::AssetQuery::default())
                    .map_err(|err| McpError::internal_error(err.to_string(), None))?;
                pentest_inventory_prompt(&inventory)
            }
        };
        Ok(
            GetPromptResult::new(vec![PromptMessage::new_text(Role::User, text)])
                .with_description("Authorized testing plan from watcher live assets"),
        )
    }

    /// Build a web-exposure review prompt from live web services and URLs.
    ///
    /// # Arguments
    /// - `params`: Optional business-system name.
    ///
    /// # Returns
    /// Prompt messages that include live web inventory JSON.
    ///
    /// # Errors
    /// Returns an MCP error if inventory loading fails.
    #[prompt(
        name = "review_web_exposure",
        description = "Load live HTTP(S) services and 2xx/3xx URLs, then ask the model to review web exposure without attacking unauthorized targets."
    )]
    pub fn review_web_exposure(
        &self,
        Parameters(params): Parameters<OptionalSystemParams>,
    ) -> Result<GetPromptResult, McpError> {
        let query = crate::models::AssetQuery {
            system: params.system,
            ..crate::models::AssetQuery::default()
        }
        .sanitized();

        let inventory = self
            .db
            .live_inventory(&query)
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;
        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            Role::User,
            web_exposure_prompt(&inventory),
        )])
        .with_description("Web exposure review from watcher live web assets"))
    }
}

/// Render a pentest-planning prompt for one business system.
///
/// # Arguments
/// - `context`: Live, web, and finding context for the system.
///
/// # Returns
/// User-role prompt text.
///
/// # Examples
/// ```
/// # use watcher::db::Database;
/// # use watcher::mcp::prompts::pentest_system_prompt;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// # db.upsert_system("core")?;
/// let context = db.system_context("core", &watcher::models::AssetQuery::default())?;
/// let text = pentest_system_prompt(&context);
/// assert!(text.contains("core"));
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn pentest_system_prompt(context: &SystemContext) -> String {
    let json = serde_json::to_string_pretty(context).unwrap_or_else(|_| "{}".to_string());
    format!(
        "You are assisting with authorized security testing.\n\
         Watcher is an asset-monitoring inventory. Only discuss or plan tests against the live assets below.\n\
         Nested lists are one page. If has_more is true, call list_* tools with next_offset instead of assuming the list is complete.\n\
         Do not invent hosts, ports, or URLs that are not in this inventory.\n\
         Do not provide exploit code. Prefer reconnaissance, configuration review, and safe validation steps.\n\
         Confirm the operator is authorized before recommending any active test.\n\n\
         Business system context (JSON):\n{json}"
    )
}

/// Render a pentest-planning prompt from the global live inventory.
///
/// # Arguments
/// - `inventory`: Confirmed-live ports, web services, and URLs.
///
/// # Returns
/// User-role prompt text.
///
/// # Examples
/// ```
/// # use watcher::db::Database;
/// # use watcher::mcp::prompts::pentest_inventory_prompt;
/// # use watcher::models::AssetQuery;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// let inventory = db.live_inventory(&AssetQuery::default())?;
/// let text = pentest_inventory_prompt(&inventory);
/// assert!(text.contains("live assets"));
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn pentest_inventory_prompt(inventory: &LiveInventory) -> String {
    let json = serde_json::to_string_pretty(inventory).unwrap_or_else(|_| "{}".to_string());
    format!(
        "You are assisting with authorized security testing.\n\
         Watcher has retained the following confirmed-live assets (open ports, web services, and 2xx/3xx URLs).\n\
         This payload is one page. If any list has has_more=true, call the matching list_* tool with next_offset.\n\
         Plan testing only against these assets. Skip unknown, closed, or unprobed items.\n\
         Do not invent targets. Do not provide exploit code.\n\
         Confirm authorization before recommending active tests.\n\n\
         Live inventory (JSON):\n{json}"
    )
}

/// Render a web-exposure review prompt.
///
/// # Arguments
/// - `inventory`: Live web services and URLs.
///
/// # Returns
/// User-role prompt text.
///
/// # Examples
/// ```
/// # use watcher::db::Database;
/// # use watcher::mcp::prompts::web_exposure_prompt;
/// # use watcher::models::AssetQuery;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// let inventory = db.live_inventory(&AssetQuery::default())?;
/// let text = web_exposure_prompt(&inventory);
/// assert!(text.contains("web exposure"));
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn web_exposure_prompt(inventory: &LiveInventory) -> String {
    let json = serde_json::to_string_pretty(inventory).unwrap_or_else(|_| "{}".to_string());
    format!(
        "Review the following live web assets retained by watcher.\n\
         Focus on web exposure: unexpected open HTTP(S) ports, non-baseline URLs, weak fingerprints, and already-recorded findings.\n\
         Nested lists are one page. If has_more is true, call list_web_services or list_live_urls with next_offset.\n\
         Do not propose attacks against assets outside this inventory.\n\n\
         Live web inventory (JSON):\n{json}"
    )
}

//! Model Context Protocol server for the watcher asset inventory.
//!
//! Watcher stays an asset-monitoring library. The MCP surface is read-only and
//! exposes live ports, web services, URL status, alerts, and findings so an LLM
//! can plan authorized testing against already-confirmed live assets.

pub mod params;

pub mod prompts;

mod server;
mod tools;

pub use server::{WatcherMcp, run_stdio};

/// Stable MCP tool names advertised to LLM hosts.
pub const TOOL_NAMES: &[&str] = &[
    "get_snapshot",
    "get_live_inventory",
    "get_system_context",
    "list_systems",
    "list_live_ports",
    "list_web_services",
    "list_live_urls",
    "query_urls",
    "query_ips",
    "query_names",
    "list_alerts",
    "list_vulnerabilities",
    "list_batches",
];

/// Stable MCP prompt names advertised to LLM hosts.
pub const PROMPT_NAMES: &[&str] = &["pentest_live_assets", "review_web_exposure"];

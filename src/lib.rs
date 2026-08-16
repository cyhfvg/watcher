//! Reusable application library for the watcher command-line tool.
//!
//! The binary entry point only parses process arguments and delegates to this
//! crate. Keeping operational logic here makes it directly testable and ready
//! for future embedding by another process supervisor or service wrapper.
//!
//! Public modules cover configuration, the daemon, the terminal dashboard,
//! storage, the monitoring pipeline, and reports. External callers should
//! prefer these stable paths over crate-internal `pub(crate)` helpers.

pub mod cli;
pub mod config;
pub mod daemon;
pub mod dashboard;
pub mod db;
pub mod dict;
pub mod import;
pub mod local_time;
pub mod logging;
pub mod models;
pub mod monitor;
pub mod notify;
pub mod report;

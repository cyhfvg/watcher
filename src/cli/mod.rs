//! Command-line definitions and small output helpers.
//!
//! Argument types, batch/log/system handlers, baseline-asset handlers, and
//! non-baseline entity handlers live in separate files. The public path remains
//! `watcher::cli`.

mod args;
mod baseline;
mod common;
mod entities;
mod handlers;

pub use args::{
    BaselineAddArgs, BaselineAssetType, BaselineCommands, BaselineExportArgs, BaselineImportArgs,
    BaselineImportType, BaselineMutateArgs, BaselineQueryArgs, Cli, Commands, DaemonCommands,
    DictCommands, EntityAddArgs, EntityCommands, EntityImportArgs, LogCommands, LogLevelArg,
    LogQueryArgs, PathCommands, QueryArgs, SystemCommands, TaskCommands,
};
pub use baseline::handle_baseline;
pub use entities::{handle_ips, handle_names, handle_ports, handle_urls};
pub use handlers::{handle_logs, handle_systems, print_batch_status, print_batches};

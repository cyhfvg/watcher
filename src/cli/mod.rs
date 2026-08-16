//! Command-line definitions and small output helpers.
//!
//! Argument types, action-first handlers, and task printers live in separate
//! files. The public path remains `watcher::cli`.

mod actions;
mod args;
mod assets;
mod common;
mod handlers;

pub use actions::{
    handle_add, handle_clear, handle_delete, handle_export, handle_import, handle_query,
    handle_rename, handle_unmark,
};
pub use args::{
    AddArgs, AddTarget, ClearArgs, ClearTarget, Cli, Commands, DaemonCommands, DeleteArgs,
    DeleteTarget, ExportArgs, ImportArgs, ImportTarget, InspectTarget, LogLevelArg, QueryArgs,
    RenameArgs, RenameTarget, TargetKind, TaskCommands, UnmarkArgs, UnmarkTarget,
};
pub use handlers::{print_batch_status, print_batches};

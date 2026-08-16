//! 命令行定义与小型输出辅助.
//!
//! 参数类型, 批次/日志/系统处理, 基线资产处理和非基线实体处理分文件存放.
//! 对外路径仍集中在 `watcher::cli`.

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

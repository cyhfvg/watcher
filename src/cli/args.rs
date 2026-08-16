//! CLI 参数与子命令类型.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Top-level CLI options.
#[derive(Debug, Parser)]
#[command(
    name = "watcher",
    version,
    about = "Long-running asset monitoring toolkit"
)]
pub struct Cli {
    /// Print an example configuration and exit.
    #[arg(long, global = true)]
    pub example: bool,

    /// Command to execute.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Top-level command groups.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create default config/database paths if they do not exist.
    Init,
    /// Manage imported baseline assets.
    #[command(subcommand)]
    Baseline(BaselineCommands),
    /// Manage business systems.
    #[command(alias = "systems")]
    #[command(subcommand)]
    System(SystemCommands),
    /// Run the long-lived scheduler.
    #[command(subcommand)]
    Daemon(DaemonCommands),
    /// Manage monitoring tasks.
    #[command(alias = "tasks")]
    #[command(subcommand)]
    Task(TaskCommands),
    /// Query or export application logs stored in SQLite.
    #[command(alias = "logs")]
    #[command(subcommand)]
    Log(LogCommands),
    /// Manage dictionaries.
    #[command(alias = "dicts")]
    #[command(subcommand)]
    Dict(DictCommands),
    /// Manage URL assets.
    #[command(alias = "urls")]
    #[command(subcommand)]
    Url(EntityCommands),
    /// Manage port assets.
    #[command(alias = "ports")]
    #[command(subcommand)]
    Port(EntityCommands),
    /// Manage IP assets.
    #[command(alias = "ips")]
    #[command(subcommand)]
    Ip(EntityCommands),
    /// Manage domain-name assets.
    #[command(alias = "names")]
    #[command(subcommand)]
    Name(EntityCommands),
    /// Build a report package for a batch. Defaults to latest batch.
    Report {
        /// Batch id to package.
        #[arg(long)]
        batch: Option<String>,
    },
    /// Open an interactive terminal dashboard for operational metrics and progress.
    Dashboard {
        /// Seconds between automatic data refreshes.
        #[arg(long, default_value_t = 2)]
        refresh_seconds: u64,
    },
}

/// Baseline asset management command group.
#[derive(Debug, Subcommand)]
pub enum BaselineCommands {
    /// Add one baseline asset.
    Add(BaselineAddArgs),
    /// Import baseline assets from Excel or newline-delimited files.
    Import(BaselineImportArgs),
    /// Export baseline assets to CSV.
    Export(BaselineExportArgs),
    /// Query baseline assets.
    Query(BaselineQueryArgs),
    /// Remove one baseline asset row.
    Delete(BaselineMutateArgs),
    /// Remove the baseline marker but keep the asset row.
    Unmark(BaselineMutateArgs),
}

/// Business system command group.
#[derive(Debug, Subcommand)]
pub enum SystemCommands {
    /// Add one business system.
    Add { name: String },
    /// Query business systems and asset counters.
    Query(QueryArgs),
    /// Export business systems and asset counters to CSV.
    Export {
        /// CSV output path.
        file: PathBuf,
    },
    /// Delete a business system and all assets below it.
    Delete { name: String },
    /// Rename a business system.
    Rename {
        /// Existing business system name.
        old_name: String,
        /// New business system name.
        new_name: String,
    },
}

/// Daemon command group.
#[derive(Debug, Subcommand)]
pub enum DaemonCommands {
    /// Run the scheduler loop.
    Run {
        /// Run only one batch and exit.
        #[arg(long)]
        once: bool,
        /// Keep the daemon in the foreground for debugging.
        #[arg(long)]
        foreground: bool,
    },
    /// Show daemon process status.
    Status,
    /// Stop a background daemon process.
    Stop,
    /// Stop then start the daemon process.
    Restart {
        /// Keep the restarted daemon in the foreground for debugging.
        #[arg(long)]
        foreground: bool,
    },
}

/// Log command group.
#[derive(Debug, Subcommand)]
pub enum LogCommands {
    /// Query recent logs.
    Query(LogQueryArgs),
    /// Export logs to CSV.
    Export {
        /// CSV output path.
        file: PathBuf,
        /// Optional log level filter.
        #[arg(long, value_enum)]
        level: Option<LogLevelArg>,
        /// Optional keyword matched against message and fields.
        #[arg(long)]
        keyword: Option<String>,
        /// Maximum rows to export.
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// Clear logs. Use --before with an RFC3339 timestamp to delete old records.
    Clear {
        /// Optional RFC3339 cutoff timestamp.
        #[arg(long)]
        before: Option<String>,
    },
}

/// Log query arguments.
#[derive(Debug, Args)]
pub struct LogQueryArgs {
    /// Optional log level filter.
    #[arg(long, value_enum)]
    pub level: Option<LogLevelArg>,
    /// Optional keyword matched against message and fields.
    #[arg(long)]
    pub keyword: Option<String>,
    /// Maximum rows to print.
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
}

/// Log level filter for log query/export commands.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogLevelArg {
    /// Error events.
    Error,
    /// Warning events.
    Warn,
    /// Informational events.
    Info,
    /// Debug events.
    Debug,
    /// Trace events.
    Trace,
}

impl LogLevelArg {
    /// 返回写入 SQLite 的大写日志级别.
    ///
    /// # 参数
    ///
    /// - `self`: 要转换的日志级别.
    ///
    /// # 返回
    ///
    /// 对应的数据库级别字符串, 例如 `ERROR`.
    ///
    /// # 示例
    ///
    /// ```text
    /// LogLevelArg::Error.as_db_level() -> "ERROR"
    /// ```
    pub(crate) fn as_db_level(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

/// Task command group.
#[derive(Debug, Subcommand)]
pub enum TaskCommands {
    /// Run monitoring tasks.
    Run {
        /// Run only one batch and exit.
        #[arg(long)]
        once: bool,
    },
    /// List recent task batches.
    List,
    /// Print task status.
    Status {
        /// Optional batch id. Defaults to latest batch.
        #[arg(long)]
        batch: Option<String>,
    },
    /// Request a running batch to stop at the next safe checkpoint.
    Stop {
        /// Optional batch id. Defaults to latest running batch.
        #[arg(long)]
        batch: Option<String>,
    },
}

/// Dictionary command group.
#[derive(Debug, Subcommand)]
pub enum DictCommands {
    /// Manage path dictionary entries for web directory enumeration.
    #[command(subcommand)]
    Path(PathCommands),
}

/// Path dictionary commands.
#[derive(Debug, Subcommand)]
pub enum PathCommands {
    /// Import paths from a newline-delimited text file.
    Import { file: PathBuf },
    /// Export paths to a CSV file.
    Export { file: PathBuf },
    /// Query path dictionary entries.
    Query(QueryArgs),
    /// Delete a path dictionary entry.
    Delete { path: String },
}

/// Generic entity management commands.
#[derive(Debug, Subcommand)]
pub enum EntityCommands {
    /// Add one non-baseline asset without preparing an import file.
    Add(EntityAddArgs),
    /// Import non-baseline values from a newline-delimited text file.
    Import(EntityImportArgs),
    /// Export values to CSV.
    Export { file: PathBuf },
    /// Query values.
    Query(QueryArgs),
    /// Delete a value.
    Delete { value: String },
}

/// Arguments for adding one non-baseline asset.
#[derive(Debug, Args)]
pub struct EntityAddArgs {
    /// Business system name.
    #[arg(long)]
    pub system: String,
    /// Optional IP address bound to a port asset.
    #[arg(long)]
    pub ip: Option<String>,
    /// Expected or known bound IP address for a domain-name asset.
    #[arg(long)]
    pub bind_ip: Option<String>,
    /// Exact asset value. Ports must be numeric.
    pub value: String,
}

/// Arguments for importing non-baseline entity assets.
#[derive(Debug, Args)]
pub struct EntityImportArgs {
    /// Business system name.
    #[arg(long)]
    pub system: String,
    /// Optional IP address all imported ports are bound to.
    #[arg(long)]
    pub ip: Option<String>,
    /// Expected or known bound IP address for imported domain names.
    #[arg(long)]
    pub bind_ip: Option<String>,
    /// Newline-delimited asset file.
    pub file: PathBuf,
}

/// Baseline import type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BaselineImportType {
    /// Excel file with columns id, system, servername, real_ip, servername_bind_ip, port, url.
    Excel,
    /// URL asset.
    Url,
    /// TCP port asset.
    Port,
    /// IP address asset.
    Ip,
    /// Domain-name asset.
    Name,
}

/// Baseline item type used by action-style baseline commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BaselineAssetType {
    /// URL asset.
    Url,
    /// TCP port asset.
    Port,
    /// IP address asset.
    Ip,
    /// Domain-name asset.
    Name,
}

/// Arguments for adding one baseline asset.
#[derive(Debug, Args)]
pub struct BaselineAddArgs {
    /// Asset type to add: url, port, ip or name.
    #[arg(long, value_enum)]
    pub asset_type: BaselineAssetType,
    /// Business system name.
    #[arg(long)]
    pub system: String,
    /// Optional IP address for port assets.
    #[arg(long)]
    pub ip: Option<String>,
    /// Expected or known bound IP address for domain assets.
    #[arg(long)]
    pub bind_ip: Option<String>,
    /// Exact asset value. Ports must be numeric.
    pub value: String,
}

/// Arguments for importing baseline assets.
#[derive(Debug, Args)]
pub struct BaselineImportArgs {
    /// Asset type to import. Use excel for the structured Excel import.
    #[arg(long, value_enum)]
    pub asset_type: BaselineImportType,
    /// Business system name for newline-delimited imports. Not used by asset-type=excel.
    #[arg(long)]
    pub system: Option<String>,
    /// Optional IP address all imported ports are bound to.
    #[arg(long)]
    pub ip: Option<String>,
    /// Newline-delimited file or Excel file depending on asset-type.
    pub file: PathBuf,
}

/// Arguments for exporting baseline assets.
#[derive(Debug, Args)]
pub struct BaselineExportArgs {
    /// Asset type to export: url, port, ip or name.
    #[arg(long, value_enum)]
    pub asset_type: BaselineAssetType,
    /// CSV output path.
    pub file: PathBuf,
}

/// Arguments for querying baseline assets.
#[derive(Debug, Args)]
pub struct BaselineQueryArgs {
    /// Asset type to query: url, port, ip or name.
    #[arg(long, value_enum)]
    pub asset_type: BaselineAssetType,
    /// Optional SQL LIKE keyword.
    #[arg(long)]
    pub keyword: Option<String>,
    /// Maximum rows to print.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

/// Arguments for deleting or unmarking one baseline asset.
#[derive(Debug, Args)]
pub struct BaselineMutateArgs {
    /// Asset type to mutate: url, port, ip or name.
    #[arg(long, value_enum)]
    pub asset_type: BaselineAssetType,
    /// Business system name.
    #[arg(long)]
    pub system: String,
    /// Optional IP address for port assets.
    #[arg(long)]
    pub ip: Option<String>,
    /// Exact asset value. Ports must be numeric.
    pub value: String,
}

/// Query arguments shared by list-like commands.
#[derive(Debug, Args)]
pub struct QueryArgs {
    /// Optional SQL LIKE keyword.
    #[arg(long)]
    pub keyword: Option<String>,
    /// Maximum rows to print.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

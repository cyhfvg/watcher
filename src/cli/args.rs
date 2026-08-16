//! CLI argument and subcommand types.
//!
//! Asset, dictionary, and log operations use action-first commands with a
//! `--type` noun filter. Daemon and task keep lifecycle subcommands.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Top-level CLI options.
#[derive(Debug, Parser)]
#[command(
    name = "watcher",
    version,
    about = "Long-running asset monitoring toolkit",
    long_about = "Long-running asset monitoring toolkit.\n\n\
Asset, dictionary, and log operations use action-first commands:\n  \
watcher add|import|export|query|delete|unmark|rename|clear --type <noun> ...\n\n\
Daemon and task keep dedicated lifecycle subcommands."
)]
pub struct Cli {
    /// Print an example configuration and exit.
    #[arg(long, global = true)]
    pub example: bool,

    /// Command to execute.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create default config/database paths if they do not exist.
    Init,
    /// Add one business system or asset.
    Add(AddArgs),
    /// Import assets, a path dictionary, or an Excel baseline workbook.
    Import(ImportArgs),
    /// Export assets, systems, path dictionary, or logs.
    Export(ExportArgs),
    /// Query assets, systems, path dictionary, or logs.
    #[command(alias = "list")]
    Query(QueryArgs),
    /// Delete one business system, asset, or path-dictionary entry.
    Delete(DeleteArgs),
    /// Remove the baseline marker but keep the asset row.
    Unmark(UnmarkArgs),
    /// Rename a business system.
    Rename(RenameArgs),
    /// Clear stored records. Currently supports logs.
    Clear(ClearArgs),
    /// Run and control the long-lived scheduler process.
    #[command(subcommand)]
    Daemon(DaemonCommands),
    /// Run and inspect monitoring batches.
    #[command(alias = "tasks")]
    #[command(subcommand)]
    Task(TaskCommands),
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

/// Noun selected by `--type` / `-t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TargetKind {
    /// URL asset.
    Url,
    /// TCP port asset.
    Port,
    /// IP address asset.
    Ip,
    /// Domain-name asset.
    Name,
    /// Business system.
    System,
    /// Web path dictionary entry.
    Path,
    /// Application log stored in SQLite.
    Log,
    /// Structured Excel baseline workbook.
    Excel,
}

impl TargetKind {
    /// Returns a lowercase noun used in messages.
    ///
    /// # Arguments
    ///
    /// - `self`: selected noun.
    ///
    /// # Returns
    ///
    /// A stable lowercase label such as `url` or `system`.
    ///
    /// # Examples
    ///
    /// ```
    /// use watcher::cli::TargetKind;
    /// assert_eq!(TargetKind::Url.as_str(), "url");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::Port => "port",
            Self::Ip => "ip",
            Self::Name => "name",
            Self::System => "system",
            Self::Path => "path",
            Self::Log => "log",
            Self::Excel => "excel",
        }
    }

    /// Returns whether this noun is a URL/port/IP/name asset.
    ///
    /// # Arguments
    ///
    /// - `self`: selected noun.
    ///
    /// # Returns
    ///
    /// `true` for `url`, `port`, `ip`, and `name`.
    ///
    /// # Examples
    ///
    /// ```
    /// use watcher::cli::TargetKind;
    /// assert!(TargetKind::Port.is_asset());
    /// assert!(!TargetKind::Log.is_asset());
    /// ```
    pub fn is_asset(self) -> bool {
        matches!(self, Self::Url | Self::Port | Self::Ip | Self::Name)
    }
}

impl std::fmt::Display for TargetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Nouns accepted by `add`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AddTarget {
    /// URL asset.
    Url,
    /// TCP port asset.
    Port,
    /// IP address asset.
    Ip,
    /// Domain-name asset.
    Name,
    /// Business system.
    System,
}

impl From<AddTarget> for TargetKind {
    fn from(value: AddTarget) -> Self {
        match value {
            AddTarget::Url => Self::Url,
            AddTarget::Port => Self::Port,
            AddTarget::Ip => Self::Ip,
            AddTarget::Name => Self::Name,
            AddTarget::System => Self::System,
        }
    }
}

/// Nouns accepted by `import`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImportTarget {
    /// URL asset.
    Url,
    /// TCP port asset.
    Port,
    /// IP address asset.
    Ip,
    /// Domain-name asset.
    Name,
    /// Structured Excel baseline workbook.
    Excel,
    /// Web path dictionary.
    Path,
}

impl From<ImportTarget> for TargetKind {
    fn from(value: ImportTarget) -> Self {
        match value {
            ImportTarget::Url => Self::Url,
            ImportTarget::Port => Self::Port,
            ImportTarget::Ip => Self::Ip,
            ImportTarget::Name => Self::Name,
            ImportTarget::Excel => Self::Excel,
            ImportTarget::Path => Self::Path,
        }
    }
}

/// Nouns accepted by `query` and `export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InspectTarget {
    /// URL asset.
    Url,
    /// TCP port asset.
    Port,
    /// IP address asset.
    Ip,
    /// Domain-name asset.
    Name,
    /// Business system.
    System,
    /// Web path dictionary.
    Path,
    /// Application log stored in SQLite.
    Log,
}

impl From<InspectTarget> for TargetKind {
    fn from(value: InspectTarget) -> Self {
        match value {
            InspectTarget::Url => Self::Url,
            InspectTarget::Port => Self::Port,
            InspectTarget::Ip => Self::Ip,
            InspectTarget::Name => Self::Name,
            InspectTarget::System => Self::System,
            InspectTarget::Path => Self::Path,
            InspectTarget::Log => Self::Log,
        }
    }
}

/// Nouns accepted by `delete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DeleteTarget {
    /// URL asset.
    Url,
    /// TCP port asset.
    Port,
    /// IP address asset.
    Ip,
    /// Domain-name asset.
    Name,
    /// Business system.
    System,
    /// Web path dictionary entry.
    Path,
}

impl From<DeleteTarget> for TargetKind {
    fn from(value: DeleteTarget) -> Self {
        match value {
            DeleteTarget::Url => Self::Url,
            DeleteTarget::Port => Self::Port,
            DeleteTarget::Ip => Self::Ip,
            DeleteTarget::Name => Self::Name,
            DeleteTarget::System => Self::System,
            DeleteTarget::Path => Self::Path,
        }
    }
}

/// Nouns accepted by `unmark`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum UnmarkTarget {
    /// URL asset.
    Url,
    /// TCP port asset.
    Port,
    /// IP address asset.
    Ip,
    /// Domain-name asset.
    Name,
}

impl From<UnmarkTarget> for TargetKind {
    fn from(value: UnmarkTarget) -> Self {
        match value {
            UnmarkTarget::Url => Self::Url,
            UnmarkTarget::Port => Self::Port,
            UnmarkTarget::Ip => Self::Ip,
            UnmarkTarget::Name => Self::Name,
        }
    }
}

/// Nouns accepted by `rename`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RenameTarget {
    /// Business system.
    System,
}

impl From<RenameTarget> for TargetKind {
    fn from(value: RenameTarget) -> Self {
        match value {
            RenameTarget::System => Self::System,
        }
    }
}

/// Nouns accepted by `clear`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ClearTarget {
    /// Application log stored in SQLite.
    Log,
}

impl From<ClearTarget> for TargetKind {
    fn from(value: ClearTarget) -> Self {
        match value {
            ClearTarget::Log => Self::Log,
        }
    }
}

/// Arguments for `watcher add --type <noun>`.
#[derive(Debug, Args)]
pub struct AddArgs {
    /// Noun to add: url, port, ip, name, or system.
    #[arg(short = 't', long = "type", value_enum)]
    pub target: AddTarget,
    /// Mark a URL/port/IP/name asset as baseline.
    #[arg(long)]
    pub baseline: bool,
    /// Business system that owns the asset. Required for url/port/ip/name.
    #[arg(long)]
    pub system: Option<String>,
    /// Optional IP address bound to a port asset.
    #[arg(long)]
    pub ip: Option<String>,
    /// Expected or known bound IP address for a domain-name asset.
    #[arg(long)]
    pub bind_ip: Option<String>,
    /// Asset value, or the business-system name when `--type system`.
    pub value: String,
}

/// Arguments for `watcher import --type <noun>`.
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Noun to import: url, port, ip, name, excel, or path.
    #[arg(short = 't', long = "type", value_enum)]
    pub target: ImportTarget,
    /// Mark imported URL/port/IP/name assets as baseline. Implied by `--type excel`.
    #[arg(long)]
    pub baseline: bool,
    /// Business system for newline-delimited asset imports. Not used by excel/path.
    #[arg(long)]
    pub system: Option<String>,
    /// Optional IP address all imported ports are bound to.
    #[arg(long)]
    pub ip: Option<String>,
    /// Expected or known bound IP address for imported domain names.
    #[arg(long)]
    pub bind_ip: Option<String>,
    /// Newline-delimited file, path dictionary, or Excel workbook.
    pub file: PathBuf,
}

/// Arguments for `watcher export --type <noun>`.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Noun to export: url, port, ip, name, system, path, or log.
    #[arg(short = 't', long = "type", value_enum)]
    pub target: InspectTarget,
    /// Export only baseline URL/port/IP/name assets.
    #[arg(long)]
    pub baseline: bool,
    /// Optional log level filter. Only used by `--type log`.
    #[arg(long, value_enum)]
    pub level: Option<LogLevelArg>,
    /// Optional keyword matched against log message and fields.
    #[arg(long)]
    pub keyword: Option<String>,
    /// Maximum log rows to export. Only used by `--type log`.
    #[arg(long, default_value_t = 1000)]
    pub limit: usize,
    /// Output file path.
    pub file: PathBuf,
}

/// Arguments for `watcher query --type <noun>`.
#[derive(Debug, Args)]
pub struct QueryArgs {
    /// Noun to query: url, port, ip, name, system, path, or log.
    #[arg(short = 't', long = "type", value_enum)]
    pub target: InspectTarget,
    /// Query only baseline URL/port/IP/name assets.
    #[arg(long)]
    pub baseline: bool,
    /// Optional SQL LIKE keyword, or log message/fields keyword.
    #[arg(long)]
    pub keyword: Option<String>,
    /// Optional log level filter. Only used by `--type log`.
    #[arg(long, value_enum)]
    pub level: Option<LogLevelArg>,
    /// Maximum rows to print.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

/// Arguments for `watcher delete --type <noun>`.
#[derive(Debug, Args)]
pub struct DeleteArgs {
    /// Noun to delete: url, port, ip, name, system, or path.
    #[arg(short = 't', long = "type", value_enum)]
    pub target: DeleteTarget,
    /// Require a scoped delete of a baseline asset. Implies `--system`.
    #[arg(long)]
    pub baseline: bool,
    /// Business system that owns the asset. Scopes url/port/ip/name deletes.
    #[arg(long)]
    pub system: Option<String>,
    /// Optional IP address for a scoped port delete.
    #[arg(long)]
    pub ip: Option<String>,
    /// Exact asset value, business-system name, or dictionary path.
    pub value: String,
}

/// Arguments for `watcher unmark --type <noun>`.
#[derive(Debug, Args)]
pub struct UnmarkArgs {
    /// Asset noun to unmark: url, port, ip, or name.
    #[arg(short = 't', long = "type", value_enum)]
    pub target: UnmarkTarget,
    /// Business system that owns the asset.
    #[arg(long)]
    pub system: String,
    /// Optional IP address for a port asset.
    #[arg(long)]
    pub ip: Option<String>,
    /// Exact asset value. Ports must be numeric.
    pub value: String,
}

/// Arguments for `watcher rename --type system`.
#[derive(Debug, Args)]
pub struct RenameArgs {
    /// Noun to rename. Currently only `system`.
    #[arg(short = 't', long = "type", value_enum)]
    pub target: RenameTarget,
    /// Existing name.
    pub old_name: String,
    /// New name.
    pub new_name: String,
}

/// Arguments for `watcher clear --type log`.
#[derive(Debug, Args)]
pub struct ClearArgs {
    /// Noun to clear. Currently only `log`.
    #[arg(short = 't', long = "type", value_enum)]
    pub target: ClearTarget,
    /// Optional RFC3339 cutoff timestamp.
    #[arg(long)]
    pub before: Option<String>,
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
    /// Returns the uppercase log level written to SQLite.
    ///
    /// # Arguments
    ///
    /// - `self`: log level to convert.
    ///
    /// # Returns
    ///
    /// The matching database level string, for example `ERROR`.
    ///
    /// # Examples
    ///
    /// ```
    /// use watcher::cli::LogLevelArg;
    /// assert_eq!(LogLevelArg::Error.as_db_level(), "ERROR");
    /// ```
    pub fn as_db_level(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

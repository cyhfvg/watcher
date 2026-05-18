//! Command-line definitions and small output helpers.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::{db::Database, local_time};

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
    /// Returns the uppercase level stored in SQLite.
    fn as_db_level(self) -> &'static str {
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
    /// Import non-baseline values from a newline-delimited text file.
    Import(EntityImportArgs),
    /// Export values to CSV.
    Export { file: PathBuf },
    /// Query values.
    Query(QueryArgs),
    /// Delete a value.
    Delete { value: String },
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

/// Prints recent monitoring batches.
pub fn print_batches(db: &Database) -> anyhow::Result<()> {
    for row in db.list_batches(30)? {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            row.id,
            row.status,
            local_time::rfc3339_to_local(&row.started_at),
            local_time::optional_rfc3339_to_local(row.ended_at.as_deref()),
            row.report_zip.unwrap_or_else(|| "-".to_string())
        );
    }
    Ok(())
}

/// Prints status for one batch and its alert/vulnerability counts.
pub fn print_batch_status(db: &Database, batch: Option<&str>) -> anyhow::Result<()> {
    let status = db.batch_status(batch)?;
    println!("batch={}", status.batch_id);
    println!("status={}", status.status);
    println!(
        "started_at={}",
        local_time::rfc3339_to_local(&status.started_at)
    );
    println!(
        "ended_at={}",
        local_time::optional_rfc3339_to_local(status.ended_at.as_deref())
    );
    println!("alerts={}", status.alerts);
    println!("vulnerabilities={}", status.vulnerabilities);
    Ok(())
}

/// Handles log query/export/clear commands.
pub fn handle_logs(db: &Database, command: LogCommands) -> anyhow::Result<()> {
    match command {
        LogCommands::Query(args) => {
            let level = args.level.map(LogLevelArg::as_db_level);
            for row in db.query_logs(level, args.keyword.as_deref(), args.limit)? {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    local_time::rfc3339_to_local(&row.created_at),
                    row.level,
                    row.target,
                    row.message,
                    row.fields.unwrap_or_default()
                );
            }
        }
        LogCommands::Export {
            file,
            level,
            keyword,
            limit,
        } => {
            db.export_logs(
                &file,
                level.map(LogLevelArg::as_db_level),
                keyword.as_deref(),
                limit,
            )?;
            println!("{}", file.display());
        }
        LogCommands::Clear { before } => {
            let deleted = db.clear_logs(before.as_deref())?;
            println!("deleted logs: {deleted}");
        }
    }
    Ok(())
}

/// Handles baseline asset import and fine-grained baseline management commands.
pub fn handle_baseline(db: &Database, command: BaselineCommands) -> anyhow::Result<()> {
    match command {
        BaselineCommands::Add(args) => add_baseline_asset(db, args),
        BaselineCommands::Import(args) => import_baseline_assets(db, args),
        BaselineCommands::Export(args) => export_baseline_assets(db, args),
        BaselineCommands::Query(args) => query_baseline_assets(db, args),
        BaselineCommands::Delete(args) => delete_baseline_asset(db, args),
        BaselineCommands::Unmark(args) => unmark_baseline_asset(db, args),
    }
}

/// Handles business system management commands.
pub fn handle_systems(db: &Database, command: SystemCommands) -> anyhow::Result<()> {
    match command {
        SystemCommands::Add { name } => {
            db.upsert_system(&name)?;
            println!("system added: {name}");
            Ok(())
        }
        SystemCommands::Query(args) => {
            print_rows(db.query_systems(args.keyword.as_deref(), args.limit)?)
        }
        SystemCommands::Export { file } => {
            db.export_systems(&file)?;
            println!("{}", file.display());
            Ok(())
        }
        SystemCommands::Delete { name } => {
            let deleted = db.delete_system(&name)?;
            println!("deleted systems: {deleted}");
            Ok(())
        }
        SystemCommands::Rename { old_name, new_name } => {
            let changed = db.rename_system(&old_name, &new_name)?;
            println!("renamed systems: {changed}");
            Ok(())
        }
    }
}

/// Adds one baseline asset according to `--asset-type`.
fn add_baseline_asset(db: &Database, args: BaselineAddArgs) -> anyhow::Result<()> {
    match args.asset_type {
        BaselineAssetType::Url => {
            db.upsert_baseline_url_for_system(&args.system, &args.value, "manual")?;
            println!("baseline url added: {}", args.value);
        }
        BaselineAssetType::Port => {
            let port = parse_port(&args.value)?;
            db.upsert_baseline_port_for_system(&args.system, args.ip.as_deref(), port, "manual")?;
            println!("baseline port added: {port}");
        }
        BaselineAssetType::Ip => {
            db.upsert_baseline_ip_for_system(&args.system, &args.value, "manual")?;
            println!("baseline ip added: {}", args.value);
        }
        BaselineAssetType::Name => {
            db.upsert_baseline_domain_for_system(
                &args.system,
                &args.value,
                args.bind_ip.as_deref(),
            )?;
            println!("baseline name added: {}", args.value);
        }
    }
    Ok(())
}

/// Imports baseline assets according to `--asset-type`.
fn import_baseline_assets(db: &Database, args: BaselineImportArgs) -> anyhow::Result<()> {
    match args.asset_type {
        BaselineImportType::Excel => {
            let imported = crate::import::excel::import_excel(db, &args.file)
                .with_context(|| format!("failed to import excel file {}", args.file.display()))?;
            println!(
                "imported baseline systems={}, names={}, ips={}, ports={}, urls={}",
                imported.systems, imported.names, imported.ips, imported.ports, imported.urls
            );
            Ok(())
        }
        BaselineImportType::Url => {
            let system = required_system(args.system.as_deref(), args.asset_type)?;
            let values = read_import_values(&args.file)?;
            let count = db.import_baseline_urls_for_system(system, &values, "manual")?;
            println!("imported {count}");
            Ok(())
        }
        BaselineImportType::Port => {
            let system = required_system(args.system.as_deref(), args.asset_type)?;
            let ports = read_import_values(&args.file)?
                .iter()
                .map(|value| parse_port(value))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let count =
                db.import_baseline_ports_for_system(system, args.ip.as_deref(), &ports, "manual")?;
            println!("imported {count}");
            Ok(())
        }
        BaselineImportType::Ip => {
            let system = required_system(args.system.as_deref(), args.asset_type)?;
            let values = read_import_values(&args.file)?;
            let count = db.import_baseline_ips_for_system(system, &values, "manual")?;
            println!("imported {count}");
            Ok(())
        }
        BaselineImportType::Name => {
            let system = required_system(args.system.as_deref(), args.asset_type)?;
            let values = read_import_values(&args.file)?;
            let count = db.import_baseline_names_for_system(system, &values)?;
            println!("imported {count}");
            Ok(())
        }
    }
}

/// Exports baseline assets according to `--asset-type`.
fn export_baseline_assets(db: &Database, args: BaselineExportArgs) -> anyhow::Result<()> {
    match args.asset_type {
        BaselineAssetType::Url => db.export_baseline_urls(&args.file)?,
        BaselineAssetType::Port => db.export_baseline_ports(&args.file)?,
        BaselineAssetType::Ip => db.export_baseline_ips(&args.file)?,
        BaselineAssetType::Name => db.export_baseline_names(&args.file)?,
    }
    println!("{}", args.file.display());
    Ok(())
}

/// Queries baseline assets according to `--asset-type`.
fn query_baseline_assets(db: &Database, args: BaselineQueryArgs) -> anyhow::Result<()> {
    let rows = match args.asset_type {
        BaselineAssetType::Url => db.query_baseline_urls(args.keyword.as_deref(), args.limit)?,
        BaselineAssetType::Port => db.query_baseline_ports(args.keyword.as_deref(), args.limit)?,
        BaselineAssetType::Ip => db.query_baseline_ips(args.keyword.as_deref(), args.limit)?,
        BaselineAssetType::Name => db.query_baseline_names(args.keyword.as_deref(), args.limit)?,
    };
    print_rows(rows)
}

/// Deletes one baseline asset row according to `--asset-type`.
fn delete_baseline_asset(db: &Database, args: BaselineMutateArgs) -> anyhow::Result<()> {
    let deleted = match args.asset_type {
        BaselineAssetType::Url => db.delete_url_for_system(&args.system, &args.value)?,
        BaselineAssetType::Port => {
            db.delete_port_for_system(&args.system, args.ip.as_deref(), parse_port(&args.value)?)?
        }
        BaselineAssetType::Ip => db.delete_ip_for_system(&args.system, &args.value)?,
        BaselineAssetType::Name => db.delete_name_for_system(&args.system, &args.value)?,
    };
    println!("deleted baseline rows: {deleted}");
    Ok(())
}

/// Removes the baseline marker from one asset according to `--asset-type`.
fn unmark_baseline_asset(db: &Database, args: BaselineMutateArgs) -> anyhow::Result<()> {
    let changed = match args.asset_type {
        BaselineAssetType::Url => {
            db.set_url_baseline_for_system(&args.system, &args.value, false)?
        }
        BaselineAssetType::Port => db.set_port_baseline_for_system(
            &args.system,
            args.ip.as_deref(),
            parse_port(&args.value)?,
            false,
        )?,
        BaselineAssetType::Ip => db.set_ip_baseline_for_system(&args.system, &args.value, false)?,
        BaselineAssetType::Name => {
            db.set_name_baseline_for_system(&args.system, &args.value, false)?
        }
    };
    println!("baseline rows updated: {changed}");
    Ok(())
}

/// Parses a CLI port value.
fn parse_port(value: &str) -> anyhow::Result<u16> {
    value
        .parse::<u16>()
        .with_context(|| format!("invalid port {value}"))
}

/// Returns a required business system argument for typed baseline imports.
fn required_system(system: Option<&str>, asset_type: BaselineImportType) -> anyhow::Result<&str> {
    system.with_context(|| format!("--system is required for asset-type={asset_type:?}"))
}

/// Handles URL asset management commands.
pub fn handle_urls(db: &Database, command: EntityCommands) -> anyhow::Result<()> {
    match command {
        EntityCommands::Import(args) => {
            ensure_entity_import_options(&args, false, false)?;
            let values = read_import_values(&args.file)?;
            let count = db.import_urls_for_system(&args.system, &values, "manual")?;
            println!("imported {count}");
            Ok(())
        }
        EntityCommands::Export { file } => {
            db.export_urls(&file)?;
            println!("{}", file.display());
            Ok(())
        }
        EntityCommands::Query(args) => {
            print_rows(db.query_urls(args.keyword.as_deref(), args.limit)?)
        }
        EntityCommands::Delete { value } => {
            db.delete_url(&value)?;
            println!("deleted url: {value}");
            Ok(())
        }
    }
}

/// Handles port asset management commands.
pub fn handle_ports(db: &Database, command: EntityCommands) -> anyhow::Result<()> {
    match command {
        EntityCommands::Import(args) => {
            ensure_entity_import_options(&args, true, false)?;
            let ports = read_import_values(&args.file)?
                .iter()
                .map(|value| parse_port(value))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let count =
                db.import_ports_for_system(&args.system, args.ip.as_deref(), &ports, "manual")?;
            println!("imported {count}");
            Ok(())
        }
        EntityCommands::Export { file } => {
            db.export_ports(&file)?;
            println!("{}", file.display());
            Ok(())
        }
        EntityCommands::Query(args) => {
            print_rows(db.query_ports(args.keyword.as_deref(), args.limit)?)
        }
        EntityCommands::Delete { value } => {
            let port = value
                .parse::<u16>()
                .with_context(|| format!("invalid port {value}"))?;
            db.delete_port(port)?;
            println!("deleted port: {port}");
            Ok(())
        }
    }
}

/// Handles IP asset management commands.
pub fn handle_ips(db: &Database, command: EntityCommands) -> anyhow::Result<()> {
    match command {
        EntityCommands::Import(args) => {
            ensure_entity_import_options(&args, false, false)?;
            let values = read_import_values(&args.file)?;
            let count = db.import_ips_for_system(&args.system, &values, "manual")?;
            println!("imported {count}");
            Ok(())
        }
        EntityCommands::Export { file } => {
            db.export_ips(&file)?;
            println!("{}", file.display());
            Ok(())
        }
        EntityCommands::Query(args) => {
            print_rows(db.query_ips(args.keyword.as_deref(), args.limit)?)
        }
        EntityCommands::Delete { value } => {
            db.delete_ip(&value)?;
            println!("deleted ip: {value}");
            Ok(())
        }
    }
}

/// Handles domain-name asset management commands.
pub fn handle_names(db: &Database, command: EntityCommands) -> anyhow::Result<()> {
    match command {
        EntityCommands::Import(args) => {
            ensure_entity_import_options(&args, false, true)?;
            let values = read_import_values(&args.file)?;
            let count =
                db.import_names_for_system(&args.system, &values, args.bind_ip.as_deref())?;
            println!("imported {count}");
            Ok(())
        }
        EntityCommands::Export { file } => {
            db.export_names(&file)?;
            println!("{}", file.display());
            Ok(())
        }
        EntityCommands::Query(args) => {
            print_rows(db.query_names(args.keyword.as_deref(), args.limit)?)
        }
        EntityCommands::Delete { value } => {
            db.delete_name(&value)?;
            println!("deleted name: {value}");
            Ok(())
        }
    }
}

/// Reads newline-delimited values from an import file.
fn read_import_values(file: &PathBuf) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// Rejects entity import options that do not apply to the selected asset type.
fn ensure_entity_import_options(
    args: &EntityImportArgs,
    allow_ip: bool,
    allow_bind_ip: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        allow_ip || args.ip.is_none(),
        "--ip is only supported by port import"
    );
    anyhow::ensure!(
        allow_bind_ip || args.bind_ip.is_none(),
        "--bind-ip is only supported by name import"
    );
    Ok(())
}

/// Prints tab-separated rows.
fn print_rows(rows: Vec<Vec<String>>) -> anyhow::Result<()> {
    for row in rows {
        println!("{}", row.join("\t"));
    }
    Ok(())
}

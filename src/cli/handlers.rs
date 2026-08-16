//! Batch status, log, and business-system command handlers.

use crate::cli::args::{LogCommands, LogLevelArg, SystemCommands};
use crate::cli::entities::print_rows;
use crate::{db::Database, local_time};

/// Prints recent monitoring batches.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when listing batches fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::print_batches;
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// print_batches(&db)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
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

/// Prints one batch's status and its alert/vulnerability counts.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `batch`: optional batch id. Uses the latest batch when `None`.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when querying batch status fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::print_batch_status;
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// # let _ = print_batch_status(&db, None);
/// # Ok::<(), anyhow::Error>(())
/// ```
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

/// Handles log query, export, and cleanup commands.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `command`: log subcommand.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when querying, exporting, or cleaning logs fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{LogCommands, LogQueryArgs, handle_logs};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_logs(
///     &db,
///     LogCommands::Query(LogQueryArgs {
///         level: None,
///         keyword: None,
///         limit: 10,
///     }),
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
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

/// Handles business-system management commands.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `command`: business-system subcommand.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when creating, updating, listing, deleting, or exporting
/// business systems fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{SystemCommands, handle_systems};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_systems(&db, SystemCommands::Add { name: "core".into() })?;
/// # Ok::<(), anyhow::Error>(())
/// ```
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

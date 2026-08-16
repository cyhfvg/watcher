//! Action-first command handlers for assets, systems, dictionaries, and logs.

use anyhow::Context;

use crate::cli::args::{
    AddArgs, ClearArgs, DeleteArgs, ExportArgs, ImportArgs, LogLevelArg, QueryArgs, RenameArgs,
    TargetKind, UnmarkArgs,
};
use crate::cli::assets::{add_asset, delete_asset, ensure_unused_asset_options, import_assets};
use crate::cli::common::{parse_port, print_rows};
use crate::db::Database;
use crate::dict;
use crate::local_time;

/// Adds one business system or asset selected by `--type`.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `add` arguments.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when `--type` is not addable, required options are missing,
/// port parsing fails, or writing to the database fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{AddArgs, AddTarget, handle_add};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_add(
///     &db,
///     AddArgs {
///         target: AddTarget::Ip,
///         baseline: false,
///         system: Some("core".into()),
///         ip: None,
///         bind_ip: None,
///         value: "10.0.0.1".into(),
///     },
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_add(db: &Database, args: AddArgs) -> anyhow::Result<()> {
    match TargetKind::from(args.target) {
        TargetKind::System => {
            ensure_unused_asset_options(
                args.baseline,
                args.system.as_deref(),
                &args.ip,
                &args.bind_ip,
                "system add",
            )?;
            db.upsert_system(&args.value)?;
            println!("system added: {}", args.value);
        }
        TargetKind::Url | TargetKind::Port | TargetKind::Ip | TargetKind::Name => {
            add_asset(db, args)?;
        }
        other => anyhow::bail!("--type {other} is not supported by add"),
    }
    Ok(())
}

/// Imports assets, a path dictionary, or an Excel baseline workbook.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `import` arguments.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when `--type` is not importable, required options are
/// missing, reading the file fails, or writing to the database fails.
///
/// # Examples
///
/// ```
/// # use std::io::Write;
/// # use watcher::cli::{ImportArgs, ImportTarget, handle_import};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// # let file = dir.path().join("ips.txt");
/// # std::fs::File::create(&file)?.write_all(b"10.0.0.2\n")?;
/// handle_import(
///     &db,
///     ImportArgs {
///         target: ImportTarget::Ip,
///         baseline: false,
///         system: Some("core".into()),
///         ip: None,
///         bind_ip: None,
///         file,
///     },
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_import(db: &Database, args: ImportArgs) -> anyhow::Result<()> {
    match TargetKind::from(args.target) {
        TargetKind::Excel => {
            anyhow::ensure!(
                args.system.is_none(),
                "--system is not used by --type excel"
            );
            anyhow::ensure!(args.ip.is_none(), "--ip is not used by --type excel");
            anyhow::ensure!(
                args.bind_ip.is_none(),
                "--bind-ip is not used by --type excel"
            );
            let imported = crate::import::excel::import_excel(db, &args.file)
                .with_context(|| format!("failed to import excel file {}", args.file.display()))?;
            println!(
                "imported baseline systems={}, names={}, ips={}, ports={}, urls={}",
                imported.systems, imported.names, imported.ips, imported.ports, imported.urls
            );
        }
        TargetKind::Path => {
            anyhow::ensure!(!args.baseline, "--baseline is not used by --type path");
            anyhow::ensure!(args.system.is_none(), "--system is not used by --type path");
            anyhow::ensure!(args.ip.is_none(), "--ip is not used by --type path");
            anyhow::ensure!(
                args.bind_ip.is_none(),
                "--bind-ip is not used by --type path"
            );
            dict::paths::import_file(db, &args.file)?;
        }
        TargetKind::Url | TargetKind::Port | TargetKind::Ip | TargetKind::Name => {
            import_assets(db, args)?;
        }
        other => anyhow::bail!("--type {other} is not supported by import"),
    }
    Ok(())
}

/// Exports assets, systems, the path dictionary, or logs.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `export` arguments.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when `--type` is not exportable or writing the file fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{ExportArgs, InspectTarget, handle_export};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_export(
///     &db,
///     ExportArgs {
///         target: InspectTarget::System,
///         baseline: false,
///         level: None,
///         keyword: None,
///         limit: 1000,
///         file: dir.path().join("systems.csv"),
///     },
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_export(db: &Database, args: ExportArgs) -> anyhow::Result<()> {
    match TargetKind::from(args.target) {
        TargetKind::Url if args.baseline => db.export_baseline_urls(&args.file)?,
        TargetKind::Port if args.baseline => db.export_baseline_ports(&args.file)?,
        TargetKind::Ip if args.baseline => db.export_baseline_ips(&args.file)?,
        TargetKind::Name if args.baseline => db.export_baseline_names(&args.file)?,
        TargetKind::Url => db.export_urls(&args.file)?,
        TargetKind::Port => db.export_ports(&args.file)?,
        TargetKind::Ip => db.export_ips(&args.file)?,
        TargetKind::Name => db.export_names(&args.file)?,
        TargetKind::System => {
            anyhow::ensure!(!args.baseline, "--baseline is not used by --type system");
            db.export_systems(&args.file)?;
        }
        TargetKind::Path => {
            anyhow::ensure!(!args.baseline, "--baseline is not used by --type path");
            dict::paths::export_file(db, &args.file)?;
            return Ok(());
        }
        TargetKind::Log => {
            anyhow::ensure!(!args.baseline, "--baseline is not used by --type log");
            db.export_logs(
                &args.file,
                args.level.map(LogLevelArg::as_db_level),
                args.keyword.as_deref(),
                args.limit,
            )?;
        }
        other => anyhow::bail!("--type {other} is not supported by export"),
    }
    println!("{}", args.file.display());
    Ok(())
}

/// Queries assets, systems, the path dictionary, or logs.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `query` arguments.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when `--type` is not queryable or the database query fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{InspectTarget, QueryArgs, handle_query};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_query(
///     &db,
///     QueryArgs {
///         target: InspectTarget::System,
///         baseline: false,
///         keyword: None,
///         level: None,
///         limit: 10,
///     },
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_query(db: &Database, args: QueryArgs) -> anyhow::Result<()> {
    match TargetKind::from(args.target) {
        TargetKind::Url if args.baseline => {
            print_rows(db.query_baseline_urls(args.keyword.as_deref(), args.limit)?)
        }
        TargetKind::Port if args.baseline => {
            print_rows(db.query_baseline_ports(args.keyword.as_deref(), args.limit)?)
        }
        TargetKind::Ip if args.baseline => {
            print_rows(db.query_baseline_ips(args.keyword.as_deref(), args.limit)?)
        }
        TargetKind::Name if args.baseline => {
            print_rows(db.query_baseline_names(args.keyword.as_deref(), args.limit)?)
        }
        TargetKind::Url => print_rows(db.query_urls(args.keyword.as_deref(), args.limit)?),
        TargetKind::Port => print_rows(db.query_ports(args.keyword.as_deref(), args.limit)?),
        TargetKind::Ip => print_rows(db.query_ips(args.keyword.as_deref(), args.limit)?),
        TargetKind::Name => print_rows(db.query_names(args.keyword.as_deref(), args.limit)?),
        TargetKind::System => {
            anyhow::ensure!(!args.baseline, "--baseline is not used by --type system");
            print_rows(db.query_systems(args.keyword.as_deref(), args.limit)?)
        }
        TargetKind::Path => {
            anyhow::ensure!(!args.baseline, "--baseline is not used by --type path");
            dict::paths::query(db, args.keyword.as_deref(), args.limit)
        }
        TargetKind::Log => {
            anyhow::ensure!(!args.baseline, "--baseline is not used by --type log");
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
            Ok(())
        }
        other => anyhow::bail!("--type {other} is not supported by query"),
    }
}

/// Deletes one business system, asset, or path-dictionary entry.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `delete` arguments.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when `--type` is not deletable, required options are
/// missing, port parsing fails, or the delete fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{DeleteArgs, DeleteTarget, handle_delete};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_delete(
///     &db,
///     DeleteArgs {
///         target: DeleteTarget::System,
///         baseline: false,
///         system: None,
///         ip: None,
///         value: "missing".into(),
///     },
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_delete(db: &Database, args: DeleteArgs) -> anyhow::Result<()> {
    match TargetKind::from(args.target) {
        TargetKind::System => {
            anyhow::ensure!(!args.baseline, "--baseline is not used by --type system");
            anyhow::ensure!(
                args.system.is_none(),
                "--system is not used by --type system"
            );
            anyhow::ensure!(args.ip.is_none(), "--ip is not used by --type system");
            let deleted = db.delete_system(&args.value)?;
            println!("deleted systems: {deleted}");
        }
        TargetKind::Path => {
            anyhow::ensure!(!args.baseline, "--baseline is not used by --type path");
            anyhow::ensure!(args.system.is_none(), "--system is not used by --type path");
            anyhow::ensure!(args.ip.is_none(), "--ip is not used by --type path");
            dict::paths::delete(db, &args.value)?;
        }
        TargetKind::Url | TargetKind::Port | TargetKind::Ip | TargetKind::Name => {
            delete_asset(db, args)?;
        }
        other => anyhow::bail!("--type {other} is not supported by delete"),
    }
    Ok(())
}

/// Removes the baseline marker from one URL/port/IP/name asset.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `unmark` arguments.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when `--type` is not an asset, port parsing fails, or the
/// update fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{UnmarkArgs, UnmarkTarget, handle_unmark};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_unmark(
///     &db,
///     UnmarkArgs {
///         target: UnmarkTarget::Ip,
///         system: "core".into(),
///         ip: None,
///         value: "10.0.0.1".into(),
///     },
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_unmark(db: &Database, args: UnmarkArgs) -> anyhow::Result<()> {
    let changed = match TargetKind::from(args.target) {
        TargetKind::Url => db.set_url_baseline_for_system(&args.system, &args.value, false)?,
        TargetKind::Port => db.set_port_baseline_for_system(
            &args.system,
            args.ip.as_deref(),
            parse_port(&args.value)?,
            false,
        )?,
        TargetKind::Ip => db.set_ip_baseline_for_system(&args.system, &args.value, false)?,
        TargetKind::Name => {
            anyhow::ensure!(args.ip.is_none(), "--ip is only supported by --type port");
            db.set_name_baseline_for_system(&args.system, &args.value, false)?
        }
        other => anyhow::bail!("--type {other} is not supported by unmark"),
    };
    println!("baseline rows updated: {changed}");
    Ok(())
}

/// Renames a business system.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `rename` arguments.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when `--type` is not `system` or the rename fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{RenameArgs, RenameTarget, handle_rename};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// # db.upsert_system("core")?;
/// handle_rename(
///     &db,
///     RenameArgs {
///         target: RenameTarget::System,
///         old_name: "core".into(),
///         new_name: "core-prod".into(),
///     },
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_rename(db: &Database, args: RenameArgs) -> anyhow::Result<()> {
    let changed = db.rename_system(&args.old_name, &args.new_name)?;
    println!("renamed systems: {changed}");
    Ok(())
}

/// Clears stored records selected by `--type`. Currently only logs.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `clear` arguments.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when `--type` is not `log` or clearing logs fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{ClearArgs, ClearTarget, handle_clear};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_clear(
///     &db,
///     ClearArgs {
///         target: ClearTarget::Log,
///         before: None,
///     },
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_clear(db: &Database, args: ClearArgs) -> anyhow::Result<()> {
    let deleted = db.clear_logs(args.before.as_deref())?;
    println!("deleted logs: {deleted}");
    Ok(())
}

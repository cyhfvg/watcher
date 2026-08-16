//! Non-baseline URL, port, IP, and domain command handling.

use std::path::PathBuf;

use anyhow::Context;

use crate::cli::args::{EntityAddArgs, EntityCommands, EntityImportArgs};
use crate::cli::common::parse_port;
use crate::db::Database;

/// Handles URL asset management commands.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `command`: URL entity subcommand.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when an option does not apply to URLs, reading the import
/// file fails, or writing to the database fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{EntityAddArgs, EntityCommands, handle_urls};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_urls(
///     &db,
///     EntityCommands::Add(EntityAddArgs {
///         system: "core".into(),
///         ip: None,
///         bind_ip: None,
///         value: "https://example.com".into(),
///     }),
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_urls(db: &Database, command: EntityCommands) -> anyhow::Result<()> {
    match command {
        EntityCommands::Add(args) => {
            ensure_entity_add_options(&args, false, false)?;
            db.upsert_url_for_system(&args.system, &args.value, "manual")?;
            println!("added url: {}", args.value);
            Ok(())
        }
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
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `command`: port entity subcommand.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when an option does not apply to ports, port parsing fails,
/// reading the import file fails, or writing to the database fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{EntityAddArgs, EntityCommands, handle_ports};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_ports(
///     &db,
///     EntityCommands::Add(EntityAddArgs {
///         system: "core".into(),
///         ip: Some("10.0.0.1".into()),
///         bind_ip: None,
///         value: "443".into(),
///     }),
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_ports(db: &Database, command: EntityCommands) -> anyhow::Result<()> {
    match command {
        EntityCommands::Add(args) => {
            ensure_entity_add_options(&args, true, false)?;
            let port = parse_port(&args.value)?;
            db.upsert_port_for_system(&args.system, args.ip.as_deref(), port, "manual")?;
            println!("added port: {port}");
            Ok(())
        }
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
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `command`: IP entity subcommand.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when an option does not apply to IPs, reading the import
/// file fails, or writing to the database fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{EntityAddArgs, EntityCommands, handle_ips};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_ips(
///     &db,
///     EntityCommands::Add(EntityAddArgs {
///         system: "core".into(),
///         ip: None,
///         bind_ip: None,
///         value: "10.0.0.2".into(),
///     }),
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_ips(db: &Database, command: EntityCommands) -> anyhow::Result<()> {
    match command {
        EntityCommands::Add(args) => {
            ensure_entity_add_options(&args, false, false)?;
            db.upsert_ip_for_system(&args.system, &args.value, "manual")?;
            println!("added ip: {}", args.value);
            Ok(())
        }
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

/// Handles domain asset management commands.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `command`: domain entity subcommand.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when an option does not apply to domains, reading the
/// import file fails, or writing to the database fails.
///
/// # Examples
///
/// ```
/// # use watcher::cli::{EntityAddArgs, EntityCommands, handle_names};
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_names(
///     &db,
///     EntityCommands::Add(EntityAddArgs {
///         system: "core".into(),
///         ip: None,
///         bind_ip: Some("10.0.0.1".into()),
///         value: "app.example.com".into(),
///     }),
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn handle_names(db: &Database, command: EntityCommands) -> anyhow::Result<()> {
    match command {
        EntityCommands::Add(args) => {
            ensure_entity_add_options(&args, false, true)?;
            db.upsert_domain_for_system(&args.system, &args.value, args.bind_ip.as_deref())?;
            println!("added name: {}", args.value);
            Ok(())
        }
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

/// Reads newline-separated values from an import file.
///
/// # Arguments
///
/// - `file`: path to a newline-separated asset file.
///
/// # Returns
///
/// Non-empty lines after trimming whitespace.
///
/// # Errors
///
/// Returns an error when reading the file fails.
///
/// # Examples
///
/// ```text
/// read_import_values(PathBuf::from("urls.txt")) -> Ok(vec!["https://a", "https://b"])
/// ```
pub(crate) fn read_import_values(file: &PathBuf) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// Rejects entity-import options that do not apply to the selected asset type.
///
/// # Arguments
///
/// - `args`: entity import arguments.
/// - `allow_ip`: whether `--ip` is allowed.
/// - `allow_bind_ip`: whether `--bind-ip` is allowed.
///
/// # Returns
///
/// `Ok(())` when the options are valid.
///
/// # Errors
///
/// Returns an error when an option is not supported for the current asset type.
///
/// # Examples
///
/// ```text
/// ensure_entity_import_options(args, false, false)
/// ```
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

/// Rejects add options that do not apply to the selected asset type.
///
/// # Arguments
///
/// - `args`: entity add arguments.
/// - `allow_ip`: whether `--ip` is allowed.
/// - `allow_bind_ip`: whether `--bind-ip` is allowed.
///
/// # Returns
///
/// `Ok(())` when the options are valid.
///
/// # Errors
///
/// Returns an error when an option is not supported for the current asset type.
///
/// # Examples
///
/// ```text
/// ensure_entity_add_options(args, false, false)
/// ```
fn ensure_entity_add_options(
    args: &EntityAddArgs,
    allow_ip: bool,
    allow_bind_ip: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        allow_ip || args.ip.is_none(),
        "--ip is only supported by port add"
    );
    anyhow::ensure!(
        allow_bind_ip || args.bind_ip.is_none(),
        "--bind-ip is only supported by name add"
    );
    Ok(())
}

/// Prints tab-separated rows.
///
/// # Arguments
///
/// - `rows`: cell rows to print.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// The current implementation never returns an error.
///
/// # Examples
///
/// ```text
/// print_rows(vec![vec!["a".into(), "b".into()]])
/// ```
pub(crate) fn print_rows(rows: Vec<Vec<String>>) -> anyhow::Result<()> {
    for row in rows {
        println!("{}", row.join("\t"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an `EntityAddArgs` used by option-validation tests.
    ///
    /// # Arguments
    ///
    /// - `value`: asset value.
    /// - `ip`: optional bind IP.
    /// - `bind_ip`: optional domain bind IP.
    ///
    /// # Returns
    ///
    /// Arguments with the business system fixed to `core`.
    ///
    /// # Examples
    ///
    /// ```text
    /// add_args("443", Some("10.0.0.1"), None)
    /// ```
    fn add_args(value: &str, ip: Option<&str>, bind_ip: Option<&str>) -> EntityAddArgs {
        EntityAddArgs {
            system: "core".to_string(),
            ip: ip.map(str::to_string),
            bind_ip: bind_ip.map(str::to_string),
            value: value.to_string(),
        }
    }

    /// Checks that the URL add command rejects `--ip`.
    ///
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// none
    ///
    /// # Examples
    ///
    /// ```text
    /// cargo test --lib cli::entities::tests::rejects_options_that_do_not_apply_to_asset_type
    /// ```

    #[test]
    fn rejects_options_that_do_not_apply_to_asset_type() {
        let error = ensure_entity_add_options(
            &add_args("https://example.com", Some("10.0.0.1"), None),
            false,
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("only supported by port add"));
    }
}

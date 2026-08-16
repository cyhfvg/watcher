//! URL/port/IP/name helpers shared by action-first commands.

use anyhow::Context;

use crate::cli::args::{AddArgs, DeleteArgs, ImportArgs, TargetKind};
use crate::cli::common::parse_port;
use crate::db::Database;

/// Adds one URL, port, IP, or domain asset.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `add` arguments for an asset noun.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when `--system` is missing, an option does not apply, port
/// parsing fails, or writing to the database fails.
///
/// # Examples
///
/// ```text
/// add_asset(db, AddArgs { target: Url, ... })
/// ```
pub(crate) fn add_asset(db: &Database, args: AddArgs) -> anyhow::Result<()> {
    let target = TargetKind::from(args.target);
    let system = required_system(args.system.as_deref(), target)?;
    ensure_asset_bind_options(target, args.ip.as_deref(), args.bind_ip.as_deref())?;
    match (target, args.baseline) {
        (TargetKind::Url, false) => {
            db.upsert_url_for_system(system, &args.value, "manual")?;
            println!("added url: {}", args.value);
        }
        (TargetKind::Url, true) => {
            db.upsert_baseline_url_for_system(system, &args.value, "manual")?;
            println!("baseline url added: {}", args.value);
        }
        (TargetKind::Port, false) => {
            let port = parse_port(&args.value)?;
            db.upsert_port_for_system(system, args.ip.as_deref(), port, "manual")?;
            println!("added port: {port}");
        }
        (TargetKind::Port, true) => {
            let port = parse_port(&args.value)?;
            db.upsert_baseline_port_for_system(system, args.ip.as_deref(), port, "manual")?;
            println!("baseline port added: {port}");
        }
        (TargetKind::Ip, false) => {
            db.upsert_ip_for_system(system, &args.value, "manual")?;
            println!("added ip: {}", args.value);
        }
        (TargetKind::Ip, true) => {
            db.upsert_baseline_ip_for_system(system, &args.value, "manual")?;
            println!("baseline ip added: {}", args.value);
        }
        (TargetKind::Name, false) => {
            db.upsert_domain_for_system(system, &args.value, args.bind_ip.as_deref())?;
            println!("added name: {}", args.value);
        }
        (TargetKind::Name, true) => {
            db.upsert_baseline_domain_for_system(system, &args.value, args.bind_ip.as_deref())?;
            println!("baseline name added: {}", args.value);
        }
        (other, _) => anyhow::bail!("--type {other} is not supported by add"),
    }
    Ok(())
}

/// Imports newline-delimited URL, port, IP, or domain assets.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `import` arguments for an asset noun.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when `--system` is missing, an option does not apply,
/// reading the file fails, port parsing fails, or writing fails.
///
/// # Examples
///
/// ```text
/// import_assets(db, ImportArgs { target: Url, ... })
/// ```
pub(crate) fn import_assets(db: &Database, args: ImportArgs) -> anyhow::Result<()> {
    let target = TargetKind::from(args.target);
    let system = required_system(args.system.as_deref(), target)?;
    ensure_asset_bind_options(target, args.ip.as_deref(), args.bind_ip.as_deref())?;
    let values = read_import_values(&args.file)?;
    let count = match (target, args.baseline) {
        (TargetKind::Url, false) => db.import_urls_for_system(system, &values, "manual")?,
        (TargetKind::Url, true) => db.import_baseline_urls_for_system(system, &values, "manual")?,
        (TargetKind::Port, false) => {
            let ports = parse_ports(&values)?;
            db.import_ports_for_system(system, args.ip.as_deref(), &ports, "manual")?
        }
        (TargetKind::Port, true) => {
            let ports = parse_ports(&values)?;
            db.import_baseline_ports_for_system(system, args.ip.as_deref(), &ports, "manual")?
        }
        (TargetKind::Ip, false) => db.import_ips_for_system(system, &values, "manual")?,
        (TargetKind::Ip, true) => db.import_baseline_ips_for_system(system, &values, "manual")?,
        (TargetKind::Name, false) => {
            db.import_names_for_system(system, &values, args.bind_ip.as_deref())?
        }
        (TargetKind::Name, true) => db.import_baseline_names_for_system(system, &values)?,
        (other, _) => anyhow::bail!("--type {other} is not supported by import"),
    };
    println!("imported {count}");
    Ok(())
}

/// Deletes one URL, port, IP, or domain asset.
///
/// # Arguments
///
/// - `db`: opened database that has already been migrated.
/// - `args`: parsed `delete` arguments for an asset noun.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error when a scoped delete is missing `--system`, an option does
/// not apply, port parsing fails, or the delete fails.
///
/// # Examples
///
/// ```text
/// delete_asset(db, DeleteArgs { target: Url, ... })
/// ```
pub(crate) fn delete_asset(db: &Database, args: DeleteArgs) -> anyhow::Result<()> {
    let target = TargetKind::from(args.target);
    let scoped = args.baseline || args.system.is_some();
    if args.baseline {
        required_system(args.system.as_deref(), target)?;
    }
    if !scoped {
        anyhow::ensure!(
            args.ip.is_none(),
            "--ip requires --system for a scoped port delete"
        );
        match target {
            TargetKind::Url => {
                db.delete_url(&args.value)?;
                println!("deleted url: {}", args.value);
            }
            TargetKind::Port => {
                let port = parse_port(&args.value)?;
                db.delete_port(port)?;
                println!("deleted port: {port}");
            }
            TargetKind::Ip => {
                db.delete_ip(&args.value)?;
                println!("deleted ip: {}", args.value);
            }
            TargetKind::Name => {
                db.delete_name(&args.value)?;
                println!("deleted name: {}", args.value);
            }
            other => anyhow::bail!("--type {other} is not supported by delete"),
        }
        return Ok(());
    }

    let system = required_system(args.system.as_deref(), target)?;
    ensure_asset_bind_options(target, args.ip.as_deref(), None)?;
    let deleted = match target {
        TargetKind::Url => db.delete_url_for_system(system, &args.value)?,
        TargetKind::Port => {
            db.delete_port_for_system(system, args.ip.as_deref(), parse_port(&args.value)?)?
        }
        TargetKind::Ip => db.delete_ip_for_system(system, &args.value)?,
        TargetKind::Name => db.delete_name_for_system(system, &args.value)?,
        other => anyhow::bail!("--type {other} is not supported by delete"),
    };
    println!("deleted baseline rows: {deleted}");
    Ok(())
}

/// Returns the business-system argument required by asset commands.
///
/// # Arguments
///
/// - `system`: optional business-system name.
/// - `target`: noun being operated on, used in the error message.
///
/// # Returns
///
/// The business-system name when present.
///
/// # Errors
///
/// Returns an error when `system` is `None`.
///
/// # Examples
///
/// ```text
/// required_system(Some("core"), TargetKind::Url) -> Ok("core")
/// ```
pub(crate) fn required_system(system: Option<&str>, target: TargetKind) -> anyhow::Result<&str> {
    system.with_context(|| format!("--system is required for --type {target}"))
}

/// Rejects bind options that do not apply to the selected asset noun.
///
/// # Arguments
///
/// - `target`: selected asset noun.
/// - `ip`: optional `--ip` value.
/// - `bind_ip`: optional `--bind-ip` value.
///
/// # Returns
///
/// `Ok(())` when the options are valid.
///
/// # Errors
///
/// Returns an error when `--ip` or `--bind-ip` is not supported.
///
/// # Examples
///
/// ```text
/// ensure_asset_bind_options(TargetKind::Url, Some("10.0.0.1"), None)
/// ```
pub(crate) fn ensure_asset_bind_options(
    target: TargetKind,
    ip: Option<&str>,
    bind_ip: Option<&str>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        target == TargetKind::Port || ip.is_none(),
        "--ip is only supported by --type port"
    );
    anyhow::ensure!(
        target == TargetKind::Name || bind_ip.is_none(),
        "--bind-ip is only supported by --type name"
    );
    Ok(())
}

/// Rejects asset-only options on non-asset commands.
///
/// # Arguments
///
/// - `baseline`: whether `--baseline` was set.
/// - `system`: optional `--system` value.
/// - `ip`: optional `--ip` value.
/// - `bind_ip`: optional `--bind-ip` value.
/// - `command`: command name used in the error message.
///
/// # Returns
///
/// `Ok(())` when none of the asset-only options were provided.
///
/// # Errors
///
/// Returns an error when an asset-only option is present.
///
/// # Examples
///
/// ```text
/// ensure_unused_asset_options(false, None, &None, &None, "system add")
/// ```
pub(crate) fn ensure_unused_asset_options(
    baseline: bool,
    system: Option<&str>,
    ip: &Option<String>,
    bind_ip: &Option<String>,
    command: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(!baseline, "--baseline is not used by {command}");
    anyhow::ensure!(system.is_none(), "--system is not used by {command}");
    anyhow::ensure!(ip.is_none(), "--ip is not used by {command}");
    anyhow::ensure!(bind_ip.is_none(), "--bind-ip is not used by {command}");
    Ok(())
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
/// read_import_values(Path::new("urls.txt")) -> Ok(vec!["https://a"])
/// ```
fn read_import_values(file: &std::path::Path) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// Parses imported port strings.
///
/// # Arguments
///
/// - `values`: raw port strings.
///
/// # Returns
///
/// Parsed `u16` ports.
///
/// # Errors
///
/// Returns an error when any value is not a valid `u16`.
///
/// # Examples
///
/// ```text
/// parse_ports(&["80".into(), "443".into()]) -> Ok(vec![80, 443])
/// ```
fn parse_ports(values: &[String]) -> anyhow::Result<Vec<u16>> {
    values.iter().map(|value| parse_port(value)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that URL add rejects `--ip`.
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
    /// cargo test --lib cli::assets::tests::rejects_options_that_do_not_apply_to_asset_type
    /// ```
    #[test]
    fn rejects_options_that_do_not_apply_to_asset_type() {
        let error = ensure_asset_bind_options(TargetKind::Url, Some("10.0.0.1"), None).unwrap_err();
        assert!(error.to_string().contains("only supported by --type port"));
    }
}

//! Batch list and status printers used by `task` subcommands.

use crate::cli::common::print_rows;
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
    print_rows(
        db.list_batches(30)?
            .into_iter()
            .map(|row| {
                vec![
                    row.id,
                    row.status,
                    local_time::rfc3339_to_local(&row.started_at),
                    local_time::optional_rfc3339_to_local(row.ended_at.as_deref()),
                    row.report_zip.unwrap_or_else(|| "-".to_string()),
                ]
            })
            .collect(),
    )
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

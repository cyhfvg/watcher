//! Report generation and zip packaging.
//!
//! The public entry points are [`ReportPackage`] and [`build_report_package`].

mod archive;
mod summary;
mod tables;

use std::{fs, path::PathBuf};

use anyhow::Context;

use crate::{config::AppConfig, db::Database};

use self::archive::zip_dir;
use self::summary::render_markdown;
use self::tables::{build_detail_tables, write_detail_tables, write_text};

/// Metadata for a generated report archive.
#[derive(Debug, Clone)]
pub struct ReportPackage {
    /// Path of the generated zip archive.
    pub zip_path: PathBuf,
}

/// Builds a report directory for a batch (or the latest batch) and packs it as a zip.
///
/// # Arguments
/// - `db`: opened database handle used to read batch status and details
/// - `config`: runtime config providing the report output directory and detail format
/// - `batch`: batch ID; uses the latest batch when `None`
///
/// # Returns
/// A [`ReportPackage`] that contains the generated zip path
///
/// # Errors
/// Returns an error when the batch does not exist, a database query fails, or
/// writing the report directory, files, or archive fails.
///
/// # Examples
///
/// ```
/// use watcher::config::AppConfig;
/// use watcher::db::Database;
/// use watcher::report::{ReportPackage, build_report_package};
///
/// fn generate(db: &Database, config: &AppConfig) -> anyhow::Result<ReportPackage> {
///     build_report_package(db, config, Some("batch-1"))
/// }
/// ```
pub fn build_report_package(
    db: &Database,
    config: &AppConfig,
    batch: Option<&str>,
) -> anyhow::Result<ReportPackage> {
    let batch_id = match batch {
        Some(batch) => batch.to_string(),
        None => db.latest_batch_id()?,
    };
    let status = db.batch_status(Some(&batch_id))?;
    let alerts = db.list_alerts(&batch_id)?;
    let vulns = db.list_vulnerabilities(&batch_id)?;
    let urls = db.list_urls()?;
    let ports = db.list_open_ports()?;

    let report_dir = config.report.output_dir.join(&batch_id);
    fs::create_dir_all(&report_dir)
        .with_context(|| format!("failed to create {}", report_dir.display()))?;

    let tables = build_detail_tables(&alerts, &vulns, &urls, &ports);
    write_text(
        &report_dir.join("summary.md"),
        &render_markdown(
            &status,
            &alerts,
            &vulns,
            &urls,
            &ports,
            config.report.format,
        ),
    )?;
    write_detail_tables(&report_dir, config.report.format, &tables)?;

    let zip_path = config.report.output_dir.join(format!("{batch_id}.zip"));
    zip_dir(&report_dir, &zip_path)?;
    Ok(ReportPackage { zip_path })
}

//! 报告生成与 zip 打包.
//!
//! 公开入口为 [`ReportPackage`] 与 [`build_report_package`].

mod archive;
mod summary;
mod tables;

use std::{fs, path::PathBuf};

use anyhow::Context;

use crate::{config::AppConfig, db::Database};

use self::archive::zip_dir;
use self::summary::render_markdown;
use self::tables::{build_detail_tables, write_detail_tables, write_text};

/// 已生成的报告压缩包元数据.
#[derive(Debug, Clone)]
pub struct ReportPackage {
    /// 生成的 zip 归档路径.
    pub zip_path: PathBuf,
}

/// 为指定批次或最新批次构建报告目录并打包 zip.
///
/// # 参数
/// - `db`: 已打开的数据库句柄, 用于读取批次状态与明细
/// - `config`: 运行时配置, 提供报告输出目录与明细格式
/// - `batch`: 批次 ID; `None` 时使用最新批次
///
/// # 返回
/// 包含生成 zip 路径的 [`ReportPackage`]
///
/// # Errors
/// 当批次不存在, 数据库查询失败, 或报告目录/文件/压缩包写入失败时返回错误.
///
/// # 示例
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

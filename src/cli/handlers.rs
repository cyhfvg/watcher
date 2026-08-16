//! 批次状态, 日志和业务系统命令处理.

use crate::cli::args::{LogCommands, LogLevelArg, SystemCommands};
use crate::cli::entities::print_rows;
use crate::{db::Database, local_time};

/// 打印近期监控批次.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 查询批次列表失败时返回错误.
///
/// # 示例
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

/// 打印一个批次的状态及其告警/漏洞计数.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `batch`: 可选批次 id. `None` 时使用最新批次.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 查询批次状态失败时返回错误.
///
/// # 示例
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

/// 处理日志查询/导出/清理命令.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `command`: 日志子命令.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 查询, 导出或清理日志失败时返回错误.
///
/// # 示例
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

/// 处理业务系统管理命令.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `command`: 业务系统子命令.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 增删改查或导出业务系统失败时返回错误.
///
/// # 示例
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

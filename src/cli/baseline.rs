//! 基线资产命令处理.

use anyhow::Context;

use crate::cli::args::{
    BaselineAddArgs, BaselineAssetType, BaselineCommands, BaselineExportArgs, BaselineImportArgs,
    BaselineImportType, BaselineMutateArgs, BaselineQueryArgs,
};
use crate::cli::common::parse_port;
use crate::cli::entities::{print_rows, read_import_values};
use crate::db::Database;

/// 处理基线资产导入和细粒度基线管理命令.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `command`: 基线子命令.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 添加, 导入, 导出, 查询, 删除或取消基线标记失败时返回错误.
///
/// # 示例
///
/// ```
/// # use watcher::cli::{
/// #     BaselineAddArgs, BaselineAssetType, BaselineCommands, handle_baseline,
/// # };
/// # use watcher::db::Database;
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// handle_baseline(
///     &db,
///     BaselineCommands::Add(BaselineAddArgs {
///         asset_type: BaselineAssetType::Ip,
///         system: "core".into(),
///         ip: None,
///         bind_ip: None,
///         value: "10.0.0.1".into(),
///     }),
/// )?;
/// # Ok::<(), anyhow::Error>(())
/// ```
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

/// 按 `--asset-type` 添加一条基线资产.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `args`: 添加基线资产的参数.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 端口解析失败或写入数据库失败时返回错误.
///
/// # 示例
///
/// ```text
/// add_baseline_asset(db, BaselineAddArgs { asset_type: Ip, ... })
/// ```
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

/// 按 `--asset-type` 导入基线资产.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `args`: 导入基线资产的参数.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 缺少 `--system`, 读文件失败, 端口解析失败或写入数据库失败时返回错误.
///
/// # 示例
///
/// ```text
/// import_baseline_assets(db, BaselineImportArgs { asset_type: Url, ... })
/// ```
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

/// 按 `--asset-type` 导出基线资产.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `args`: 导出基线资产的参数.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 写出 CSV 失败时返回错误.
///
/// # 示例
///
/// ```text
/// export_baseline_assets(db, BaselineExportArgs { asset_type: Url, file })
/// ```
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

/// 按 `--asset-type` 查询基线资产.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `args`: 查询基线资产的参数.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 查询数据库失败时返回错误.
///
/// # 示例
///
/// ```text
/// query_baseline_assets(db, BaselineQueryArgs { asset_type: Ip, ... })
/// ```
fn query_baseline_assets(db: &Database, args: BaselineQueryArgs) -> anyhow::Result<()> {
    let rows = match args.asset_type {
        BaselineAssetType::Url => db.query_baseline_urls(args.keyword.as_deref(), args.limit)?,
        BaselineAssetType::Port => db.query_baseline_ports(args.keyword.as_deref(), args.limit)?,
        BaselineAssetType::Ip => db.query_baseline_ips(args.keyword.as_deref(), args.limit)?,
        BaselineAssetType::Name => db.query_baseline_names(args.keyword.as_deref(), args.limit)?,
    };
    print_rows(rows)
}

/// 按 `--asset-type` 删除一条基线资产行.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `args`: 删除基线资产的参数.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 端口解析失败或删除数据库行失败时返回错误.
///
/// # 示例
///
/// ```text
/// delete_baseline_asset(db, BaselineMutateArgs { asset_type: Url, ... })
/// ```
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

/// 按 `--asset-type` 去掉一条资产的基线标记.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `args`: 取消基线标记的参数.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 端口解析失败或更新数据库失败时返回错误.
///
/// # 示例
///
/// ```text
/// unmark_baseline_asset(db, BaselineMutateArgs { asset_type: Ip, ... })
/// ```
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

/// 返回类型化基线导入所需的业务系统参数.
///
/// # 参数
///
/// - `system`: 可选业务系统名称.
/// - `asset_type`: 当前导入的资产类型, 用于错误提示.
///
/// # 返回
///
/// 存在时返回业务系统名称.
///
/// # Errors
///
/// `system` 为 `None` 时返回错误.
///
/// # 示例
///
/// ```text
/// required_system(Some("core"), BaselineImportType::Url) -> Ok("core")
/// required_system(None, BaselineImportType::Ip) -> Err(...)
/// ```
fn required_system(system: Option<&str>, asset_type: BaselineImportType) -> anyhow::Result<&str> {
    system.with_context(|| format!("--system is required for asset-type={asset_type:?}"))
}

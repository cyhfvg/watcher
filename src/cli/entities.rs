//! 非基线 URL/端口/IP/域名命令处理.

use std::path::PathBuf;

use anyhow::Context;

use crate::cli::args::{EntityAddArgs, EntityCommands, EntityImportArgs};
use crate::cli::common::parse_port;
use crate::db::Database;

/// 处理 URL 资产管理命令.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `command`: URL 实体子命令.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 选项不适用于 URL, 读导入文件失败或写入数据库失败时返回错误.
///
/// # 示例
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

/// 处理端口资产管理命令.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `command`: 端口实体子命令.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 选项不适用于端口, 端口解析失败, 读导入文件失败或写入数据库失败时返回错误.
///
/// # 示例
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

/// 处理 IP 资产管理命令.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `command`: IP 实体子命令.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 选项不适用于 IP, 读导入文件失败或写入数据库失败时返回错误.
///
/// # 示例
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

/// 处理域名资产管理命令.
///
/// # 参数
///
/// - `db`: 已打开并完成迁移的数据库.
/// - `command`: 域名实体子命令.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 选项不适用于域名, 读导入文件失败或写入数据库失败时返回错误.
///
/// # 示例
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

/// 从导入文件读取按行分隔的值.
///
/// # 参数
///
/// - `file`: 按行分隔的资产文件路径.
///
/// # 返回
///
/// 去掉空白后的非空行列表.
///
/// # Errors
///
/// 读取文件失败时返回错误.
///
/// # 示例
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

/// 拒绝不适用于所选资产类型的实体导入选项.
///
/// # 参数
///
/// - `args`: 实体导入参数.
/// - `allow_ip`: 是否允许 `--ip`.
/// - `allow_bind_ip`: 是否允许 `--bind-ip`.
///
/// # 返回
///
/// 选项合法时返回 `Ok(())`.
///
/// # Errors
///
/// 传入当前资产类型不支持的选项时返回错误.
///
/// # 示例
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

/// 拒绝不适用于所选资产类型的添加选项.
///
/// # 参数
///
/// - `args`: 实体添加参数.
/// - `allow_ip`: 是否允许 `--ip`.
/// - `allow_bind_ip`: 是否允许 `--bind-ip`.
///
/// # 返回
///
/// 选项合法时返回 `Ok(())`.
///
/// # Errors
///
/// 传入当前资产类型不支持的选项时返回错误.
///
/// # 示例
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

/// 打印制表符分隔的行.
///
/// # 参数
///
/// - `rows`: 要打印的单元格行.
///
/// # 返回
///
/// 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 当前实现不会返回错误.
///
/// # 示例
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

    /// 构造一条用于选项校验测试的 `EntityAddArgs`.
    ///
    /// # 参数
    ///
    /// - `value`: 资产值.
    /// - `ip`: 可选绑定 IP.
    /// - `bind_ip`: 可选域名绑定 IP.
    ///
    /// # 返回
    ///
    /// 业务系统固定为 `core` 的参数结构.
    ///
    /// # 示例
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

    /// 校验 URL 添加命令拒绝 `--ip`.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 无
    ///
    /// # 示例
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

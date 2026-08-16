//! Path dictionary CLI handlers.

use anyhow::Context;

use crate::{cli::PathCommands, db::Database};

/// 处理 `dict path` 子命令: 导入, 导出, 查询和删除路径字典.
///
/// # 参数
///
/// - `db`: 路径字典所在的数据库.
/// - `command`: 已解析的 `dict path` 子命令.
///
/// # 返回
///
/// 子命令完成并已向标准输出打印结果时返回 `Ok(())`.
///
/// # Errors
///
/// 读文件, 导入, 导出, 查询或删除失败时返回错误.
///
/// # 示例
///
/// ```no_run
/// # use watcher::{cli::PathCommands, db::Database, dict};
/// # fn demo(db: &Database, command: PathCommands) -> anyhow::Result<()> {
/// dict::paths::handle(db, command)?;
/// # Ok(())
/// # }
/// ```
pub fn handle(db: &Database, command: PathCommands) -> anyhow::Result<()> {
    match command {
        PathCommands::Import { file } => {
            let content = std::fs::read_to_string(&file)
                .with_context(|| format!("failed to read {}", file.display()))?;
            let paths = content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            let count = db.import_dict_paths(&paths)?;
            println!("imported {count}");
        }
        PathCommands::Export { file } => {
            db.export_dict_paths(&file)?;
            println!("{}", file.display());
        }
        PathCommands::Query(args) => {
            for row in db.query_dict_paths(args.keyword.as_deref(), args.limit)? {
                println!("{}", row.join("\t"));
            }
        }
        PathCommands::Delete { path } => {
            db.delete_dict_path(&path)?;
            println!("deleted path: {path}");
        }
    }
    Ok(())
}

//! 数据库句柄与导入/待办公开类型.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use rusqlite::Connection;

/// SQLite 数据库句柄. 每次操作打开短生命周期连接, 因此句柄可以廉价克隆.
#[derive(Debug, Clone)]
pub struct Database {
    path: Arc<PathBuf>,
}

/// 结构化基线资产导入中的一行规范化记录.
#[derive(Debug, Clone, Default)]
pub struct BaselineImportRow {
    /// 业务系统名称.
    pub system: String,
    /// 域名, 空值表示本行不含域名.
    pub name: Option<String>,
    /// 域名绑定 IP.
    pub bind_ip: Option<String>,
    /// 真实 IP.
    pub ip: Option<String>,
    /// 端口列表.
    pub ports: Vec<u16>,
    /// URL.
    pub url: Option<String>,
}

/// 批量基线导入完成后的计数.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BaselineImportSummary {
    /// Number of business-system rows processed.
    pub systems: usize,
    /// Number of domain names imported.
    pub names: usize,
    /// Number of IP addresses imported.
    pub ips: usize,
    /// Number of ports imported.
    pub ports: usize,
    /// Number of URLs imported.
    pub urls: usize,
}

/// 供后续批次回放的待办项.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWorkItem {
    /// Pending work primary key.
    pub id: String,
    /// Business system the target belongs to.
    pub system_id: String,
    /// URL or other task-specific target to process.
    pub target: String,
}

impl Database {
    /// 为指定 SQLite 文件打开数据库句柄, 必要时创建父目录.
    ///
    /// # 参数
    /// - `path`: SQLite 文件路径.
    ///
    /// # 返回
    /// 可克隆的 [`Database`] 句柄.
    ///
    /// # Errors
    /// 父目录无法创建时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// let db = Database::open(&dir.path().join("watcher.db"))?;
    /// assert!(db.path().ends_with("watcher.db"));
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        Ok(Self {
            path: Arc::new(path.to_path_buf()),
        })
    }

    /// 返回底层 SQLite 文件路径.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// 打开句柄时传入的路径.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("watcher.db");
    /// # let db = Database::open(&path)?;
    /// assert_eq!(db.path(), path.as_path());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 打开启用外键的 SQLite 连接.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// 新的 rusqlite 连接.
    ///
    /// # Errors
    /// 无法打开数据库文件或设置 `PRAGMA` 失败时返回错误.
    ///
    /// # 示例
    /// ```text
    /// let conn = db.conn()?;
    /// ```
    pub(crate) fn conn(&self) -> anyhow::Result<Connection> {
        let conn = Connection::open(self.path())?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(conn)
    }
}

//! 路径字典导入, 查询, 删除与导出.

use std::path::Path;

use rusqlite::params;

use super::{
    helpers::{collect_rows, new_id, normalize_path, now},
    types::Database,
};

impl Database {
    /// 在单个事务内批量导入字典路径.
    ///
    /// # 参数
    /// - `paths`: 原始路径列表.
    ///
    /// # 返回
    /// 处理条数(含重复输入).
    ///
    /// # Errors
    /// 事务写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.import_dict_paths(&["admin".into()])?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_dict_paths(&self, paths: &[String]) -> anyhow::Result<usize> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let mut count = 0usize;
        {
            let mut insert = tx.prepare(
                "INSERT OR IGNORE INTO dict_paths (id, path, enabled, created_at)
                 VALUES (?1, ?2, 1, ?3)",
            )?;
            for path in paths {
                let normalized = normalize_path(path);
                if normalized.is_empty() {
                    continue;
                }
                insert.execute(params![new_id(), normalized, now()])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// 列出已启用的字典路径.
    ///
    /// # 参数
    /// - `limit`: 最大条数.
    ///
    /// # 返回
    /// 规范化路径列表.
    ///
    /// # Errors
    /// 查询失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.list_dict_paths(10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_dict_paths(&self, limit: usize) -> anyhow::Result<Vec<String>> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare("SELECT path FROM dict_paths WHERE enabled = 1 ORDER BY path LIMIT ?1")?;
        collect_rows(&mut stmt, [limit as i64], |row| Ok(row.get(0)?))
    }

    /// 按可选关键字查询字典路径.
    ///
    /// # 参数
    /// - `keyword`: 可选关键字.
    /// - `limit`: 最大条数.
    ///
    /// # 返回
    /// 单列表格行.
    ///
    /// # Errors
    /// 查询失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.query_dict_paths(Some("admin"), 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_dict_paths(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_simple("dict_paths", "path", keyword, limit)
    }

    /// 删除一条字典路径.
    ///
    /// # 参数
    /// - `path`: 原始或规范化路径.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 删除失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.delete_dict_path("admin")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_dict_path(&self, path: &str) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM dict_paths WHERE path = ?1",
            [normalize_path(path)],
        )?;
        Ok(())
    }

    /// 将字典路径导出为 CSV.
    ///
    /// # 参数
    /// - `file`: 输出 CSV 路径.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 查询或写文件失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.export_dict_paths(&dir.path().join("paths.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_dict_paths(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(file, "SELECT path FROM dict_paths ORDER BY path", &["path"])
    }
}

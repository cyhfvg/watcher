//! 应用日志写入, 查询, 导出与清理.

use std::path::Path;

use anyhow::Context;
use rusqlite::params;

use crate::{local_time, models::LogRow};

use super::{
    helpers::{collect_rows, map_log, new_id, now},
    types::Database,
};

impl Database {
    /// 写入一条应用日志.
    ///
    /// # 参数
    /// - `level`: 日志级别.
    /// - `target`: 日志目标.
    /// - `message`: 消息.
    /// - `fields`: 可选结构化字段.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 插入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.add_log("INFO", "watcher::test", "hello", None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn add_log(
        &self,
        level: &str,
        target: &str,
        message: &str,
        fields: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO logs (id, created_at, level, target, message, fields)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![new_id(), now(), level, target, message, fields],
        )?;
        Ok(())
    }

    /// 按级别与关键字查询应用日志, 最新在前.
    ///
    /// # 参数
    /// - `level`: 可选级别.
    /// - `keyword`: 可选关键字.
    /// - `limit`: 最大条数.
    ///
    /// # 返回
    /// 日志行.
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
    /// let _ = db.query_logs(Some("INFO"), None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_logs(
        &self,
        level: Option<&str>,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<LogRow>> {
        let level = level.map(|value| value.to_ascii_uppercase());
        let pattern = keyword
            .map(|value| format!("%{value}%"))
            .unwrap_or_else(|| "%".to_string());
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, created_at, level, target, message, fields
             FROM logs
             WHERE (?1 IS NULL OR level = ?1)
               AND (message LIKE ?2 OR COALESCE(fields, '') LIKE ?2 OR target LIKE ?2)
             ORDER BY created_at DESC
             LIMIT ?3",
        )?;
        collect_rows(
            &mut stmt,
            params![level.as_deref(), pattern, limit as i64],
            map_log,
        )
    }

    /// 将应用日志导出为 CSV.
    ///
    /// # 参数
    /// - `file`: 输出 CSV 路径.
    /// - `level`: 可选级别.
    /// - `keyword`: 可选关键字.
    /// - `limit`: 最大条数.
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
    /// db.export_logs(&dir.path().join("logs.csv"), None, None, 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_logs(
        &self,
        file: &Path,
        level: Option<&str>,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<()> {
        let mut writer = csv::Writer::from_path(file)
            .with_context(|| format!("failed to create {}", file.display()))?;
        writer.write_record(["created_at", "level", "target", "message", "fields"])?;
        for row in self.query_logs(level, keyword, limit)? {
            writer.write_record([
                local_time::rfc3339_to_local(&row.created_at),
                row.level,
                row.target,
                row.message,
                row.fields.unwrap_or_default(),
            ])?;
        }
        writer.flush()?;
        Ok(())
    }

    /// 清理应用日志并返回删除行数.
    ///
    /// # 参数
    /// - `before`: 仅删除该时间之前的日志; `None` 表示全部.
    ///
    /// # 返回
    /// 删除行数.
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
    /// let _ = db.clear_logs(None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn clear_logs(&self, before: Option<&str>) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        let deleted = match before {
            Some(before) => conn.execute("DELETE FROM logs WHERE created_at < ?1", [before])?,
            None => conn.execute("DELETE FROM logs", [])?,
        };
        Ok(deleted)
    }
}

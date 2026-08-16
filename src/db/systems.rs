//! 业务系统增删改查与导出.

use std::path::Path;

use rusqlite::{OptionalExtension, Row, params};

use super::{
    helpers::{collect_rows, new_id, now},
    types::Database,
};

/// `system query` 使用的汇总 SQL.
pub(crate) const SYSTEM_SUMMARY_SQL: &str = "
    SELECT
        s.name,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id) AS names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id) AS ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id) AS ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id) AS urls,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id AND d.is_baseline = 1) AS baseline_names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id AND i.is_baseline = 1) AS baseline_ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id AND p.is_baseline = 1) AS baseline_ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id AND u.is_baseline = 1) AS baseline_urls,
        s.created_at
    FROM systems s
    WHERE s.name LIKE ?1
    ORDER BY s.name
    LIMIT ?2";

/// `system export` 使用的汇总 SQL.
pub(crate) const SYSTEM_EXPORT_SQL: &str = "
    SELECT
        s.name,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id) AS names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id) AS ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id) AS ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id) AS urls,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id AND d.is_baseline = 1) AS baseline_names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id AND i.is_baseline = 1) AS baseline_ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id AND p.is_baseline = 1) AS baseline_ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id AND u.is_baseline = 1) AS baseline_urls,
        s.created_at
    FROM systems s
    ORDER BY s.name";

/// 将系统汇总行映射为 CLI 表格列.
///
/// # 参数
/// - `row`: 系统汇总查询行.
///
/// # 返回
/// 名称、计数与创建时间组成的字符串列.
///
/// # Errors
/// 列读取失败时返回错误.
///
/// # 示例
/// ```text
/// collect_rows(&mut stmt, params, map_system_summary)
/// ```
pub(crate) fn map_system_summary(row: &Row<'_>) -> anyhow::Result<Vec<String>> {
    Ok(vec![
        row.get::<_, String>(0)?,
        row.get::<_, i64>(1)?.to_string(),
        row.get::<_, i64>(2)?.to_string(),
        row.get::<_, i64>(3)?.to_string(),
        row.get::<_, i64>(4)?.to_string(),
        row.get::<_, i64>(5)?.to_string(),
        row.get::<_, i64>(6)?.to_string(),
        row.get::<_, i64>(7)?.to_string(),
        row.get::<_, i64>(8)?.to_string(),
        row.get::<_, String>(9)?,
    ])
}

impl Database {
    /// 插入业务系统并返回 id; 已存在则直接返回原 id.
    ///
    /// # 参数
    /// - `name`: 业务系统名称.
    ///
    /// # 返回
    /// 系统主键.
    ///
    /// # Errors
    /// 名称为空或数据库写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let id = db.upsert_system("core")?;
    /// assert!(!id.is_empty());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn upsert_system(&self, name: &str) -> anyhow::Result<String> {
        let name = name.trim();
        anyhow::ensure!(!name.is_empty(), "system name must not be empty");
        let conn = self.conn()?;
        if let Some(id) = conn
            .query_row("SELECT id FROM systems WHERE name = ?1", [name], |row| {
                row.get(0)
            })
            .optional()?
        {
            return Ok(id);
        }
        let id = new_id();
        conn.execute(
            "INSERT INTO systems (id, name, created_at) VALUES (?1, ?2, ?3)",
            params![id, name, now()],
        )?;
        Ok(id)
    }

    /// 重命名业务系统并返回受影响行数.
    ///
    /// # 参数
    /// - `old_name`: 原名称.
    /// - `new_name`: 新名称.
    ///
    /// # 返回
    /// 更新行数.
    ///
    /// # Errors
    /// 名称为空或 `UPDATE` 失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// # db.upsert_system("core")?;
    /// assert_eq!(db.rename_system("core", "core-renamed")?, 1);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn rename_system(&self, old_name: &str, new_name: &str) -> anyhow::Result<usize> {
        let old_name = old_name.trim();
        let new_name = new_name.trim();
        anyhow::ensure!(!old_name.is_empty(), "old system name must not be empty");
        anyhow::ensure!(!new_name.is_empty(), "new system name must not be empty");
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE systems SET name = ?1 WHERE name = ?2",
            params![new_name, old_name],
        )?;
        Ok(changed)
    }

    /// 按名称删除业务系统. 子资产由外键级联删除.
    ///
    /// # 参数
    /// - `name`: 业务系统名称.
    ///
    /// # 返回
    /// 删除行数.
    ///
    /// # Errors
    /// 名称为空或 `DELETE` 失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// # db.upsert_system("core")?;
    /// assert_eq!(db.delete_system("core")?, 1);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_system(&self, name: &str) -> anyhow::Result<usize> {
        let name = name.trim();
        anyhow::ensure!(!name.is_empty(), "system name must not be empty");
        let conn = self.conn()?;
        Ok(conn.execute("DELETE FROM systems WHERE name = ?1", [name])?)
    }

    /// 按关键字查询业务系统及资产计数.
    ///
    /// # 参数
    /// - `keyword`: 可选名称关键字.
    /// - `limit`: 最大返回行数.
    ///
    /// # 返回
    /// 表格行, 每行含名称、计数与创建时间.
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
    /// # db.upsert_system("core")?;
    /// let rows = db.query_systems(Some("core"), 10)?;
    /// assert_eq!(rows[0][0], "core");
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn query_systems(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let conn = self.conn()?;
        let mut stmt = conn.prepare(SYSTEM_SUMMARY_SQL)?;
        collect_rows(
            &mut stmt,
            params![pattern, limit as i64],
            map_system_summary,
        )
    }

    /// 将业务系统及资产计数导出为 CSV.
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
    /// db.export_systems(&dir.path().join("systems.csv"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn export_systems(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            SYSTEM_EXPORT_SQL,
            &[
                "system",
                "names",
                "ips",
                "ports",
                "urls",
                "baseline_names",
                "baseline_ips",
                "baseline_ports",
                "baseline_urls",
                "created_at",
            ],
        )
    }
}

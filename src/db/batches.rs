//! 批次生命周期, 阶段与待办.

use std::path::Path;

use chrono::Utc;
use rusqlite::params;

use crate::models::BatchContext;

use super::{
    helpers::{collect_rows, new_id, now},
    types::{Database, PendingWorkItem},
};

impl Database {
    /// 创建新的监测批次.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// 新批次上下文.
    ///
    /// # Errors
    /// 中断旧批次或插入新批次失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?; assert_eq!(batch.id.is_empty(), false);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn create_batch(&self) -> anyhow::Result<BatchContext> {
        self.interrupt_running_batches("previous watcher process exited before finalizing batch")?;
        let id = new_id();
        let started_at = Utc::now();
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO batches (id, status, started_at) VALUES (?1, 'running', ?2)",
            params![id, started_at.to_rfc3339()],
        )?;
        Ok(BatchContext { id, started_at })
    }

    /// 将残留的运行中批次标为中断.
    ///
    /// # 参数
    /// - `reason`: 中断原因.
    ///
    /// # 返回
    /// 被中断的批次数.
    ///
    /// # Errors
    /// 更新失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.interrupt_running_batches("process exited")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn interrupt_running_batches(&self, reason: &str) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE batch_stages
             SET status = 'interrupted', ended_at = ?1, detail = ?2
             WHERE status = 'running'
               AND batch_id IN (SELECT id FROM batches WHERE status = 'running')",
            params![now(), reason],
        )?;
        Ok(conn.execute(
            "UPDATE batches
             SET status = 'interrupted', ended_at = ?1, error = ?2, stop_requested = 1
             WHERE status = 'running'",
            params![now(), reason],
        )?)
    }

    /// 以最终状态结束一个批次.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    /// - `status`: 最终状态.
    /// - `error`: 可选错误信息.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 更新失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?; db.finish_batch(&batch.id, "completed", None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn finish_batch(
        &self,
        batch_id: &str,
        status: &str,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE batches SET status = ?1, ended_at = ?2, error = ?3 WHERE id = ?4",
            params![status, now(), error, batch_id],
        )?;
        Ok(())
    }

    /// 将监测流水线的一个阶段标为运行中.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    /// - `stage`: 阶段名.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?; db.start_batch_stage(&batch.id, "dns")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn start_batch_stage(&self, batch_id: &str, stage: &str) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO batch_stages (batch_id, stage, status, started_at, ended_at, detail)
             VALUES (?1, ?2, 'running', ?3, NULL, NULL)
             ON CONFLICT(batch_id, stage) DO UPDATE SET
                status = 'running', started_at = excluded.started_at, ended_at = NULL, detail = NULL",
            params![batch_id, stage, now()],
        )?;
        Ok(())
    }

    /// 完成一个监测流水线阶段, 可附带诊断信息.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    /// - `stage`: 阶段名.
    /// - `status`: 阶段状态.
    /// - `detail`: 可选诊断.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 更新失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?; db.start_batch_stage(&batch.id, "dns")?; db.finish_batch_stage(&batch.id, "dns", "completed", None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn finish_batch_stage(
        &self,
        batch_id: &str,
        stage: &str,
        status: &str,
        detail: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE batch_stages
             SET status = ?1, ended_at = ?2, detail = ?3
             WHERE batch_id = ?4 AND stage = ?5",
            params![status, now(), detail, batch_id, stage],
        )?;
        Ok(())
    }

    /// 保存批次报告 zip 路径.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    /// - `path`: 报告文件路径.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 更新失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?; db.set_batch_report(&batch.id, dir.path())?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_batch_report(&self, batch_id: &str, path: &Path) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE batches SET report_zip = ?1 WHERE id = ?2",
            params![path.display().to_string(), batch_id],
        )?;
        Ok(())
    }

    /// 请求运行中批次在下一检查点停止.
    ///
    /// # 参数
    /// - `batch`: 指定批次; `None` 表示全部运行中批次.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 更新失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?; db.request_batch_stop(Some(&batch.id))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn request_batch_stop(&self, batch: Option<&str>) -> anyhow::Result<()> {
        let conn = self.conn()?;
        if let Some(batch) = batch {
            conn.execute(
                "UPDATE batches SET stop_requested = 1 WHERE id = ?1",
                [batch],
            )?;
        } else {
            conn.execute(
                "UPDATE batches SET stop_requested = 1 WHERE status = 'running'",
                [],
            )?;
        }
        Ok(())
    }

    /// 判断批次是否已被请求停止.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    ///
    /// # 返回
    /// 已请求停止则为 `true`.
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
    /// let batch = db.create_batch()?; assert!(!db.should_stop_batch(&batch.id)?);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn should_stop_batch(&self, batch_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn()?;
        let value: i64 = conn.query_row(
            "SELECT stop_requested FROM batches WHERE id = ?1",
            [batch_id],
            |row| row.get(0),
        )?;
        Ok(value == 1)
    }

    /// 登记待办, 供后续批次优先处理.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    /// - `system_id`: 业务系统 id.
    /// - `task_kind`: 任务类型.
    /// - `target`: 任务目标.
    /// - `priority`: 优先级, 越小越先.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?; db.add_pending_work(&batch.id, "sys", "web_enum", "https://example.com", 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn add_pending_work(
        &self,
        batch_id: &str,
        system_id: &str,
        task_kind: &str,
        target: &str,
        priority: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO pending_work (id, batch_id, system_id, task_kind, target, status, priority, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7, ?7)
             ON CONFLICT(task_kind, target) DO UPDATE SET batch_id = excluded.batch_id, system_id = excluded.system_id, status = 'pending', priority = MIN(pending_work.priority, excluded.priority), updated_at = excluded.updated_at",
            params![new_id(), batch_id, system_id, task_kind, target, priority, now()],
        )?;
        Ok(())
    }

    /// 领取指定任务类型的待办.
    ///
    /// # 参数
    /// - `task_kind`: 任务类型.
    /// - `limit`: 最多领取条数.
    ///
    /// # 返回
    /// 待办列表.
    ///
    /// # Errors
    /// 查询或状态更新失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.take_pending_work("web_enum", 10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn take_pending_work(
        &self,
        task_kind: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<PendingWorkItem>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, system_id, target FROM pending_work WHERE task_kind = ?1 AND status = 'pending' ORDER BY priority, created_at LIMIT ?2",
        )?;
        let rows = collect_rows(&mut stmt, params![task_kind, limit as i64], |row| {
            Ok(PendingWorkItem {
                id: row.get(0)?,
                system_id: row.get(1)?,
                target: row.get(2)?,
            })
        })?;
        for item in &rows {
            conn.execute(
                "UPDATE pending_work SET status = 'running', updated_at = ?1 WHERE id = ?2",
                params![now(), item.id],
            )?;
        }
        Ok(rows)
    }

    /// 将待办标为完成.
    ///
    /// # 参数
    /// - `id`: 待办主键.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 更新失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// db.finish_pending_work("missing-id")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn finish_pending_work(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE pending_work SET status = 'done', updated_at = ?1 WHERE id = ?2",
            params![now(), id],
        )?;
        Ok(())
    }
}

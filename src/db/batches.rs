//! Batch lifecycle, stages, and pending work.

use std::path::Path;

use chrono::Utc;
use rusqlite::{TransactionBehavior, params};

use crate::models::BatchContext;

use super::{
    helpers::{collect_rows, new_id, now},
    types::{Database, PendingWorkItem},
};

impl Database {
    /// Create a new monitoring batch.
    ///
    /// # Arguments
    /// none
    ///
    /// # Returns
    /// New batch context.
    ///
    /// # Errors
    /// Returns an error if interrupting old batches or inserting the new batch fails.
    ///
    /// # Examples
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

    /// Mark leftover running batches as interrupted.
    ///
    /// Claimed `pending_work` rows are returned to `pending` before the batch status changes.
    ///
    /// # Arguments
    /// - `reason`: Interruption reason.
    ///
    /// # Returns
    /// Number of interrupted batches.
    ///
    /// # Errors
    /// Returns an error if the pending requeue or status update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.interrupt_running_batches("process exited")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn interrupt_running_batches(&self, reason: &str) -> anyhow::Result<usize> {
        self.requeue_running_pending_work()?;
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

    /// Move claimed pending rows back to `pending`.
    ///
    /// # Arguments
    /// none
    ///
    /// # Returns
    /// Number of rows moved from `running` to `pending`.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.requeue_running_pending_work()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn requeue_running_pending_work(&self) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "UPDATE pending_work SET status = 'pending', updated_at = ?1 WHERE status = 'running'",
            [now()],
        )?)
    }

    /// Requeue claimed work and mark one batch interrupted.
    ///
    /// # Arguments
    /// - `batch_id`: Batch that is stopping.
    /// - `reason`: Operator-visible interruption reason.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the pending update or batch update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?;
    /// db.finalize_stopped_batch(&batch.id, "stop requested")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn finalize_stopped_batch(&self, batch_id: &str, reason: &str) -> anyhow::Result<()> {
        self.requeue_running_pending_work()?;
        let conn = self.conn()?;
        conn.execute(
            "UPDATE batch_stages
             SET status = 'interrupted', ended_at = ?1, detail = ?2
             WHERE batch_id = ?3 AND status = 'running'",
            params![now(), reason, batch_id],
        )?;
        self.finish_batch(batch_id, "interrupted", Some(reason))?;
        Ok(())
    }

    /// Return a claimed row to `pending`, or mark it done after too many attempts.
    ///
    /// # Arguments
    /// - `id`: Pending-work primary key.
    ///
    /// # Returns
    /// `true` when the row was abandoned (`done`) because attempts reached 3.
    ///
    /// # Errors
    /// Returns an error if the row does not exist or the update fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?;
    /// db.add_pending_work(&batch.id, "sys", "web_enum", "https://example.com/a", 10)?;
    /// let item = db.take_pending_work("web_enum", 1)?.remove(0);
    /// assert!(!db.retry_pending_work(&item.id)?);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn retry_pending_work(&self, id: &str) -> anyhow::Result<bool> {
        const MAX_ATTEMPTS: i64 = 3;
        let conn = self.conn()?;
        let status: String = conn.query_row(
            "UPDATE pending_work
             SET attempts = attempts + 1,
                 status = CASE WHEN attempts + 1 >= ?1 THEN 'done' ELSE 'pending' END,
                 updated_at = ?2
             WHERE id = ?3
             RETURNING status",
            params![MAX_ATTEMPTS, now(), id],
            |row| row.get(0),
        )?;
        Ok(status == "done")
    }

    /// Finish a batch with a terminal status.
    ///
    /// # Arguments
    /// - `batch_id`: Batch id.
    /// - `status`: Terminal status.
    /// - `error`: Optional error message.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
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

    /// Mark one monitoring-pipeline stage as running.
    ///
    /// # Arguments
    /// - `batch_id`: Batch id.
    /// - `stage`: Stage name.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the write fails.
    ///
    /// # Examples
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

    /// Finish a monitoring-pipeline stage, optionally with diagnostics.
    ///
    /// # Arguments
    /// - `batch_id`: Batch id.
    /// - `stage`: Stage name.
    /// - `status`: Stage status.
    /// - `detail`: Optional diagnostics.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
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

    /// Store the batch report zip path.
    ///
    /// # Arguments
    /// - `batch_id`: Batch id.
    /// - `path`: Report file path.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
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

    /// Ask running batches to stop at the next checkpoint.
    ///
    /// # Arguments
    /// - `batch`: Specific batch; `None` means every running batch.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
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

    /// Return whether a batch has been asked to stop.
    ///
    /// # Arguments
    /// - `batch_id`: Batch id.
    ///
    /// # Returns
    /// `true` if a stop has been requested.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    ///
    /// # Examples
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

    /// Register pending work so later batches can process it first.
    ///
    /// # Arguments
    /// - `batch_id`: Batch id.
    /// - `system_id`: Business-system id.
    /// - `task_kind`: Task kind.
    /// - `target`: Task target.
    /// - `priority`: Priority; lower values run first.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the write fails.
    ///
    /// # Examples
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
        self.with_immediate_tx(|tx| {
            tx.execute(
                "INSERT INTO pending_work (id, batch_id, system_id, task_kind, target, status, priority, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7, ?7)
                 ON CONFLICT(task_kind, target) DO UPDATE SET batch_id = excluded.batch_id, system_id = excluded.system_id, status = 'pending', priority = MIN(pending_work.priority, excluded.priority), updated_at = excluded.updated_at",
                params![new_id(), batch_id, system_id, task_kind, target, priority, now()],
            )?;
            Ok(())
        })
    }

    /// Claim pending work of the given task kind.
    ///
    /// # Arguments
    /// - `task_kind`: Task kind.
    /// - `limit`: Maximum number of items to claim.
    ///
    /// # Returns
    /// Pending-work list.
    ///
    /// # Errors
    /// Returns an error if the query or status update fails.
    ///
    /// # Examples
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
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows = {
            let mut stmt = tx.prepare(
                "UPDATE pending_work
                 SET status = 'running', updated_at = ?1
                 WHERE id IN (
                     SELECT id FROM pending_work
                     WHERE task_kind = ?2 AND status = 'pending'
                     ORDER BY priority, created_at
                     LIMIT ?3
                 )
                 RETURNING id, system_id, target",
            )?;
            collect_rows(&mut stmt, params![now(), task_kind, limit as i64], |row| {
                Ok(PendingWorkItem {
                    id: row.get(0)?,
                    system_id: row.get(1)?,
                    target: row.get(2)?,
                })
            })?
        };
        tx.commit()?;
        Ok(rows)
    }

    /// Mark pending work as done.
    ///
    /// # Arguments
    /// - `id`: Pending-work primary key.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the update fails.
    ///
    /// # Examples
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

    /// Insert many pending-work rows in one transaction.
    ///
    /// # Arguments
    /// - `batch_id`: Owning batch.
    /// - `task_kind`: Task kind, such as `web_enum`.
    /// - `items`: `(system_id, target, priority)` rows. Empty input is a no-op.
    ///
    /// # Returns
    /// none
    ///
    /// # Errors
    /// Returns an error if the transaction cannot be started or a row cannot be written.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?;
    /// db.add_pending_work_batch(&batch.id, "web_enum", &[("sys", "https://example.com/a", 10)])?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn add_pending_work_batch(
        &self,
        batch_id: &str,
        task_kind: &str,
        items: &[(&str, &str, i64)],
    ) -> anyhow::Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let timestamp = now();
        {
            let mut stmt = tx.prepare(
                "INSERT INTO pending_work (id, batch_id, system_id, task_kind, target, status, priority, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7, ?7)
                 ON CONFLICT(task_kind, target) DO UPDATE SET
                    batch_id = excluded.batch_id,
                    system_id = excluded.system_id,
                    status = 'pending',
                    priority = MIN(pending_work.priority, excluded.priority),
                    updated_at = excluded.updated_at",
            )?;
            for (system_id, target, priority) in items {
                stmt.execute(params![
                    new_id(),
                    batch_id,
                    system_id,
                    task_kind,
                    target,
                    priority,
                    timestamp
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

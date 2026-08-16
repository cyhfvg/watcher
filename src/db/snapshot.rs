//! Terminal dashboard snapshot aggregation.

use rusqlite::OptionalExtension;

use crate::models::{
    DashboardAlert, DashboardAssetCounts, DashboardBatch, DashboardQueueCounts,
    DashboardSeverityCounts, DashboardSnapshot, DashboardStage,
};

use super::{
    helpers::{collect_rows, map_batch, now},
    types::Database,
};

impl Database {
    /// Return aggregated state for the terminal dashboard.
    ///
    /// # Arguments
    /// none
    ///
    /// # Returns
    /// Dashboard snapshot.
    ///
    /// # Errors
    /// Returns an error if an aggregate query fails.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.dashboard_snapshot()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn dashboard_snapshot(&self) -> anyhow::Result<DashboardSnapshot> {
        let conn = self.conn()?;
        let assets = conn.query_row(
            "SELECT
                (SELECT COUNT(*) FROM systems),
                (SELECT COUNT(*) FROM domains),
                (SELECT COUNT(*) FROM ip_addresses),
                (SELECT COUNT(*) FROM ports),
                (SELECT COUNT(*) FROM ports WHERE state = 'open'),
                (SELECT COUNT(*) FROM ports WHERE state = 'open' AND is_web = 1),
                (SELECT COUNT(*) FROM urls),
                (SELECT COUNT(*) FROM domains WHERE is_baseline = 1)
                  + (SELECT COUNT(*) FROM ip_addresses WHERE is_baseline = 1)
                  + (SELECT COUNT(*) FROM ports WHERE is_baseline = 1)
                  + (SELECT COUNT(*) FROM urls WHERE is_baseline = 1),
                (SELECT COUNT(*) FROM dict_paths WHERE enabled = 1)",
            [],
            |row| {
                Ok(DashboardAssetCounts {
                    systems: row.get(0)?,
                    domains: row.get(1)?,
                    ips: row.get(2)?,
                    ports: row.get(3)?,
                    open_ports: row.get(4)?,
                    web_services: row.get(5)?,
                    urls: row.get(6)?,
                    baseline_assets: row.get(7)?,
                    dictionary_paths: row.get(8)?,
                })
            },
        )?;

        let latest = conn
            .query_row(
                "SELECT id, status, started_at, ended_at, report_zip
                 FROM batches ORDER BY started_at DESC LIMIT 1",
                [],
                map_batch,
            )
            .optional()?;
        let mut stages = Vec::new();
        let mut alert_severity = DashboardSeverityCounts::default();
        let latest_batch = if let Some(batch) = latest {
            let alerts: i64 = conn.query_row(
                "SELECT COUNT(*) FROM alerts WHERE batch_id = ?1",
                [&batch.id],
                |row| row.get(0),
            )?;
            let vulnerabilities: i64 = conn.query_row(
                "SELECT COUNT(*) FROM vulnerabilities WHERE batch_id = ?1",
                [&batch.id],
                |row| row.get(0),
            )?;
            let mut stage_stmt = conn.prepare(
                "SELECT stage, status, started_at, ended_at, detail
                 FROM batch_stages WHERE batch_id = ?1 ORDER BY started_at, stage",
            )?;
            stages = collect_rows(&mut stage_stmt, [&batch.id], |row| {
                Ok(DashboardStage {
                    stage: row.get(0)?,
                    status: row.get(1)?,
                    started_at: row.get(2)?,
                    ended_at: row.get(3)?,
                    detail: row.get(4)?,
                })
            })?;
            let mut severity_stmt = conn.prepare(
                "SELECT severity, COUNT(*) FROM alerts WHERE batch_id = ?1 GROUP BY severity",
            )?;
            let severity_rows: Vec<(String, i64)> =
                collect_rows(&mut severity_stmt, [&batch.id], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?;
            for (severity, count) in severity_rows {
                match severity.to_ascii_lowercase().as_str() {
                    "critical" => alert_severity.critical += count,
                    "high" => alert_severity.high += count,
                    "medium" => alert_severity.medium += count,
                    "low" => alert_severity.low += count,
                    _ => alert_severity.other += count,
                }
            }
            Some(DashboardBatch {
                id: batch.id,
                status: batch.status,
                started_at: batch.started_at,
                ended_at: batch.ended_at,
                alerts,
                vulnerabilities,
            })
        } else {
            None
        };

        let queue = conn.query_row(
            "SELECT
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END)
             FROM pending_work",
            [],
            |row| {
                Ok(DashboardQueueCounts {
                    pending: row.get::<_, Option<i64>>(0)?.unwrap_or_default(),
                    running: row.get::<_, Option<i64>>(1)?.unwrap_or_default(),
                    done: row.get::<_, Option<i64>>(2)?.unwrap_or_default(),
                })
            },
        )?;
        let mut alert_stmt = conn.prepare(
            "SELECT a.severity, a.kind, a.subject, s.name, a.created_at
             FROM alerts a LEFT JOIN systems s ON s.id = a.system_id
             ORDER BY a.created_at DESC LIMIT 8",
        )?;
        let recent_alerts = collect_rows(&mut alert_stmt, [], |row| {
            Ok(DashboardAlert {
                severity: row.get(0)?,
                kind: row.get(1)?,
                subject: row.get(2)?,
                system_name: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;

        Ok(DashboardSnapshot {
            generated_at: now(),
            assets,
            latest_batch,
            stages,
            queue,
            alert_severity,
            recent_alerts,
        })
    }
}

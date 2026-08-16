//! 资产, 批次, 告警与漏洞列表查询.

use chrono::Utc;

use crate::models::{
    Alert, BatchRow, BatchStatus, DomainAsset, IpAsset, PortAsset, UrlAsset, Vulnerability,
};

use super::{
    helpers::{collect_rows, map_batch, map_ip, map_port, map_url},
    types::Database,
};

impl Database {
    /// 列出全部域名资产.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// 域名资产列表.
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
    /// let _ = db.list_domains()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_domains(&self) -> anyhow::Result<Vec<DomainAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT d.id, d.system_id, s.name, d.name, d.bind_ip, d.is_baseline
             FROM domains d JOIN systems s ON s.id = d.system_id
             ORDER BY s.name, d.name",
        )?;
        collect_rows(&mut stmt, [], |row| {
            Ok(DomainAsset {
                id: row.get(0)?,
                system_id: row.get(1)?,
                system_name: row.get(2)?,
                name: row.get(3)?,
                bind_ip: row.get(4)?,
                is_baseline: row.get::<_, i64>(5)? == 1,
            })
        })
    }

    /// 列出指定业务系统的域名资产.
    ///
    /// # 参数
    /// - `system_id`: 业务系统 id.
    ///
    /// # 返回
    /// 域名资产列表.
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
    /// let sid = db.upsert_system("core")?; let _ = db.list_domains_for_system(&sid)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_domains_for_system(&self, system_id: &str) -> anyhow::Result<Vec<DomainAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT d.id, d.system_id, s.name, d.name, d.bind_ip, d.is_baseline
             FROM domains d JOIN systems s ON s.id = d.system_id
             WHERE d.system_id = ?1
             ORDER BY d.name",
        )?;
        collect_rows(&mut stmt, [system_id], |row| {
            Ok(DomainAsset {
                id: row.get(0)?,
                system_id: row.get(1)?,
                system_name: row.get(2)?,
                name: row.get(3)?,
                bind_ip: row.get(4)?,
                is_baseline: row.get::<_, i64>(5)? == 1,
            })
        })
    }

    /// 列出用于端口扫描的导入/手工真实 IP.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// IP 资产列表.
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
    /// let _ = db.list_real_ips()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_real_ips(&self) -> anyhow::Result<Vec<IpAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT i.id, i.system_id, s.name, i.ip, i.source, i.is_baseline
             FROM ip_addresses i JOIN systems s ON s.id = i.system_id
             WHERE i.source != 'resolved'
             ORDER BY s.name, i.ip",
        )?;
        collect_rows(&mut stmt, [], |row| Ok(map_ip(row)?))
    }

    /// 列出开放端口.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// 端口资产列表.
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
    /// let _ = db.list_open_ports()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_open_ports(&self) -> anyhow::Result<Vec<PortAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.system_id, s.name, p.ip_id, i.ip, p.port, p.state, p.service, p.fingerprint, p.is_web, p.scheme, p.is_baseline
             FROM ports p
             JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE p.state = 'open'
             ORDER BY s.name, i.ip, p.port",
        )?;
        collect_rows(&mut stmt, [], |row| Ok(map_port(row)?))
    }

    /// 列出指纹识别出的 Web 服务.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// 端口资产列表.
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
    /// let _ = db.list_web_services()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_web_services(&self) -> anyhow::Result<Vec<PortAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.system_id, s.name, p.ip_id, i.ip, p.port, p.state, p.service, p.fingerprint, p.is_web, p.scheme, p.is_baseline
             FROM ports p
             JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE p.state = 'open' AND p.is_web = 1
             ORDER BY s.name, i.ip, p.port",
        )?;
        collect_rows(&mut stmt, [], |row| Ok(map_port(row)?))
    }

    /// 列出 URL 资产.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// URL 资产列表.
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
    /// let _ = db.list_urls()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_urls(&self) -> anyhow::Result<Vec<UrlAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT u.id, u.system_id, s.name, u.url, u.source, u.status_code, u.value_score, u.is_baseline
             FROM urls u JOIN systems s ON s.id = u.system_id
             ORDER BY s.name, u.url",
        )?;
        collect_rows(&mut stmt, [], |row| Ok(map_url(row)?))
    }

    /// 列出最近批次.
    ///
    /// # 参数
    /// - `limit`: 最大条数.
    ///
    /// # 返回
    /// 批次列表.
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
    /// let _ = db.list_batches(10)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_batches(&self, limit: usize) -> anyhow::Result<Vec<BatchRow>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, status, started_at, ended_at, report_zip FROM batches ORDER BY started_at DESC LIMIT ?1",
        )?;
        collect_rows(&mut stmt, [limit as i64], |row| {
            Ok(BatchRow {
                id: row.get(0)?,
                status: row.get(1)?,
                started_at: row.get(2)?,
                ended_at: row.get(3)?,
                report_zip: row.get(4)?,
            })
        })
    }

    /// 返回指定或最新批次的状态.
    ///
    /// # 参数
    /// - `batch`: 批次 id; `None` 表示最新批次.
    ///
    /// # 返回
    /// 批次状态.
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
    /// let batch = db.create_batch()?; let _ = db.batch_status(Some(&batch.id))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn batch_status(&self, batch: Option<&str>) -> anyhow::Result<BatchStatus> {
        let conn = self.conn()?;
        let row: BatchRow = match batch {
            Some(batch) => conn.query_row(
                "SELECT id, status, started_at, ended_at, report_zip FROM batches WHERE id = ?1",
                [batch],
                map_batch,
            )?,
            None => conn.query_row(
                "SELECT id, status, started_at, ended_at, report_zip FROM batches ORDER BY started_at DESC LIMIT 1",
                [],
                map_batch,
            )?,
        };
        let alerts: i64 = conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE batch_id = ?1",
            [&row.id],
            |r| r.get(0),
        )?;
        let vulnerabilities: i64 = conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE batch_id = ?1",
            [&row.id],
            |r| r.get(0),
        )?;
        Ok(BatchStatus {
            batch_id: row.id,
            status: row.status,
            started_at: row.started_at,
            ended_at: row.ended_at,
            alerts,
            vulnerabilities,
        })
    }

    /// 列出一个批次的告警.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    ///
    /// # 返回
    /// 告警列表.
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
    /// let batch = db.create_batch()?; let _ = db.list_alerts(&batch.id)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_alerts(&self, batch_id: &str) -> anyhow::Result<Vec<Alert>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT a.id, a.batch_id, a.system_id, s.name, a.kind, a.severity, a.subject, a.old_value, a.new_value, a.details, a.created_at
             FROM alerts a
             LEFT JOIN systems s ON s.id = a.system_id
             WHERE a.batch_id = ?1
             ORDER BY a.created_at",
        )?;
        collect_rows(&mut stmt, [batch_id], |row| {
            let created_at: String = row.get(10)?;
            Ok(Alert {
                id: row.get(0)?,
                batch_id: row.get(1)?,
                system_id: row.get(2)?,
                system_name: row.get(3)?,
                kind: row.get(4)?,
                severity: row.get(5)?,
                subject: row.get(6)?,
                old_value: row.get(7)?,
                new_value: row.get(8)?,
                details: row.get(9)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            })
        })
    }

    /// 列出一个批次的漏洞.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    ///
    /// # 返回
    /// 漏洞列表.
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
    /// let batch = db.create_batch()?; let _ = db.list_vulnerabilities(&batch.id)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_vulnerabilities(&self, batch_id: &str) -> anyhow::Result<Vec<Vulnerability>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT v.id, v.batch_id, v.system_id, s.name, v.url, v.poc, v.severity, v.evidence, v.created_at
             FROM vulnerabilities v
             JOIN systems s ON s.id = v.system_id
             WHERE v.batch_id = ?1
             ORDER BY v.created_at",
        )?;
        collect_rows(&mut stmt, [batch_id], |row| {
            let created_at: String = row.get(8)?;
            Ok(Vulnerability {
                id: row.get(0)?,
                batch_id: row.get(1)?,
                system_id: row.get(2)?,
                system_name: row.get(3)?,
                url: row.get(4)?,
                poc: row.get(5)?,
                severity: row.get(6)?,
                evidence: row.get(7)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            })
        })
    }

    /// 返回最新批次 id.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// 批次 id.
    ///
    /// # Errors
    /// 没有批次或查询失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.create_batch()?; let _ = db.latest_batch_id()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn latest_batch_id(&self) -> anyhow::Result<String> {
        let conn = self.conn()?;
        Ok(conn.query_row(
            "SELECT id FROM batches ORDER BY started_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )?)
    }
}

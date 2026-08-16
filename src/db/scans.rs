//! IP 扫描记录, 指纹更新与告警/漏洞写入.

use std::collections::HashSet;

use rusqlite::params;

use crate::models::{DomainAsset, ScanSummary};

use super::{
    helpers::{
        collect_rows, compact_port_list, insert_alert_in_tx, new_id, now, port_change_details,
    },
    types::Database,
};

impl Database {
    /// 在单个事务内记录一次 IP 扫描结果.
    ///
    /// 关闭的未知端口不会落库. 非基线端口关闭后会在记录变更后删除. 告警和扫描摘要按 IP 聚合写入, 而不是按端口各写一次.
    ///
    /// 当 `scan_complete` 为 false 时, 只 upsert 新发现的开放端口. 未被探测到的已有开放端口保持不变, 避免中断的全端口扫描把它们标成关闭.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    /// - `system_id`: 业务系统 id.
    /// - `ip_id`: IP 主键.
    /// - `ip`: IP 文本.
    /// - `open_ports`: 本次发现的开放端口.
    /// - `probed_ports`: 探测端口数.
    /// - `scan_complete`: 扫描是否完整.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 事务、告警或摘要写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let sid = db.upsert_system("core")?; let ip = db.upsert_ip(&sid, "10.0.0.1", "imported")?; let batch = db.create_batch()?; db.record_ip_scan(&batch.id, &sid, &ip, "10.0.0.1", &[80], 1, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn record_ip_scan(
        &self,
        batch_id: &str,
        system_id: &str,
        ip_id: &str,
        ip: &str,
        open_ports: &[u16],
        probed_ports: u32,
        scan_complete: bool,
    ) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let scanned_at = now();
        let open_set: HashSet<u16> = open_ports.iter().copied().collect();

        let existing: Vec<(String, u16, String, bool)> = {
            let mut stmt = tx.prepare(
                "SELECT id, port, state, is_baseline
                 FROM ports
                 WHERE system_id = ?1 AND ip_id = ?2",
            )?;
            collect_rows(&mut stmt, params![system_id, ip_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get::<_, i64>(1)? as u16,
                    row.get(2)?,
                    row.get::<_, i64>(3)? == 1,
                ))
            })?
        };
        let existing_ports: HashSet<u16> = existing.iter().map(|row| row.1).collect();

        let mut opened = Vec::new();
        let mut closed = Vec::new();
        let mut delete_ids = Vec::new();

        {
            let mut update_state =
                tx.prepare("UPDATE ports SET state = ?1, last_seen = ?2 WHERE id = ?3")?;
            for (port_id, port, old_state, is_baseline) in &existing {
                let is_open = open_set.contains(port);
                if !is_open && !scan_complete {
                    continue;
                }
                let new_state = if is_open { "open" } else { "closed" };
                if old_state != new_state {
                    if is_open && (*old_state != "unknown" || is_open) {
                        opened.push(*port);
                    } else if old_state == "open" {
                        closed.push(*port);
                    }
                }
                update_state.execute(params![new_state, scanned_at, port_id])?;
                if !is_open && !*is_baseline {
                    delete_ids.push(port_id.clone());
                }
            }
        }

        {
            let mut insert_port = tx.prepare(
                "INSERT INTO ports (id, system_id, ip_id, port, source, state, is_baseline, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, 'scan', 'open', 0, ?5, ?5)",
            )?;
            for port in &open_set {
                if existing_ports.contains(port) {
                    continue;
                }
                insert_port.execute(params![new_id(), system_id, ip_id, *port, scanned_at])?;
                opened.push(*port);
            }
        }

        if !delete_ids.is_empty() {
            let mut delete_port = tx.prepare("DELETE FROM ports WHERE id = ?1")?;
            for port_id in &delete_ids {
                delete_port.execute(params![port_id])?;
            }
        }

        opened.sort_unstable();
        opened.dedup();
        closed.sort_unstable();
        closed.dedup();

        if !opened.is_empty() {
            insert_alert_in_tx(
                &tx,
                batch_id,
                Some(system_id),
                "port_change",
                "high",
                ip,
                Some("closed/unknown"),
                Some("open"),
                Some(&port_change_details(&opened)),
            )?;
        }
        if !closed.is_empty() {
            insert_alert_in_tx(
                &tx,
                batch_id,
                Some(system_id),
                "port_change",
                "medium",
                ip,
                Some("open"),
                Some("closed"),
                Some(&port_change_details(&closed)),
            )?;
        }

        tx.execute(
            "INSERT INTO scan_summaries (
                id, batch_id, system_id, ip_id, ip, probed_ports, open_count,
                opened_ports, closed_ports, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(batch_id, ip_id, ip) DO UPDATE SET
                probed_ports = excluded.probed_ports,
                open_count = excluded.open_count,
                opened_ports = excluded.opened_ports,
                closed_ports = excluded.closed_ports,
                created_at = excluded.created_at",
            params![
                new_id(),
                batch_id,
                system_id,
                ip_id,
                ip,
                probed_ports as i64,
                open_ports.len() as i64,
                compact_port_list(&opened),
                compact_port_list(&closed),
                scanned_at
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 列出一个批次的精简端口扫描摘要.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    ///
    /// # 返回
    /// 扫描摘要列表.
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
    /// let batch = db.create_batch()?; let _ = db.list_scan_summaries(&batch.id)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn list_scan_summaries(&self, batch_id: &str) -> anyhow::Result<Vec<ScanSummary>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, batch_id, system_id, ip_id, ip, probed_ports, open_count,
                    opened_ports, closed_ports, created_at
             FROM scan_summaries
             WHERE batch_id = ?1
             ORDER BY ip",
        )?;
        collect_rows(&mut stmt, [batch_id], |row| {
            Ok(ScanSummary {
                id: row.get(0)?,
                batch_id: row.get(1)?,
                system_id: row.get(2)?,
                ip_id: row.get(3)?,
                ip: row.get(4)?,
                probed_ports: row.get(5)?,
                open_count: row.get(6)?,
                opened_ports: row.get(7)?,
                closed_ports: row.get(8)?,
                created_at: row.get(9)?,
            })
        })
    }

    /// 更新端口的服务指纹信息.
    ///
    /// # 参数
    /// - `port_id`: 端口主键.
    /// - `service`: 服务名.
    /// - `fingerprint`: 指纹文本.
    /// - `is_web`: 是否 Web 服务.
    /// - `scheme`: 可选协议.
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
    /// let sid = db.upsert_system("core")?; let pid = db.upsert_port(&sid, None, 80, "scan")?; db.update_port_fingerprint(&pid, Some("http"), None, true, Some("http"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn update_port_fingerprint(
        &self,
        port_id: &str,
        service: Option<&str>,
        fingerprint: Option<&str>,
        is_web: bool,
        scheme: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE ports SET service = ?1, fingerprint = ?2, is_web = ?3, scheme = ?4, last_seen = ?5 WHERE id = ?6",
            params![service, fingerprint, is_web as i64, scheme, now(), port_id],
        )?;
        Ok(())
    }

    /// 更新详细服务指纹字段, 同时保留 Web 分类.
    ///
    /// # 参数
    /// - `port_id`: 端口主键.
    /// - `service`: 服务名.
    /// - `fingerprint`: 指纹文本.
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
    /// let sid = db.upsert_system("core")?; let pid = db.upsert_port(&sid, None, 80, "scan")?; db.update_port_detailed_fingerprint(&pid, Some("http"), None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn update_port_detailed_fingerprint(
        &self,
        port_id: &str,
        service: Option<&str>,
        fingerprint: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE ports SET service = COALESCE(?1, service), fingerprint = COALESCE(?2, fingerprint), last_seen = ?3 WHERE id = ?4",
            params![service, fingerprint, now(), port_id],
        )?;
        Ok(())
    }

    /// 更新 DNS 解析状态, 发生变化时写告警.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    /// - `domain`: 待更新的域名资产.
    /// - `new_ips`: 最新解析 IP.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 更新域名、写入解析 IP 或告警失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let batch = db.create_batch()?; let _id = db.upsert_domain_for_system("core", "example.com", None)?; let domain = &db.list_domains()?[0]; db.update_domain_resolution(&batch.id, domain, &["1.1.1.1".into()])?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn update_domain_resolution(
        &self,
        batch_id: &str,
        domain: &DomainAsset,
        new_ips: &[String],
    ) -> anyhow::Result<()> {
        let new_value = new_ips.join(",");
        let old_value = domain.bind_ip.clone().unwrap_or_default();
        let conn = self.conn()?;
        conn.execute(
            "UPDATE domains SET bind_ip = ?1, last_resolved_ips = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_value, now(), domain.id],
        )?;
        for ip in new_ips {
            self.upsert_ip(&domain.system_id, ip, "resolved")?;
        }
        if old_value != new_value {
            self.add_alert(
                batch_id,
                Some(&domain.system_id),
                "dns_change",
                "medium",
                &domain.name,
                if old_value.is_empty() {
                    None
                } else {
                    Some(&old_value)
                },
                Some(&new_value),
                None,
            )?;
        }
        Ok(())
    }

    /// 新增一条告警.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    /// - `system_id`: 可选业务系统 id.
    /// - `kind`: 告警类型.
    /// - `severity`: 严重级别.
    /// - `subject`: 告警主体.
    /// - `old_value`: 变更前值.
    /// - `new_value`: 变更后值.
    /// - `details`: 附加详情.
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
    /// let batch = db.create_batch()?; db.add_alert(&batch.id, None, "dns_change", "low", "example.com", None, None, None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn add_alert(
        &self,
        batch_id: &str,
        system_id: Option<&str>,
        kind: &str,
        severity: &str,
        subject: &str,
        old_value: Option<&str>,
        new_value: Option<&str>,
        details: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO alerts (id, batch_id, system_id, kind, severity, subject, old_value, new_value, details, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![new_id(), batch_id, system_id, kind, severity, subject, old_value, new_value, details, now()],
        )?;
        Ok(())
    }

    /// 新增或忽略一条漏洞发现.
    ///
    /// # 参数
    /// - `batch_id`: 批次 id.
    /// - `system_id`: 业务系统 id.
    /// - `url`: 命中 URL.
    /// - `poc`: PoC 名称.
    /// - `severity`: 严重级别.
    /// - `evidence`: 证据.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// 插入漏洞或回写 URL 失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let sid = db.upsert_system("core")?; let batch = db.create_batch()?; db.add_vulnerability(&batch.id, &sid, "https://example.com", "poc", "low", "e")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn add_vulnerability(
        &self,
        batch_id: &str,
        system_id: &str,
        url: &str,
        poc: &str,
        severity: &str,
        evidence: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO vulnerabilities (id, batch_id, system_id, url, poc, severity, evidence, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![new_id(), batch_id, system_id, url, poc, severity, evidence, now()],
        )?;
        self.upsert_url(system_id, url, "vuln", None, 100)?;
        Ok(())
    }
}

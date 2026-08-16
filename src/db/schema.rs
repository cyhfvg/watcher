//! 数据库迁移与兼容性补列.

use crate::db::Database;

use super::helpers::collect_rows;

impl Database {
    /// 应用幂等数据库迁移, 创建表/索引并回填旧库列.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// SQL 执行、补列或清理失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// db.migrate()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS systems (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS domains (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                bind_ip TEXT,
                last_resolved_ips TEXT,
                is_baseline INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(system_id, name)
            );

            CREATE TABLE IF NOT EXISTS ip_addresses (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                source TEXT NOT NULL,
                is_baseline INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(system_id, ip)
            );

            CREATE TABLE IF NOT EXISTS ports (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
                ip_id TEXT REFERENCES ip_addresses(id) ON DELETE CASCADE,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                state TEXT NOT NULL DEFAULT 'unknown',
                source TEXT NOT NULL,
                service TEXT,
                fingerprint TEXT,
                is_web INTEGER NOT NULL DEFAULT 0,
                scheme TEXT,
                is_baseline INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(system_id, ip_id, port)
            );

            CREATE TABLE IF NOT EXISTS urls (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                source TEXT NOT NULL,
                status_code INTEGER,
                title TEXT,
                value_score INTEGER NOT NULL DEFAULT 0,
                is_baseline INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(system_id, url)
            );

            CREATE TABLE IF NOT EXISTS dict_paths (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS batches (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                stop_requested INTEGER NOT NULL DEFAULT 0,
                report_zip TEXT,
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS batch_stages (
                batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
                stage TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                detail TEXT,
                PRIMARY KEY(batch_id, stage)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
                system_id TEXT REFERENCES systems(id) ON DELETE SET NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                subject TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                details TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
                system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                poc TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(batch_id, system_id, url, poc)
            );

            CREATE TABLE IF NOT EXISTS pending_work (
                id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL,
                system_id TEXT NOT NULL,
                task_kind TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                priority INTEGER NOT NULL DEFAULT 100,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(task_kind, target)
            );

            CREATE TABLE IF NOT EXISTS logs (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                level TEXT NOT NULL,
                target TEXT NOT NULL,
                message TEXT NOT NULL,
                fields TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_summaries (
                id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
                system_id TEXT REFERENCES systems(id) ON DELETE SET NULL,
                ip_id TEXT REFERENCES ip_addresses(id) ON DELETE SET NULL,
                ip TEXT NOT NULL,
                probed_ports INTEGER NOT NULL,
                open_count INTEGER NOT NULL,
                opened_ports TEXT,
                closed_ports TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(batch_id, ip_id, ip)
            );


            CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(name);
            CREATE INDEX IF NOT EXISTS idx_domains_system_baseline_name ON domains(system_id, is_baseline, name);
            CREATE INDEX IF NOT EXISTS idx_domains_baseline_name ON domains(is_baseline, name);
            CREATE INDEX IF NOT EXISTS idx_ips_ip ON ip_addresses(ip);
            CREATE INDEX IF NOT EXISTS idx_ips_system_baseline_ip ON ip_addresses(system_id, is_baseline, ip);
            CREATE INDEX IF NOT EXISTS idx_ips_baseline_ip ON ip_addresses(is_baseline, ip);
            CREATE INDEX IF NOT EXISTS idx_ips_source_ip ON ip_addresses(source, ip);
            CREATE INDEX IF NOT EXISTS idx_ports_state ON ports(state);
            CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
            CREATE INDEX IF NOT EXISTS idx_ports_system_baseline_port ON ports(system_id, is_baseline, port);
            CREATE INDEX IF NOT EXISTS idx_ports_baseline_port ON ports(is_baseline, port);
            CREATE INDEX IF NOT EXISTS idx_ports_state_web ON ports(state, is_web);
            CREATE INDEX IF NOT EXISTS idx_urls_url ON urls(url);
            CREATE INDEX IF NOT EXISTS idx_urls_system_baseline_url ON urls(system_id, is_baseline, url);
            CREATE INDEX IF NOT EXISTS idx_urls_baseline_url ON urls(is_baseline, url);
            CREATE INDEX IF NOT EXISTS idx_dict_paths_enabled_path ON dict_paths(enabled, path);
            CREATE INDEX IF NOT EXISTS idx_alerts_batch ON alerts(batch_id);
            CREATE INDEX IF NOT EXISTS idx_batch_stages_batch ON batch_stages(batch_id, started_at);
            CREATE INDEX IF NOT EXISTS idx_vulns_batch ON vulnerabilities(batch_id);
            CREATE INDEX IF NOT EXISTS idx_pending_work_take ON pending_work(task_kind, status, priority, created_at);
            CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at);
            CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
            CREATE INDEX IF NOT EXISTS idx_scan_summaries_batch ON scan_summaries(batch_id);
            CREATE INDEX IF NOT EXISTS idx_scan_summaries_ip ON scan_summaries(ip);

            "#,
        )?;
        drop(conn);
        let added_domains =
            self.ensure_column("domains", "is_baseline", "INTEGER NOT NULL DEFAULT 0")?;
        let added_ips =
            self.ensure_column("ip_addresses", "is_baseline", "INTEGER NOT NULL DEFAULT 0")?;
        let added_ports =
            self.ensure_column("ports", "is_baseline", "INTEGER NOT NULL DEFAULT 0")?;
        let added_urls = self.ensure_column("urls", "is_baseline", "INTEGER NOT NULL DEFAULT 0")?;
        if added_domains || added_ips || added_ports || added_urls {
            self.mark_existing_imports_as_baseline(
                added_domains,
                added_ips,
                added_ports,
                added_urls,
            )?;
        }
        self.prune_redundant_port_rows()?;
        Ok(())
    }

    /// 删除旧版全端口扫描留下的已关闭非基线端口行.
    ///
    /// # 参数
    /// 无
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// `DELETE` 失败时返回错误.
    ///
    /// # 示例
    /// ```text
    /// db.prune_redundant_port_rows()?;
    /// ```
    fn prune_redundant_port_rows(&self) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM ports WHERE state = 'closed' AND is_baseline = 0",
            [],
        )?;
        Ok(())
    }

    /// 当旧库缺少指定列时补上该列.
    ///
    /// # 参数
    /// - `table`: 表名.
    /// - `column`: 列名.
    /// - `definition`: `ALTER TABLE` 列定义.
    ///
    /// # 返回
    /// 新增列为 `true`, 已存在为 `false`.
    ///
    /// # Errors
    /// `PRAGMA` 或 `ALTER TABLE` 失败时返回错误.
    ///
    /// # 示例
    /// ```text
    /// let added = self.ensure_column("domains", "is_baseline", "INTEGER NOT NULL DEFAULT 0")?;
    /// ```
    fn ensure_column(&self, table: &str, column: &str, definition: &str) -> anyhow::Result<bool> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = collect_rows(&mut stmt, [], |row| Ok(row.get::<_, String>(1)?))?;
        if columns.iter().any(|existing| existing == column) {
            return Ok(false);
        }
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )?;
        Ok(true)
    }

    /// 为引入 `is_baseline` 之前的旧库回填基线标记.
    ///
    /// # 参数
    /// - `domains`: 是否回填域名.
    /// - `ips`: 是否回填 IP.
    /// - `ports`: 是否回填端口.
    /// - `urls`: 是否回填 URL.
    ///
    /// # 返回
    /// 无
    ///
    /// # Errors
    /// `UPDATE` 失败时返回错误.
    ///
    /// # 示例
    /// ```text
    /// self.mark_existing_imports_as_baseline(true, true, true, true)?;
    /// ```
    fn mark_existing_imports_as_baseline(
        &self,
        domains: bool,
        ips: bool,
        ports: bool,
        urls: bool,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        if domains {
            conn.execute(
                "UPDATE domains SET is_baseline = 1 WHERE is_baseline = 0",
                [],
            )?;
        }
        if ips {
            conn.execute(
                "UPDATE ip_addresses SET is_baseline = 1 WHERE is_baseline = 0 AND source IN ('imported', 'manual')",
                [],
            )?;
        }
        if ports {
            conn.execute(
                "UPDATE ports SET is_baseline = 1 WHERE is_baseline = 0 AND source IN ('imported', 'manual')",
                [],
            )?;
        }
        if urls {
            conn.execute(
                "UPDATE urls SET is_baseline = 1 WHERE is_baseline = 0 AND source IN ('imported', 'manual')",
                [],
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::BaselineImportRow;

    #[test]
    fn bulk_imports_baseline_assets_and_creates_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("watcher.db")).unwrap();
        db.migrate().unwrap();

        let summary = db
            .import_baseline_rows(
                &[
                    BaselineImportRow {
                        system: "core".to_string(),
                        name: Some("example.com.".to_string()),
                        bind_ip: Some("10.0.0.1".to_string()),
                        ip: Some("10.0.0.1".to_string()),
                        ports: vec![80, 443],
                        url: Some("https://example.com".to_string()),
                    },
                    BaselineImportRow {
                        system: "core".to_string(),
                        name: Some("example.com".to_string()),
                        bind_ip: None,
                        ip: Some("10.0.0.1".to_string()),
                        ports: vec![80],
                        url: Some("https://example.com".to_string()),
                    },
                ],
                "imported",
            )
            .unwrap();

        assert_eq!(summary.systems, 2);
        assert_eq!(summary.names, 2);
        assert_eq!(summary.ips, 2);
        assert_eq!(summary.ports, 3);
        assert_eq!(summary.urls, 2);

        let systems = db.query_systems(Some("core"), 10).unwrap();
        assert_eq!(systems[0][1], "1");
        assert_eq!(systems[0][2], "1");
        assert_eq!(systems[0][3], "2");
        assert_eq!(systems[0][4], "1");
        assert_eq!(systems[0][5], "1");
        assert_eq!(systems[0][6], "1");
        assert_eq!(systems[0][7], "2");
        assert_eq!(systems[0][8], "1");

        let imported = db
            .import_baseline_ports_for_system("core", None, &[8080, 8080], "manual")
            .unwrap();
        assert_eq!(imported, 2);
        assert_eq!(db.query_systems(Some("core"), 10).unwrap()[0][3], "3");

        let conn = db.conn().unwrap();
        let index_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN (
                    'idx_domains_system_baseline_name',
                    'idx_ips_system_baseline_ip',
                    'idx_ports_system_baseline_port',
                    'idx_urls_system_baseline_url',
                    'idx_pending_work_take'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index_count, 5);
    }

    #[test]
    fn migrate_prunes_closed_non_baseline_ports() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("watcher.db")).unwrap();
        db.migrate().unwrap();
        let system_id = db.upsert_system("core").unwrap();
        let ip_id = db.upsert_ip(&system_id, "10.0.0.1", "imported").unwrap();
        let closed_id = db
            .upsert_port(&system_id, Some(&ip_id), 8080, "scan")
            .unwrap();
        let conn = db.conn().unwrap();
        conn.execute(
            "UPDATE ports SET state = 'closed' WHERE id = ?1",
            [&closed_id],
        )
        .unwrap();
        drop(conn);

        db.migrate().unwrap();
        assert!(db.query_ports(Some("8080"), 10).unwrap().is_empty());
    }
}

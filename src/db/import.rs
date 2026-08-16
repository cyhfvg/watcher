//! 基线与非基线资产批量导入.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, params};

use super::{
    helpers::{cached_system_id, ensure_system_in_tx, new_id, now, trimmed_opt},
    types::{BaselineImportRow, BaselineImportSummary, Database},
};

impl Database {
    /// 在单个事务内批量导入结构化基线行.
    ///
    /// # 参数
    /// - `rows`: 规范化基线行.
    /// - `source`: 来源标记.
    ///
    /// # 返回
    /// 导入计数摘要.
    ///
    /// # Errors
    /// 事务或 upsert 失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// use watcher::db::BaselineImportRow; let _ = db.import_baseline_rows(&[BaselineImportRow { system: "core".into(), ..Default::default() }], "imported")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_baseline_rows(
        &self,
        rows: &[BaselineImportRow],
        source: &str,
    ) -> anyhow::Result<BaselineImportSummary> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let mut system_cache = HashMap::<String, String>::new();
        let mut summary = BaselineImportSummary::default();

        {
            let mut select_system = tx.prepare("SELECT id FROM systems WHERE name = ?1")?;
            let mut insert_system = tx.prepare(
                "INSERT OR IGNORE INTO systems (id, name, created_at) VALUES (?1, ?2, ?3)",
            )?;
            let mut upsert_domain = tx.prepare(
                "INSERT INTO domains (id, system_id, name, bind_ip, is_baseline, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
                 ON CONFLICT(system_id, name) DO UPDATE SET
                    bind_ip = COALESCE(excluded.bind_ip, domains.bind_ip),
                    is_baseline = 1,
                    updated_at = excluded.updated_at",
            )?;
            let mut upsert_ip = tx.prepare(
                "INSERT INTO ip_addresses (id, system_id, ip, source, is_baseline, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
                 ON CONFLICT(system_id, ip) DO UPDATE SET
                    source = CASE WHEN ip_addresses.source = 'resolved' THEN excluded.source ELSE ip_addresses.source END,
                    is_baseline = 1,
                    updated_at = excluded.updated_at",
            )?;
            let mut select_ip =
                tx.prepare("SELECT id FROM ip_addresses WHERE system_id = ?1 AND ip = ?2")?;
            let mut select_port = tx.prepare(
                "SELECT id FROM ports
                 WHERE system_id = ?1
                   AND ((ip_id IS NULL AND ?2 IS NULL) OR ip_id = ?2)
                   AND port = ?3",
            )?;
            let mut insert_port = tx.prepare(
                "INSERT INTO ports (id, system_id, ip_id, port, source, is_baseline, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
            )?;
            let mut mark_port_baseline =
                tx.prepare("UPDATE ports SET is_baseline = 1, last_seen = ?1 WHERE id = ?2")?;
            let mut upsert_url = tx.prepare(
                "INSERT INTO urls (id, system_id, url, source, value_score, is_baseline, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 10, 1, ?5, ?5)
                 ON CONFLICT(system_id, url) DO UPDATE SET
                    source = CASE WHEN urls.source = 'imported' THEN urls.source ELSE excluded.source END,
                    value_score = MAX(urls.value_score, excluded.value_score),
                    is_baseline = 1,
                    updated_at = excluded.updated_at",
            )?;

            for row in rows {
                let system = row.system.trim();
                if system.is_empty() {
                    continue;
                }
                summary.systems += 1;
                let system_id = cached_system_id(
                    &mut system_cache,
                    &mut select_system,
                    &mut insert_system,
                    system,
                )?;

                if let Some(name) = trimmed_opt(row.name.as_deref()) {
                    let name = name.trim_end_matches('.');
                    if name.is_empty() {
                        continue;
                    }
                    upsert_domain.execute(params![
                        new_id(),
                        system_id,
                        name,
                        trimmed_opt(row.bind_ip.as_deref()),
                        now()
                    ])?;
                    summary.names += 1;
                }

                let ip_id = if let Some(ip) = trimmed_opt(row.ip.as_deref()) {
                    upsert_ip.execute(params![new_id(), system_id, ip, source, now()])?;
                    let id: String =
                        select_ip.query_row(params![system_id, ip], |row| row.get(0))?;
                    summary.ips += 1;
                    Some(id)
                } else {
                    None
                };

                for port in &row.ports {
                    if let Some(id) = select_port
                        .query_row(params![system_id, ip_id.as_deref(), *port], |row| {
                            row.get::<_, String>(0)
                        })
                        .optional()?
                    {
                        mark_port_baseline.execute(params![now(), id])?;
                    } else {
                        insert_port.execute(params![
                            new_id(),
                            system_id,
                            ip_id.as_deref(),
                            *port,
                            source,
                            now()
                        ])?;
                    }
                    summary.ports += 1;
                }

                if let Some(url) = trimmed_opt(row.url.as_deref()) {
                    upsert_url.execute(params![new_id(), system_id, url, source, now()])?;
                    summary.urls += 1;
                }
            }
        }

        tx.commit()?;
        Ok(summary)
    }

    /// 为单个业务系统批量导入基线 URL.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `values`: URL 列表.
    /// - `source`: 来源标记.
    ///
    /// # 返回
    /// 处理条数.
    ///
    /// # Errors
    /// 系统名为空或写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.import_baseline_urls_for_system("core", &["https://example.com".into()], "manual")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_baseline_urls_for_system(
        &self,
        system: &str,
        values: &[String],
        source: &str,
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO urls (id, system_id, url, source, value_score, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, 1, ?5, ?5)
             ON CONFLICT(system_id, url) DO UPDATE SET
                source = CASE WHEN urls.source = 'imported' THEN urls.source ELSE excluded.source END,
                is_baseline = 1,
                updated_at = excluded.updated_at",
            Some(source),
            false,
        )
    }

    /// 为单个业务系统批量导入非基线 URL.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `values`: URL 列表.
    /// - `source`: 来源标记.
    ///
    /// # 返回
    /// 处理条数.
    ///
    /// # Errors
    /// 系统名为空或写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.import_urls_for_system("core", &["https://example.com/login".into()], "manual")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_urls_for_system(
        &self,
        system: &str,
        values: &[String],
        source: &str,
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO urls (id, system_id, url, source, value_score, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, ?5)
             ON CONFLICT(system_id, url) DO UPDATE SET
                source = CASE WHEN urls.source = 'imported' THEN urls.source ELSE excluded.source END,
                updated_at = excluded.updated_at",
            Some(source),
            false,
        )
    }

    /// 为单个业务系统批量导入基线 IP.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `values`: IP 列表.
    /// - `source`: 来源标记.
    ///
    /// # 返回
    /// 处理条数.
    ///
    /// # Errors
    /// 系统名为空或写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.import_baseline_ips_for_system("core", &["10.0.0.1".into()], "manual")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_baseline_ips_for_system(
        &self,
        system: &str,
        values: &[String],
        source: &str,
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO ip_addresses (id, system_id, ip, source, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
             ON CONFLICT(system_id, ip) DO UPDATE SET
                source = CASE WHEN ip_addresses.source = 'resolved' THEN excluded.source ELSE ip_addresses.source END,
                is_baseline = 1,
                updated_at = excluded.updated_at",
            Some(source),
            false,
        )
    }

    /// 为单个业务系统批量导入非基线 IP.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `values`: IP 列表.
    /// - `source`: 来源标记.
    ///
    /// # 返回
    /// 处理条数.
    ///
    /// # Errors
    /// 系统名为空或写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.import_ips_for_system("core", &["10.0.0.2".into()], "manual")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_ips_for_system(
        &self,
        system: &str,
        values: &[String],
        source: &str,
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO ip_addresses (id, system_id, ip, source, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)
             ON CONFLICT(system_id, ip) DO UPDATE SET
                source = CASE WHEN ip_addresses.source = 'resolved' THEN excluded.source ELSE ip_addresses.source END,
                updated_at = excluded.updated_at",
            Some(source),
            false,
        )
    }

    /// 为单个业务系统批量导入基线域名.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `values`: 域名列表.
    ///
    /// # 返回
    /// 处理条数.
    ///
    /// # Errors
    /// 系统名为空或写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.import_baseline_names_for_system("core", &["example.com".into()])?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_baseline_names_for_system(
        &self,
        system: &str,
        values: &[String],
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO domains (id, system_id, name, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, ?5, ?5)
             ON CONFLICT(system_id, name) DO UPDATE SET
                is_baseline = 1,
                updated_at = excluded.updated_at",
            None,
            true,
        )
    }

    /// 为单个业务系统批量导入非基线域名.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `values`: 域名列表.
    /// - `bind_ip`: 可选绑定 IP.
    ///
    /// # 返回
    /// 处理条数.
    ///
    /// # Errors
    /// 系统名为空或写入失败时返回错误.
    ///
    /// # 示例
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let db = Database::open(&dir.path().join("watcher.db"))?;
    /// # db.migrate()?;
    /// let _ = db.import_names_for_system("core", &["www.example.com".into()], None)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn import_names_for_system(
        &self,
        system: &str,
        values: &[String],
        bind_ip: Option<&str>,
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO domains (id, system_id, name, bind_ip, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)
             ON CONFLICT(system_id, name) DO UPDATE SET
                bind_ip = COALESCE(excluded.bind_ip, domains.bind_ip),
                updated_at = excluded.updated_at",
            trimmed_opt(bind_ip),
            true,
        )
    }

    /// 使用给定 upsert SQL 为单个业务系统批量导入简单值.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `values`: 待导入值.
    /// - `upsert_sql`: 预编译 upsert 语句.
    /// - `parameter4`: 可选第 4 绑定参数.
    /// - `trim_trailing_dot`: 是否去掉末尾点号.
    ///
    /// # 返回
    /// 处理条数.
    ///
    /// # Errors
    /// 系统名为空或写入失败时返回错误.
    ///
    /// # 示例
    /// ```text
    /// self.import_values_for_system(system, values, sql, Some(source), false)?;
    /// ```
    fn import_values_for_system(
        &self,
        system: &str,
        values: &[String],
        upsert_sql: &str,
        parameter4: Option<&str>,
        trim_trailing_dot: bool,
    ) -> anyhow::Result<usize> {
        let system = system.trim();
        anyhow::ensure!(!system.is_empty(), "system name must not be empty");
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let system_id = ensure_system_in_tx(&tx, system)?;
        let mut count = 0usize;
        {
            let mut upsert = tx.prepare(upsert_sql)?;
            for value in values {
                let Some(value) = trimmed_opt(Some(value.as_str())) else {
                    continue;
                };
                let value = if trim_trailing_dot {
                    value.trim_end_matches('.')
                } else {
                    value
                };
                anyhow::ensure!(!value.is_empty(), "asset value must not be empty");
                upsert.execute(params![new_id(), system_id, value, parameter4, now()])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }
}

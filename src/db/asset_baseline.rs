//! 资产基线标记.

use rusqlite::params;

use super::types::Database;

impl Database {
    /// 按主键将域名标为基线或非基线.
    ///
    /// # 参数
    /// - `id`: 域名主键.
    /// - `is_baseline`: 是否基线.
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
    /// let id = db.upsert_domain_for_system("core", "example.com", None)?; db.set_domain_baseline_by_id(&id, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_domain_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("domains", id, is_baseline)
    }

    /// 按主键将 IP 标为基线或非基线.
    ///
    /// # 参数
    /// - `id`: IP 主键.
    /// - `is_baseline`: 是否基线.
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
    /// let id = db.upsert_ip_for_system("core", "10.0.0.1", "imported")?; db.set_ip_baseline_by_id(&id, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_ip_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("ip_addresses", id, is_baseline)
    }

    /// 按主键将端口标为基线或非基线.
    ///
    /// # 参数
    /// - `id`: 端口主键.
    /// - `is_baseline`: 是否基线.
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
    /// let id = db.upsert_port_for_system("core", None, 80, "imported")?; db.set_port_baseline_by_id(&id, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_port_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("ports", id, is_baseline)
    }

    /// 按主键将 URL 标为基线或非基线.
    ///
    /// # 参数
    /// - `id`: URL 主键.
    /// - `is_baseline`: 是否基线.
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
    /// let id = db.upsert_url_for_system("core", "https://example.com", "imported")?; db.set_url_baseline_by_id(&id, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_url_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("urls", id, is_baseline)
    }

    /// 按业务系统将指定 URL 标为基线或非基线.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `value`: URL.
    /// - `is_baseline`: 是否基线.
    ///
    /// # 返回
    /// 更新行数.
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
    /// db.upsert_url_for_system("core", "https://example.com", "imported")?; let _ = db.set_url_baseline_for_system("core", "https://example.com", true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_url_baseline_for_system(
        &self,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        self.set_baseline_by_system_value("urls", "url", system, value, is_baseline)
    }

    /// 按业务系统与可选 IP 将端口标为基线或非基线.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `ip`: 可选绑定 IP.
    /// - `port`: 端口号.
    /// - `is_baseline`: 是否基线.
    ///
    /// # 返回
    /// 更新行数.
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
    /// db.upsert_port_for_system("core", Some("10.0.0.1"), 443, "imported")?; let _ = db.set_port_baseline_for_system("core", Some("10.0.0.1"), 443, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_port_baseline_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        port: u16,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "UPDATE ports
             SET is_baseline = ?1
             WHERE system_id = (SELECT id FROM systems WHERE name = ?2)
               AND port = ?3
               AND (?4 IS NULL OR ip_id IN (
                   SELECT id FROM ip_addresses
                   WHERE system_id = ports.system_id AND ip = ?4
               ))",
            params![is_baseline as i64, system, port, ip],
        )?)
    }

    /// 按业务系统将指定 IP 标为基线或非基线.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `value`: IP 地址.
    /// - `is_baseline`: 是否基线.
    ///
    /// # 返回
    /// 更新行数.
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
    /// db.upsert_ip_for_system("core", "10.0.0.1", "imported")?; let _ = db.set_ip_baseline_for_system("core", "10.0.0.1", true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_ip_baseline_for_system(
        &self,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        self.set_baseline_by_system_value("ip_addresses", "ip", system, value, is_baseline)
    }

    /// 按业务系统将指定域名标为基线或非基线.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `value`: 域名.
    /// - `is_baseline`: 是否基线.
    ///
    /// # 返回
    /// 更新行数.
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
    /// db.upsert_domain_for_system("core", "example.com", None)?; let _ = db.set_name_baseline_for_system("core", "example.com", true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn set_name_baseline_for_system(
        &self,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        self.set_baseline_by_system_value("domains", "name", system, value, is_baseline)
    }
}

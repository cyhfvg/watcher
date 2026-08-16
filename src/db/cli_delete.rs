//! CLI 资产删除.

use rusqlite::params;

use super::types::Database;

impl Database {
    /// 按精确值删除 URL.
    ///
    /// # 参数
    /// - `value`: URL.
    ///
    /// # 返回
    /// 无
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
    /// db.delete_url("https://example.com")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_url(&self, value: &str) -> anyhow::Result<()> {
        self.delete_by_value("urls", "url", value)
    }

    /// 按业务系统与精确值删除 URL.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `value`: URL.
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
    /// let _ = db.delete_url_for_system("core", "https://example.com")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_url_for_system(&self, system: &str, value: &str) -> anyhow::Result<usize> {
        self.delete_by_system_value("urls", "url", system, value)
    }

    /// 按精确端口号从所有系统/IP 删除端口.
    ///
    /// # 参数
    /// - `value`: 端口号.
    ///
    /// # 返回
    /// 无
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
    /// db.delete_port(80)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_port(&self, value: u16) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM ports WHERE port = ?1", [value])?;
        Ok(())
    }

    /// 按业务系统, 可选 IP 与精确端口删除端口.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `ip`: 可选绑定 IP.
    /// - `port`: 端口号.
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
    /// let _ = db.delete_port_for_system("core", None, 80)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_port_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        port: u16,
    ) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "DELETE FROM ports
             WHERE system_id = (SELECT id FROM systems WHERE name = ?1)
               AND port = ?2
               AND (?3 IS NULL OR ip_id IN (
                   SELECT id FROM ip_addresses
                   WHERE system_id = ports.system_id AND ip = ?3
               ))",
            params![system, port, ip],
        )?)
    }

    /// 按精确值删除 IP.
    ///
    /// # 参数
    /// - `value`: IP 地址.
    ///
    /// # 返回
    /// 无
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
    /// db.delete_ip("10.0.0.1")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_ip(&self, value: &str) -> anyhow::Result<()> {
        self.delete_by_value("ip_addresses", "ip", value)
    }

    /// 按业务系统与精确值删除 IP.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `value`: IP 地址.
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
    /// let _ = db.delete_ip_for_system("core", "10.0.0.1")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_ip_for_system(&self, system: &str, value: &str) -> anyhow::Result<usize> {
        self.delete_by_system_value("ip_addresses", "ip", system, value)
    }

    /// 按精确值删除域名.
    ///
    /// # 参数
    /// - `value`: 域名.
    ///
    /// # 返回
    /// 无
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
    /// db.delete_name("example.com")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_name(&self, value: &str) -> anyhow::Result<()> {
        self.delete_by_value("domains", "name", value)
    }

    /// 按业务系统与精确值删除域名.
    ///
    /// # 参数
    /// - `system`: 业务系统名称.
    /// - `value`: 域名.
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
    /// let _ = db.delete_name_for_system("core", "example.com")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn delete_name_for_system(&self, system: &str, value: &str) -> anyhow::Result<usize> {
        self.delete_by_system_value("domains", "name", system, value)
    }
}

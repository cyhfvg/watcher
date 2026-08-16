//! 配置加载与运行时取值.

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;

use crate::local_time;

use super::defaults::{
    default_config_path, default_scan_ip_concurrency, default_scan_port_concurrency_per_ip,
    default_smtp_security, expand_tilde,
};
use super::types::{
    AppConfig, DatabaseConfig, DisplayConfig, EmailConfig, FingerprintConfig, PocConfig,
    ProbeConfig, ReportConfig, ReportFormat, ScanPortsConfig, SchedulerConfig, WebConfig,
};

impl AppConfig {
    /// Loads the default configuration file, creating it if it does not exist.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 已加载并完成路径展开, 时区校验和目录创建的 [`AppConfig`].
    ///
    /// # Errors
    ///
    /// 无法定位默认配置路径, 创建父目录, 写入/读取 YAML, 解析配置,
    /// 校验展示时区, 或创建数据库/报告目录时返回错误.
    ///
    /// # 示例
    ///
    /// ```no_run
    /// use watcher::config::AppConfig;
    ///
    /// let config = AppConfig::load_or_create()?;
    /// assert!(!config.database.path.as_os_str().is_empty());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn load_or_create() -> anyhow::Result<Self> {
        let config_path = default_config_path()?;
        if !config_path.exists() {
            if let Some(parent) = config_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            let default = Self::default_with_path(config_path.clone())?;
            fs::write(&config_path, serde_yaml::to_string(&default)?)
                .with_context(|| format!("failed to write {}", config_path.display()))?;
        }

        let content = fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?;
        let mut config: AppConfig = serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse {}", config_path.display()))?;
        config.config_path = config_path;
        config.database.path = expand_tilde(&config.database.path);
        config.report.output_dir = expand_tilde(&config.report.output_dir);
        local_time::parse_timezone(&config.display.timezone)?;
        config.ensure_dirs()?;
        Ok(config)
    }

    /// Returns an example YAML configuration suitable for stdout output.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 基于默认路径生成的 YAML 文本.
    ///
    /// # Errors
    ///
    /// 构造默认配置或序列化为 YAML 失败时返回错误.
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::AppConfig;
    ///
    /// let yaml = AppConfig::example_yaml()?;
    /// assert!(yaml.contains("scheduler:"));
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn example_yaml() -> anyhow::Result<String> {
        let example = Self::default_with_path(PathBuf::from("~/.config/watcher/watcher.yml"))?;
        Ok(serde_yaml::to_string(&example)?)
    }

    /// Returns the scheduler interval as a duration.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 至少 1 分钟的调度间隔.
    ///
    /// # 示例
    ///
    /// ```
    /// use std::time::Duration;
    /// use watcher::config::AppConfig;
    ///
    /// let config: AppConfig = serde_yaml::from_str(&AppConfig::example_yaml()?)?;
    /// assert_eq!(config.interval(), Duration::from_secs(360 * 60));
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.scheduler.interval_minutes.max(1) * 60)
    }

    /// Returns the TCP connect timeout as a duration.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 至少 100 毫秒的 TCP 连接超时.
    ///
    /// # 示例
    ///
    /// ```
    /// use std::time::Duration;
    /// use watcher::config::AppConfig;
    ///
    /// let config: AppConfig = serde_yaml::from_str(&AppConfig::example_yaml()?)?;
    /// assert_eq!(config.connect_timeout(), Duration::from_millis(2000));
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.probe.connect_timeout_ms.max(100))
    }

    /// Returns the number of IP addresses scanned concurrently.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 至少为 `1` 的 IP 扫描并发数.
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::AppConfig;
    ///
    /// let config: AppConfig = serde_yaml::from_str(&AppConfig::example_yaml()?)?;
    /// assert_eq!(config.scan_ip_concurrency(), 4);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn scan_ip_concurrency(&self) -> usize {
        self.probe.scan_ip_concurrency.max(1)
    }

    /// Returns the per-IP port scan concurrency.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 至少为 `1` 的单 IP 端口扫描并发数.
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::AppConfig;
    ///
    /// let config: AppConfig = serde_yaml::from_str(&AppConfig::example_yaml()?)?;
    /// assert_eq!(config.scan_port_concurrency_per_ip(), 4);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn scan_port_concurrency_per_ip(&self) -> usize {
        self.probe.scan_port_concurrency_per_ip.max(1)
    }

    /// Returns the HTTP timeout as a duration.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 至少 500 毫秒的 HTTP 超时.
    ///
    /// # 示例
    ///
    /// ```
    /// use std::time::Duration;
    /// use watcher::config::AppConfig;
    ///
    /// let config: AppConfig = serde_yaml::from_str(&AppConfig::example_yaml()?)?;
    /// assert_eq!(config.http_timeout(), Duration::from_millis(8000));
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn http_timeout(&self) -> Duration {
        Duration::from_millis(self.probe.http_timeout_ms.max(500))
    }

    /// Returns a conservative upper bound for concurrent HTTP probes.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 限制在 `[1, 8]` 区间内的 HTTP 并发数.
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::AppConfig;
    ///
    /// let config: AppConfig = serde_yaml::from_str(&AppConfig::example_yaml()?)?;
    /// assert_eq!(config.http_concurrency(), 8);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn http_concurrency(&self) -> usize {
        self.probe.concurrency.clamp(1, 8)
    }

    /// Returns the per-target delay as a duration.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 同一目标连续请求之间的延迟.
    ///
    /// # 示例
    ///
    /// ```
    /// use std::time::Duration;
    /// use watcher::config::AppConfig;
    ///
    /// let config: AppConfig = serde_yaml::from_str(&AppConfig::example_yaml()?)?;
    /// assert_eq!(config.per_target_delay(), Duration::from_millis(1200));
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn per_target_delay(&self) -> Duration {
        Duration::from_millis(self.probe.per_target_delay_ms)
    }

    /// Returns the daemon PID file path.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 配置文件同目录下的 `watcher.pid`; 无父目录时退回当前目录的 `watcher.pid`.
    ///
    /// # 示例
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use watcher::config::AppConfig;
    ///
    /// let mut config: AppConfig = serde_yaml::from_str(&AppConfig::example_yaml()?)?;
    /// config.config_path = PathBuf::from("/tmp/watcher/watcher.yml");
    /// assert_eq!(config.daemon_pid_path(), PathBuf::from("/tmp/watcher/watcher.pid"));
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn daemon_pid_path(&self) -> PathBuf {
        self.config_path
            .parent()
            .map(|parent| parent.join("watcher.pid"))
            .unwrap_or_else(|| PathBuf::from("watcher.pid"))
    }

    /// Expands the configured scan port set.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 升序且去重后的扫描端口列表.
    ///
    /// # Errors
    ///
    /// 端口预设不受支持, 或展开后列表为空时返回错误.
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::AppConfig;
    ///
    /// let config: AppConfig = serde_yaml::from_str(&AppConfig::example_yaml()?)?;
    /// assert!(config.scan_ports()?.contains(&80));
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn scan_ports(&self) -> anyhow::Result<Vec<u16>> {
        self.probe.scan_ports.expand()
    }

    /// Builds a default configuration with the specified config path.
    ///
    /// # 参数
    ///
    /// - `config_path`: 配置文件路径, 其父目录用于推导数据库和报告目录
    ///
    /// # 返回
    ///
    /// 填入内置默认值的 [`AppConfig`].
    ///
    /// # Errors
    ///
    /// `config_path` 没有父目录时返回错误.
    ///
    /// # 示例
    ///
    /// ```text
    /// let config = AppConfig::default_with_path(PathBuf::from("/tmp/watcher/watcher.yml"))?;
    /// ```
    pub(crate) fn default_with_path(config_path: PathBuf) -> anyhow::Result<Self> {
        let base = config_path
            .parent()
            .map(Path::to_path_buf)
            .context("config path has no parent")?;
        Ok(Self {
            config_path,
            database: DatabaseConfig {
                path: base.join("watcher.db"),
            },
            display: DisplayConfig::default(),
            scheduler: SchedulerConfig {
                interval_minutes: 360,
            },
            probe: ProbeConfig {
                connect_timeout_ms: 2000,
                http_timeout_ms: 8000,
                per_target_delay_ms: 1200,
                concurrency: 16,
                scan_ip_concurrency: default_scan_ip_concurrency(),
                scan_port_concurrency_per_ip: default_scan_port_concurrency_per_ip(),
                dns_servers: vec![],
                scan_ports: ScanPortsConfig::List(vec![
                    21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 3306,
                    3389, 5432, 6379, 7001, 8000, 8080, 8081, 8443, 9000, 9200, 9300, 10000, 27017,
                ]),
            },
            fingerprint: FingerprintConfig::default(),
            web: WebConfig {
                max_paths_per_service: 200,
                max_js_paths_per_service: 80,
                negative_body_markers: vec![
                    "接口不存在".to_string(),
                    "code=404".to_string(),
                    "\"code\":404".to_string(),
                    "'code':404".to_string(),
                ],
            },
            pocs: PocConfig::default(),
            report: ReportConfig {
                output_dir: base.join("reports"),
                format: ReportFormat::Xlsx,
            },
            email: EmailConfig {
                enabled: false,
                smtp_host: "smtp.example.com".to_string(),
                smtp_port: 587,
                smtp_security: default_smtp_security(),
                username: String::new(),
                password: String::new(),
                from: "watcher@example.com".to_string(),
                to: vec![],
            },
        })
    }

    /// Ensures configured filesystem directories exist.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 目录已存在或创建成功时返回 `()`.
    ///
    /// # Errors
    ///
    /// 无法创建数据库父目录或报告输出目录时返回错误.
    ///
    /// # 示例
    ///
    /// ```text
    /// config.ensure_dirs()?;
    /// ```
    fn ensure_dirs(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.database.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::create_dir_all(&self.report.output_dir)
            .with_context(|| format!("failed to create {}", self.report.output_dir.display()))?;
        Ok(())
    }
}

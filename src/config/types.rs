//! 配置结构体与枚举.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::defaults::{
    default_database_path, default_detailed_fingerprint_concurrency,
    default_detailed_fingerprint_timeout_ms, default_display_timezone, default_enabled,
    default_nmap_path, default_poc_max_js_files_per_url, default_poc_max_map_candidates_per_url,
    default_poc_max_urls_per_batch, default_scan_ip_concurrency,
    default_scan_port_concurrency_per_ip, default_smtp_security,
};

/// Runtime application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Actual configuration file path that was loaded.
    #[serde(skip)]
    pub config_path: std::path::PathBuf,
    /// SQLite database settings.
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Human-facing display settings.
    #[serde(default)]
    pub display: DisplayConfig,
    /// Scheduler settings.
    pub scheduler: SchedulerConfig,
    /// Network probing settings.
    pub probe: ProbeConfig,
    /// Service fingerprinting settings.
    #[serde(default)]
    pub fingerprint: FingerprintConfig,
    /// Web enumeration settings.
    pub web: WebConfig,
    /// Lightweight vulnerability POC settings.
    #[serde(default)]
    pub pocs: PocConfig,
    /// Report output settings.
    pub report: ReportConfig,
    /// Optional email notification settings.
    pub email: EmailConfig,
}

/// SQLite database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// SQLite database file path.
    #[serde(default = "default_database_path")]
    pub path: std::path::PathBuf,
}

impl Default for DatabaseConfig {
    /// 返回缺省数据库配置, 路径为 `~/.config/watcher/watcher.db`.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 使用默认数据库路径的 [`DatabaseConfig`].
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::DatabaseConfig;
    ///
    /// let config = DatabaseConfig::default();
    /// assert_eq!(
    ///     config.path,
    ///     std::path::PathBuf::from("~/.config/watcher/watcher.db")
    /// );
    /// ```
    fn default() -> Self {
        Self {
            path: default_database_path(),
        }
    }
}

/// Human-facing display configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayConfig {
    /// Timezone used when rendering logs, tasks, reports and emails. Examples: +08:00, UTC+8.
    #[serde(default = "default_display_timezone")]
    pub timezone: String,
}

impl Default for DisplayConfig {
    /// 返回缺省展示配置, 时区为 UTC+08:00.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 使用默认时区的 [`DisplayConfig`].
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::DisplayConfig;
    ///
    /// let config = DisplayConfig::default();
    /// assert_eq!(config.timezone, "+08:00");
    /// ```
    fn default() -> Self {
        Self {
            timezone: default_display_timezone(),
        }
    }
}

/// Scheduler configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    /// Interval between batch starts.
    pub interval_minutes: u64,
}

/// Network probing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    /// TCP connection timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// HTTP request timeout in milliseconds.
    pub http_timeout_ms: u64,
    /// Delay between requests to the same target.
    pub per_target_delay_ms: u64,
    /// General concurrency for non-port probing tasks.
    pub concurrency: usize,
    /// Number of IP addresses scanned at the same time during port scanning.
    #[serde(default = "default_scan_ip_concurrency")]
    pub scan_ip_concurrency: usize,
    /// Number of ports scanned at the same time for one IP during port scanning.
    #[serde(default = "default_scan_port_concurrency_per_ip")]
    pub scan_port_concurrency_per_ip: usize,
    /// DNS servers used by domain resolution. Empty means use the host/system resolver.
    #[serde(default, alias = "dns-server")]
    pub dns_servers: Vec<String>,
    /// Ports scanned for every real IP. Accepts a list of ports or `full`/`all`.
    pub scan_ports: ScanPortsConfig,
}

/// Port scan configuration. A YAML value can be either a list or a preset string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScanPortsConfig {
    /// Explicit TCP port list.
    List(Vec<u16>),
    /// Preset name. Supported values are `full` and `all`.
    Preset(String),
}

impl ScanPortsConfig {
    /// Expands the port configuration into an ordered, de-duplicated port list.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 升序且去重后的 TCP 端口列表.
    ///
    /// # Errors
    ///
    /// 预设名不受支持, 或展开后端口列表为空时返回错误.
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::ScanPortsConfig;
    ///
    /// let ports = ScanPortsConfig::List(vec![443, 80, 80]).expand()?;
    /// assert_eq!(ports, vec![80, 443]);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn expand(&self) -> anyhow::Result<Vec<u16>> {
        let mut ports = match self {
            Self::List(ports) => ports.clone(),
            Self::Preset(preset) => match preset.trim().to_ascii_lowercase().as_str() {
                "full" | "all" => (1..=u16::MAX).collect(),
                other => anyhow::bail!(
                    "unsupported scan_ports preset `{other}`; use a port list or `full`/`all`"
                ),
            },
        };
        ports.sort_unstable();
        ports.dedup();
        anyhow::ensure!(!ports.is_empty(), "scan_ports must not be empty");
        Ok(ports)
    }
}

/// Service fingerprinting configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FingerprintConfig {
    /// Detailed nmap-based service fingerprinting.
    #[serde(default)]
    pub detailed: DetailedFingerprintConfig,
}

/// Detailed fingerprinting powered by nmap service detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedFingerprintConfig {
    /// Enables nmap service detection when true.
    #[serde(default)]
    pub enabled: bool,
    /// nmap executable path or command name.
    #[serde(default = "default_nmap_path")]
    pub nmap_path: String,
    /// Per-port nmap timeout in milliseconds.
    #[serde(default = "default_detailed_fingerprint_timeout_ms")]
    pub timeout_ms: u64,
    /// Number of nmap probes running at the same time.
    #[serde(default = "default_detailed_fingerprint_concurrency")]
    pub concurrency: usize,
}

impl Default for DetailedFingerprintConfig {
    /// 返回缺省详细指纹配置, 默认关闭 nmap 探测.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 关闭状态的 [`DetailedFingerprintConfig`].
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::DetailedFingerprintConfig;
    ///
    /// let config = DetailedFingerprintConfig::default();
    /// assert!(!config.enabled);
    /// ```
    fn default() -> Self {
        Self {
            enabled: false,
            nmap_path: default_nmap_path(),
            timeout_ms: default_detailed_fingerprint_timeout_ms(),
            concurrency: default_detailed_fingerprint_concurrency(),
        }
    }
}

impl DetailedFingerprintConfig {
    /// Returns the per-port nmap timeout.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 至少 1000 毫秒的探测超时.
    ///
    /// # 示例
    ///
    /// ```
    /// use std::time::Duration;
    /// use watcher::config::DetailedFingerprintConfig;
    ///
    /// let config = DetailedFingerprintConfig::default();
    /// assert_eq!(config.timeout(), Duration::from_millis(30_000));
    /// ```
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.max(1_000))
    }

    /// Returns bounded nmap concurrency.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 限制在 `[1, 8]` 区间内的并发数.
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::DetailedFingerprintConfig;
    ///
    /// let config = DetailedFingerprintConfig::default();
    /// assert_eq!(config.concurrency(), 2);
    /// ```
    pub fn concurrency(&self) -> usize {
        self.concurrency.clamp(1, 8)
    }
}

/// Web enumeration configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    /// Maximum dictionary paths attempted per web service in one batch.
    pub max_paths_per_service: usize,
    /// Maximum JS-discovered URLs attempted per web service.
    pub max_js_paths_per_service: usize,
    /// Body markers that indicate fake gateway 200 pages.
    pub negative_body_markers: Vec<String>,
}

/// Lightweight vulnerability POC configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PocConfig {
    /// Detect exposed JavaScript source map files.
    #[serde(default)]
    pub webpack_sourcemap_disclosure: PocSwitchConfig,
}

/// Common on/off switch for one POC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocSwitchConfig {
    /// Enables this POC when true.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Maximum URL assets checked by this POC in one batch.
    #[serde(default = "default_poc_max_urls_per_batch")]
    pub max_urls_per_batch: usize,
    /// Maximum JavaScript files fetched for one URL.
    #[serde(default = "default_poc_max_js_files_per_url")]
    pub max_js_files_per_url: usize,
    /// Maximum source map candidates checked for one URL.
    #[serde(default = "default_poc_max_map_candidates_per_url")]
    pub max_map_candidates_per_url: usize,
}

impl Default for PocSwitchConfig {
    /// 返回缺省 POC 开关, 默认启用并使用内置批处理上限.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 启用状态的 [`PocSwitchConfig`].
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::PocSwitchConfig;
    ///
    /// let config = PocSwitchConfig::default();
    /// assert!(config.enabled);
    /// ```
    fn default() -> Self {
        Self {
            enabled: true,
            max_urls_per_batch: default_poc_max_urls_per_batch(),
            max_js_files_per_url: default_poc_max_js_files_per_url(),
            max_map_candidates_per_url: default_poc_max_map_candidates_per_url(),
        }
    }
}

impl PocSwitchConfig {
    /// Returns the bounded URL count checked by one POC batch.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 至少为 `1` 的 URL 批处理上限.
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::PocSwitchConfig;
    ///
    /// let config = PocSwitchConfig::default();
    /// assert_eq!(config.max_urls_per_batch(), 1_000);
    /// ```
    pub fn max_urls_per_batch(&self) -> usize {
        self.max_urls_per_batch.max(1)
    }

    /// Returns the bounded JavaScript fetch count for one URL.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 至少为 `1` 的 JS 拉取上限.
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::PocSwitchConfig;
    ///
    /// let config = PocSwitchConfig::default();
    /// assert_eq!(config.max_js_files_per_url(), 20);
    /// ```
    pub fn max_js_files_per_url(&self) -> usize {
        self.max_js_files_per_url.max(1)
    }

    /// Returns the bounded source map candidate count for one URL.
    ///
    /// # 参数
    ///
    /// 无
    ///
    /// # 返回
    ///
    /// 至少为 `1` 的 source map 候选上限.
    ///
    /// # 示例
    ///
    /// ```
    /// use watcher::config::PocSwitchConfig;
    ///
    /// let config = PocSwitchConfig::default();
    /// assert_eq!(config.max_map_candidates_per_url(), 20);
    /// ```
    pub fn max_map_candidates_per_url(&self) -> usize {
        self.max_map_candidates_per_url.max(1)
    }
}

/// Report output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Directory where report packages are created.
    pub output_dir: std::path::PathBuf,
    /// Detail report format: xlsx, json or csv.
    #[serde(default)]
    pub format: ReportFormat,
}

/// Detail report output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    /// One XLSX workbook containing all detail sheets.
    #[default]
    Xlsx,
    /// One JSON file containing all detail tables.
    Json,
    /// One CSV file per detail table.
    Csv,
}

/// Email notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// Enables SMTP notification when true.
    pub enabled: bool,
    /// SMTP server host.
    pub smtp_host: String,
    /// SMTP server port.
    pub smtp_port: u16,
    /// SMTP security mode: auto, tls, starttls, or none.
    #[serde(default = "default_smtp_security")]
    pub smtp_security: String,
    /// SMTP username.
    pub username: String,
    /// SMTP password.
    pub password: String,
    /// Sender address.
    pub from: String,
    /// Recipient addresses.
    pub to: Vec<String>,
}

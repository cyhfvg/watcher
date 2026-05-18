//! Configuration loading and defaults.

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::local_time;

/// Runtime application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Actual configuration file path that was loaded.
    #[serde(skip)]
    pub config_path: PathBuf,
    /// SQLite database settings.
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
    pub path: PathBuf,
}

/// Human-facing display configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayConfig {
    /// Timezone used when rendering logs, tasks, reports and emails. Examples: +08:00, UTC+8.
    #[serde(default = "default_display_timezone")]
    pub timezone: String,
}

impl Default for DisplayConfig {
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
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.max(1_000))
    }

    /// Returns bounded nmap concurrency.
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
    pub fn max_urls_per_batch(&self) -> usize {
        self.max_urls_per_batch.max(1)
    }

    /// Returns the bounded JavaScript fetch count for one URL.
    pub fn max_js_files_per_url(&self) -> usize {
        self.max_js_files_per_url.max(1)
    }

    /// Returns the bounded source map candidate count for one URL.
    pub fn max_map_candidates_per_url(&self) -> usize {
        self.max_map_candidates_per_url.max(1)
    }
}

/// Report output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Directory where report packages are created.
    pub output_dir: PathBuf,
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

impl AppConfig {
    /// Loads the default configuration file, creating it if it does not exist.
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
    pub fn example_yaml() -> anyhow::Result<String> {
        let example = Self::default_with_path(PathBuf::from("~/.config/watcher/watcher.yml"))?;
        Ok(serde_yaml::to_string(&example)?)
    }

    /// Returns the scheduler interval as a duration.
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.scheduler.interval_minutes.max(1) * 60)
    }

    /// Returns the TCP connect timeout as a duration.
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.probe.connect_timeout_ms.max(100))
    }

    /// Returns the number of IP addresses scanned concurrently.
    pub fn scan_ip_concurrency(&self) -> usize {
        self.probe.scan_ip_concurrency.max(1)
    }

    /// Returns the per-IP port scan concurrency.
    pub fn scan_port_concurrency_per_ip(&self) -> usize {
        self.probe.scan_port_concurrency_per_ip.max(1)
    }

    /// Returns the HTTP timeout as a duration.
    pub fn http_timeout(&self) -> Duration {
        Duration::from_millis(self.probe.http_timeout_ms.max(500))
    }

    /// Returns the per-target delay as a duration.
    pub fn per_target_delay(&self) -> Duration {
        Duration::from_millis(self.probe.per_target_delay_ms)
    }

    /// Returns the daemon PID file path.
    pub fn daemon_pid_path(&self) -> PathBuf {
        self.config_path
            .parent()
            .map(|parent| parent.join("watcher.pid"))
            .unwrap_or_else(|| PathBuf::from("watcher.pid"))
    }

    /// Expands the configured scan port set.
    pub fn scan_ports(&self) -> anyhow::Result<Vec<u16>> {
        self.probe.scan_ports.expand()
    }

    /// Builds a default configuration with the specified config path.
    fn default_with_path(config_path: PathBuf) -> anyhow::Result<Self> {
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

/// Default number of IPs scanned at the same time.
fn default_scan_ip_concurrency() -> usize {
    4
}

/// Default number of ports scanned at the same time for one IP.
fn default_scan_port_concurrency_per_ip() -> usize {
    4
}

/// Default display timezone: UTC+08:00.
fn default_display_timezone() -> String {
    local_time::DEFAULT_TIMEZONE.to_string()
}

/// Default POC switch value.
fn default_enabled() -> bool {
    true
}

/// Default maximum URL assets checked by one POC in one batch.
fn default_poc_max_urls_per_batch() -> usize {
    1_000
}

/// Default maximum JavaScript files fetched while checking one URL.
fn default_poc_max_js_files_per_url() -> usize {
    20
}

/// Default maximum source map candidates checked for one URL.
fn default_poc_max_map_candidates_per_url() -> usize {
    20
}

/// Default nmap executable used by detailed fingerprinting.
fn default_nmap_path() -> String {
    "nmap".to_string()
}

/// Default timeout for one detailed fingerprint probe.
fn default_detailed_fingerprint_timeout_ms() -> u64 {
    30_000
}

/// Default number of concurrent nmap probes.
fn default_detailed_fingerprint_concurrency() -> usize {
    2
}

/// Default SMTP security mode. `auto` maps 465 to TLS and 587 to STARTTLS.
fn default_smtp_security() -> String {
    "auto".to_string()
}

impl ScanPortsConfig {
    /// Expands the port configuration into an ordered, de-duplicated port list.
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

/// Returns the default config path.
fn default_config_path() -> anyhow::Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("failed to locate user config directory")?
        .join("watcher");
    Ok(dir.join("watcher.yml"))
}

/// Expands a leading `~` in a path.
fn expand_tilde(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .join(rest);
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_tilde_prefix() {
        let expanded = expand_tilde(Path::new("~/watcher.yml"));
        assert!(expanded.ends_with("watcher.yml"));
        assert!(!expanded.to_string_lossy().starts_with("~/"));
    }

    #[test]
    fn expands_full_scan_ports() {
        let ports = ScanPortsConfig::Preset("full".to_string())
            .expand()
            .unwrap();
        assert_eq!(ports.len(), 65_535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65_534], 65_535);
    }

    #[test]
    fn keeps_list_scan_ports_sorted_and_unique() {
        let ports = ScanPortsConfig::List(vec![443, 80, 80]).expand().unwrap();
        assert_eq!(ports, vec![80, 443]);
    }

    #[test]
    fn defaults_dns_servers_to_system_resolver() {
        let probe: ProbeConfig = serde_yaml::from_str(
            r#"
connect_timeout_ms: 2000
http_timeout_ms: 8000
per_target_delay_ms: 1200
concurrency: 16
scan_ports:
  - 80
"#,
        )
        .unwrap();
        assert!(probe.dns_servers.is_empty());
        assert_eq!(probe.scan_ip_concurrency, 4);
        assert_eq!(probe.scan_port_concurrency_per_ip, 4);
    }

    #[test]
    fn defaults_report_format_to_xlsx() {
        let report: ReportConfig = serde_yaml::from_str(
            r#"
output_dir: /tmp/watcher-reports
"#,
        )
        .unwrap();
        assert_eq!(report.format, ReportFormat::Xlsx);
    }

    #[test]
    fn defaults_display_timezone_to_east_8() {
        let display: DisplayConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(display.timezone, "+08:00");
        assert!(local_time::parse_timezone(&display.timezone).is_ok());
    }

    #[test]
    fn defaults_pocs_to_enabled() {
        let pocs: PocConfig = serde_yaml::from_str("{}").unwrap();
        assert!(pocs.webpack_sourcemap_disclosure.enabled);
        assert_eq!(pocs.webpack_sourcemap_disclosure.max_urls_per_batch, 1_000);
        assert_eq!(pocs.webpack_sourcemap_disclosure.max_js_files_per_url, 20);
        assert_eq!(
            pocs.webpack_sourcemap_disclosure.max_map_candidates_per_url,
            20
        );
    }

    #[test]
    fn defaults_detailed_fingerprint_to_disabled() {
        let fingerprint: FingerprintConfig = serde_yaml::from_str("{}").unwrap();
        assert!(!fingerprint.detailed.enabled);
        assert_eq!(fingerprint.detailed.nmap_path, "nmap");
        assert_eq!(fingerprint.detailed.timeout_ms, 30_000);
        assert_eq!(fingerprint.detailed.concurrency, 2);
    }

    #[test]
    fn parses_enabled_detailed_fingerprint() {
        let fingerprint: FingerprintConfig = serde_yaml::from_str(
            r#"
detailed:
  enabled: true
  nmap_path: /usr/bin/nmap
  timeout_ms: 60000
  concurrency: 4
"#,
        )
        .unwrap();
        assert!(fingerprint.detailed.enabled);
        assert_eq!(fingerprint.detailed.nmap_path, "/usr/bin/nmap");
        assert_eq!(fingerprint.detailed.timeout_ms, 60_000);
        assert_eq!(fingerprint.detailed.concurrency(), 4);
    }

    #[test]
    fn parses_disabled_poc() {
        let pocs: PocConfig = serde_yaml::from_str(
            r#"
webpack_sourcemap_disclosure:
  enabled: false
  max_urls_per_batch: 50
  max_js_files_per_url: 5
  max_map_candidates_per_url: 3
"#,
        )
        .unwrap();
        assert!(!pocs.webpack_sourcemap_disclosure.enabled);
        assert_eq!(pocs.webpack_sourcemap_disclosure.max_urls_per_batch(), 50);
        assert_eq!(pocs.webpack_sourcemap_disclosure.max_js_files_per_url(), 5);
        assert_eq!(
            pocs.webpack_sourcemap_disclosure
                .max_map_candidates_per_url(),
            3
        );
    }

    #[test]
    fn parses_report_formats() {
        let report: ReportConfig = serde_yaml::from_str(
            r#"
output_dir: /tmp/watcher-reports
format: json
"#,
        )
        .unwrap();
        assert_eq!(report.format, ReportFormat::Json);
    }

    #[test]
    fn accepts_dns_server_alias() {
        let probe: ProbeConfig = serde_yaml::from_str(
            r#"
connect_timeout_ms: 2000
http_timeout_ms: 8000
per_target_delay_ms: 1200
concurrency: 16
dns-server:
  - 8.8.8.8
scan_ports:
  - 80
"#,
        )
        .unwrap();
        assert_eq!(probe.dns_servers, vec!["8.8.8.8"]);
    }
}

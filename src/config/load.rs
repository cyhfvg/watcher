//! Configuration loading and runtime accessors.

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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// An [`AppConfig`] with paths expanded, the display timezone validated,
    /// and required directories created.
    ///
    /// # Errors
    ///
    /// Returns an error when the default config path cannot be located, a
    /// parent directory cannot be created, YAML cannot be written or read,
    /// the config cannot be parsed, the display timezone is invalid, or the
    /// database/report directories cannot be created.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// YAML text generated from the default paths.
    ///
    /// # Errors
    ///
    /// Returns an error when constructing the default config or serializing it
    /// to YAML fails.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// A scheduler interval of at least 1 minute.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// A TCP connect timeout of at least 100 milliseconds.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// An IP-scan concurrency of at least `1`.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// A per-IP port-scan concurrency of at least `1`.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// An HTTP timeout of at least 500 milliseconds.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// HTTP concurrency clamped to the `[1, 8]` range.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// The delay between consecutive requests to the same target.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// `watcher.pid` next to the config file; falls back to `watcher.pid` in
    /// the current directory when the config path has no parent.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// An ascending, de-duplicated scan-port list.
    ///
    /// # Errors
    ///
    /// Returns an error when the port preset is unsupported or the expanded
    /// list is empty.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// - `config_path`: config file path; its parent is used to derive the
    ///   database and report directories
    ///
    /// # Returns
    ///
    /// An [`AppConfig`] filled with built-in defaults.
    ///
    /// # Errors
    ///
    /// Returns an error when `config_path` has no parent directory.
    ///
    /// # Examples
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
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// `()` when the directories already exist or were created.
    ///
    /// # Errors
    ///
    /// Returns an error when the database parent directory or the report
    /// output directory cannot be created.
    ///
    /// # Examples
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

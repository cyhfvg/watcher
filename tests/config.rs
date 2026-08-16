//! Public configuration contract tests.

use std::path::PathBuf;

use watcher::config::{
    AppConfig, DisplayConfig, FingerprintConfig, PocConfig, ProbeConfig, ReportConfig,
    ReportFormat, ScanPortsConfig,
};
use watcher::local_time;

#[test]
fn defaults_database_path_when_config_section_is_missing() {
    let config: AppConfig = serde_yaml::from_str(
        r#"
scheduler:
  interval_minutes: 360
probe:
  connect_timeout_ms: 2000
  http_timeout_ms: 8000
  per_target_delay_ms: 1200
  concurrency: 16
  scan_ports:
    - 80
web:
  max_paths_per_service: 200
  max_js_paths_per_service: 80
  negative_body_markers: []
report:
  output_dir: ~/.config/watcher/reports
email:
  enabled: false
  smtp_host: smtp.example.com
  smtp_port: 587
  username: ""
  password: ""
  from: ""
  to: []
"#,
    )
    .unwrap();

    assert_eq!(
        config.database.path,
        PathBuf::from("~/.config/watcher/watcher.db")
    );
}

#[test]
fn bounds_http_concurrency_for_all_http_monitoring_stages() {
    let mut config: AppConfig = serde_yaml::from_str(
        r#"
scheduler:
  interval_minutes: 1
probe:
  connect_timeout_ms: 2000
  http_timeout_ms: 8000
  per_target_delay_ms: 0
  concurrency: 100
  scan_ports: [80]
web:
  max_paths_per_service: 1
  max_js_paths_per_service: 1
  negative_body_markers: []
report:
  output_dir: /tmp/watcher-reports
email:
  enabled: false
  smtp_host: smtp.example.com
  smtp_port: 587
  username: ""
  password: ""
  from: ""
  to: []
"#,
    )
    .unwrap();
    assert_eq!(config.http_concurrency(), 8);

    config.probe.concurrency = 0;
    assert_eq!(config.http_concurrency(), 1);
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

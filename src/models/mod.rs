//! Shared data models used across storage, probes and reports.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Domain asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainAsset {
    /// Domain row id.
    pub id: String,
    /// Owning business system id.
    pub system_id: String,
    /// Owning business system name.
    pub system_name: String,
    /// Domain name.
    pub name: String,
    /// Expected or last resolved IP addresses.
    pub bind_ip: Option<String>,
    /// Whether this asset belongs to the imported baseline.
    pub is_baseline: bool,
}

/// IP asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAsset {
    /// IP row id.
    pub id: String,
    /// Owning business system id.
    pub system_id: String,
    /// Owning business system name.
    pub system_name: String,
    /// IP address.
    pub ip: String,
    /// Source label such as imported, resolved or manual.
    pub source: String,
    /// Whether this asset belongs to the imported baseline.
    pub is_baseline: bool,
}

/// Port asset and service fingerprint state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAsset {
    /// Port row id.
    pub id: String,
    /// Owning business system id.
    pub system_id: String,
    /// Owning business system name.
    pub system_name: String,
    /// Optional IP row id.
    pub ip_id: Option<String>,
    /// IP address when the port is bound to one.
    pub ip: Option<String>,
    /// TCP port number.
    pub port: u16,
    /// Current port state.
    pub state: String,
    /// Service label.
    pub service: Option<String>,
    /// Human-readable fingerprint details.
    pub fingerprint: Option<String>,
    /// Whether the service was identified as HTTP(S).
    pub is_web: bool,
    /// `http` or `https` for web services.
    pub scheme: Option<String>,
    /// Whether this asset belongs to the imported baseline.
    pub is_baseline: bool,
}

/// Compact per-IP port scan summary stored instead of per-port scan logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanSummary {
    /// Summary row id.
    pub id: String,
    /// Batch that produced this scan.
    pub batch_id: String,
    /// Owning business system id.
    pub system_id: Option<String>,
    /// IP asset id when the scan targeted a stored IP.
    pub ip_id: Option<String>,
    /// Scanned IP address.
    pub ip: String,
    /// Number of TCP ports probed.
    pub probed_ports: i64,
    /// Number of ports found open in this scan.
    pub open_count: i64,
    /// Compact list of newly opened ports.
    pub opened_ports: Option<String>,
    /// Compact list of newly closed ports.
    pub closed_ports: Option<String>,
    /// Creation time.
    pub created_at: String,
}

/// URL asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlAsset {
    /// URL row id.
    pub id: String,
    /// Owning business system id.
    pub system_id: String,
    /// Owning business system name.
    pub system_name: String,
    /// Absolute URL.
    pub url: String,
    /// Source label such as imported, discovered or vuln.
    pub source: String,
    /// Latest HTTP status code.
    pub status_code: Option<u16>,
    /// Value score used by reports.
    pub value_score: i64,
    /// Whether this asset belongs to the imported baseline.
    pub is_baseline: bool,
}

/// Monitoring batch row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRow {
    /// Batch id.
    pub id: String,
    /// Batch status.
    pub status: String,
    /// RFC3339 start time.
    pub started_at: String,
    /// RFC3339 end time.
    pub ended_at: Option<String>,
    /// Report zip path.
    pub report_zip: Option<String>,
}

/// Expanded batch status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchStatus {
    /// Batch id.
    pub batch_id: String,
    /// Batch status.
    pub status: String,
    /// RFC3339 start time.
    pub started_at: String,
    /// RFC3339 end time.
    pub ended_at: Option<String>,
    /// Alert count in this batch.
    pub alerts: i64,
    /// Vulnerability count in this batch.
    pub vulnerabilities: i64,
}

/// Application log row stored in SQLite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRow {
    /// Log row id.
    pub id: String,
    /// RFC3339 creation time.
    pub created_at: String,
    /// Log level.
    pub level: String,
    /// Tracing target/module path.
    pub target: String,
    /// Main message.
    pub message: String,
    /// Additional structured fields as JSON.
    pub fields: Option<String>,
}

/// Alert record created when watcher detects a relevant change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert id.
    pub id: String,
    /// Batch id.
    pub batch_id: String,
    /// Optional system id.
    pub system_id: Option<String>,
    /// Optional human-readable business system name.
    pub system_name: Option<String>,
    /// Alert kind.
    pub kind: String,
    /// Alert severity.
    pub severity: String,
    /// Alert subject.
    pub subject: String,
    /// Old value.
    pub old_value: Option<String>,
    /// New value.
    pub new_value: Option<String>,
    /// JSON details.
    pub details: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Finding id.
    pub id: String,
    /// Batch id.
    pub batch_id: String,
    /// Owning system id.
    pub system_id: String,
    /// Human-readable business system name.
    pub system_name: String,
    /// URL affected by the finding.
    pub url: String,
    /// POC identifier.
    pub poc: String,
    /// Severity.
    pub severity: String,
    /// Evidence summary.
    pub evidence: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Monitoring batch execution context.
#[derive(Debug, Clone)]
pub struct BatchContext {
    /// Batch id.
    pub id: String,
    /// Batch start time.
    pub started_at: DateTime<Utc>,
}

/// Aggregated data displayed by the terminal dashboard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    /// RFC3339 timestamp at which the snapshot was created.
    pub generated_at: String,
    /// Current asset inventory totals.
    pub assets: DashboardAssetCounts,
    /// Latest batch, when at least one batch has been created.
    pub latest_batch: Option<DashboardBatch>,
    /// Per-stage state for the latest batch.
    pub stages: Vec<DashboardStage>,
    /// Carry-over work queue state.
    pub queue: DashboardQueueCounts,
    /// Alert severities for the latest batch.
    pub alert_severity: DashboardSeverityCounts,
    /// Most recent alerts across all batches.
    pub recent_alerts: Vec<DashboardAlert>,
}

/// Asset inventory counters for the dashboard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardAssetCounts {
    /// Business system count.
    pub systems: i64,
    /// Domain asset count.
    pub domains: i64,
    /// IP asset count.
    pub ips: i64,
    /// TCP port asset count.
    pub ports: i64,
    /// Currently open TCP port count.
    pub open_ports: i64,
    /// Identified web service count.
    pub web_services: i64,
    /// URL asset count.
    pub urls: i64,
    /// Imported baseline asset count across core asset tables.
    pub baseline_assets: i64,
    /// Path dictionary entry count.
    pub dictionary_paths: i64,
}

/// Latest monitoring batch summary shown by the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardBatch {
    /// Batch identifier.
    pub id: String,
    /// Current batch status.
    pub status: String,
    /// RFC3339 start timestamp.
    pub started_at: String,
    /// Optional RFC3339 completion timestamp.
    pub ended_at: Option<String>,
    /// Alert count for this batch.
    pub alerts: i64,
    /// Vulnerability count for this batch.
    pub vulnerabilities: i64,
}

/// One pipeline stage state for a monitoring batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStage {
    /// Stable stage identifier.
    pub stage: String,
    /// Stage state such as running, completed, or failed.
    pub status: String,
    /// RFC3339 start timestamp.
    pub started_at: String,
    /// Optional RFC3339 completion timestamp.
    pub ended_at: Option<String>,
    /// Optional error or warning detail.
    pub detail: Option<String>,
}

/// Pending work queue counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardQueueCounts {
    /// Work items not started yet.
    pub pending: i64,
    /// Work items currently replaying.
    pub running: i64,
    /// Work items completed and retained for audit.
    pub done: i64,
}

/// Alert counters grouped by importance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardSeverityCounts {
    /// Critical alerts.
    pub critical: i64,
    /// High-severity alerts.
    pub high: i64,
    /// Medium-severity alerts.
    pub medium: i64,
    /// Low-severity alerts.
    pub low: i64,
    /// Other or unclassified alerts.
    pub other: i64,
}

/// Compact recent-alert row for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardAlert {
    /// Alert severity.
    pub severity: String,
    /// Alert category.
    pub kind: String,
    /// Affected subject.
    pub subject: String,
    /// Optional business system name.
    pub system_name: Option<String>,
    /// RFC3339 creation timestamp.
    pub created_at: String,
}

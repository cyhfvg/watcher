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

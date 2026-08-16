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

/// Optional filters used by inventory and MCP queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetQuery {
    /// Exact business-system name.
    #[serde(default)]
    pub system: Option<String>,
    /// Case-insensitive LIKE keyword.
    #[serde(default)]
    pub keyword: Option<String>,
    /// Maximum rows to return in this page.
    #[serde(default)]
    pub limit: usize,
    /// Number of matching rows to skip.
    #[serde(default)]
    pub offset: usize,
}

impl Default for AssetQuery {
    fn default() -> Self {
        Self {
            system: None,
            keyword: None,
            limit: DEFAULT_ASSET_QUERY_LIMIT,
            offset: 0,
        }
    }
}

/// Default inventory page size for MCP and library callers.
pub const DEFAULT_ASSET_QUERY_LIMIT: usize = 50;

/// Hard cap that keeps a single MCP/list call bounded.
pub const MAX_ASSET_QUERY_LIMIT: usize = 200;

impl AssetQuery {
    /// Trim empty filters and clamp `limit` into the supported range.
    ///
    /// # Arguments
    /// - none. Operates on `self`.
    ///
    /// # Returns
    /// Sanitized query. Empty strings become `None`. A zero limit becomes
    /// [`DEFAULT_ASSET_QUERY_LIMIT`]. Limits above [`MAX_ASSET_QUERY_LIMIT`]
    /// are clamped. `offset` is kept as-is.
    ///
    /// # Examples
    /// ```
    /// # use watcher::models::AssetQuery;
    /// let query = AssetQuery {
    ///     system: Some("  core  ".into()),
    ///     keyword: Some(String::new()),
    ///     limit: 0,
    ///     offset: 10,
    /// }
    /// .sanitized();
    /// assert_eq!(query.system.as_deref(), Some("core"));
    /// assert_eq!(query.keyword, None);
    /// assert_eq!(query.limit, 50);
    /// assert_eq!(query.offset, 10);
    /// ```
    pub fn sanitized(self) -> Self {
        self.sanitize(DEFAULT_ASSET_QUERY_LIMIT)
    }

    /// Sanitize filters using a caller-specific default page size.
    ///
    /// # Arguments
    /// - `default_limit`: Page size used when `limit` is zero.
    ///
    /// # Returns
    /// Sanitized query with `limit` clamped to [`MAX_ASSET_QUERY_LIMIT`].
    ///
    /// # Examples
    /// ```
    /// # use watcher::models::AssetQuery;
    /// let query = AssetQuery { limit: 0, ..AssetQuery::default() }.sanitize(20);
    /// assert_eq!(query.limit, 20);
    /// ```
    pub fn sanitize(self, default_limit: usize) -> Self {
        Self {
            system: trim_filter(self.system),
            keyword: trim_filter(self.keyword),
            limit: match self.limit {
                0 => default_limit.min(MAX_ASSET_QUERY_LIMIT),
                limit => limit.min(MAX_ASSET_QUERY_LIMIT),
            },
            offset: self.offset,
        }
    }
}

/// One page of inventory rows plus enough metadata to fetch the next page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetPage<T> {
    /// Rows in this page.
    pub items: Vec<T>,
    /// Total matching rows across all pages.
    pub total: i64,
    /// Requested offset.
    pub offset: usize,
    /// Requested page size.
    pub limit: usize,
    /// Whether more rows exist after this page.
    pub has_more: bool,
    /// Offset to request next, when [`Self::has_more`] is true.
    pub next_offset: Option<usize>,
}

impl<T> AssetPage<T> {
    /// Build a page from rows and the matching total.
    ///
    /// # Arguments
    /// - `items`: Rows returned for this offset/limit.
    /// - `total`: Total matching rows.
    /// - `offset`: Requested offset.
    /// - `limit`: Requested page size.
    ///
    /// # Returns
    /// Page with `has_more` / `next_offset` derived from `total`.
    ///
    /// # Examples
    /// ```
    /// # use watcher::models::AssetPage;
    /// let page = AssetPage::new(vec!["a", "b"], 5, 0, 2);
    /// assert!(page.has_more);
    /// assert_eq!(page.next_offset, Some(2));
    /// ```
    pub fn new(items: Vec<T>, total: i64, offset: usize, limit: usize) -> Self {
        let consumed = offset.saturating_add(items.len());
        let has_more = i64::try_from(consumed).is_ok_and(|consumed| consumed < total);
        Self {
            items,
            total,
            offset,
            limit,
            has_more,
            next_offset: has_more.then_some(consumed),
        }
    }

    /// Empty page that still reports the requested window.
    ///
    /// # Arguments
    /// - `query`: Sanitized query whose offset/limit should be echoed.
    ///
    /// # Returns
    /// Page with `total = 0` and no items.
    ///
    /// # Examples
    /// ```
    /// # use watcher::models::{AssetPage, AssetQuery};
    /// let page = AssetPage::<u8>::empty(&AssetQuery::default());
    /// assert!(page.items.is_empty());
    /// assert!(!page.has_more);
    /// ```
    pub fn empty(query: &AssetQuery) -> Self {
        Self::new(Vec::new(), 0, query.offset, query.limit)
    }
}

/// Business-system inventory counts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemSummary {
    /// Business system name.
    pub name: String,
    /// Domain count.
    pub names: i64,
    /// IP count.
    pub ips: i64,
    /// Port count.
    pub ports: i64,
    /// URL count.
    pub urls: i64,
    /// Baseline domain count.
    pub baseline_names: i64,
    /// Baseline IP count.
    pub baseline_ips: i64,
    /// Baseline port count.
    pub baseline_ports: i64,
    /// Baseline URL count.
    pub baseline_urls: i64,
    /// RFC3339 creation time.
    pub created_at: String,
}

/// Confirmed-live inventory used by MCP and pentest planning prompts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveInventory {
    /// Dashboard counters and latest-batch status.
    pub snapshot: DashboardSnapshot,
    /// Matching business systems.
    pub systems: AssetPage<SystemSummary>,
    /// Currently open TCP ports.
    pub live_ports: AssetPage<PortAsset>,
    /// Open ports identified as HTTP(S).
    pub web_services: AssetPage<PortAsset>,
    /// URLs with a 2xx/3xx status from the latest probe.
    pub live_urls: AssetPage<UrlAsset>,
}

/// One business system's live, web, and finding context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemContext {
    /// System counts.
    pub system: SystemSummary,
    /// Domains owned by the system.
    pub names: AssetPage<DomainAsset>,
    /// IP addresses owned by the system.
    pub ips: AssetPage<IpAsset>,
    /// Currently open TCP ports.
    pub live_ports: AssetPage<PortAsset>,
    /// Open HTTP(S) services.
    pub web_services: AssetPage<PortAsset>,
    /// Live URLs (HTTP 2xx/3xx).
    pub live_urls: AssetPage<UrlAsset>,
    /// Latest-batch alerts for this system.
    pub alerts: AssetPage<Alert>,
    /// Latest-batch vulnerabilities for this system.
    pub vulnerabilities: AssetPage<Vulnerability>,
}

/// Trim and drop empty optional filter strings.
///
/// # Arguments
/// - `value`: Optional raw filter.
///
/// # Returns
/// Trimmed non-empty string, otherwise `None`.
///
/// # Examples
/// ```
/// # use watcher::models::trim_filter;
/// assert_eq!(trim_filter(Some("  core ".into())).as_deref(), Some("core"));
/// assert_eq!(trim_filter(Some("   ".into())), None);
/// ```
pub fn trim_filter(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

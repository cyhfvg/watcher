//! Shared helper functions used inside the database module.

use std::collections::HashMap;

use chrono::Utc;
use rusqlite::{Connection, Row, params};
use uuid::Uuid;

use crate::models::{BatchRow, IpAsset, LogRow, PortAsset, UrlAsset};

/// Collect every result row from a rusqlite statement.
///
/// # Arguments
/// - `stmt`: Prepared query statement.
/// - `params`: Bind parameters.
/// - `map`: Map one row to the target type.
///
/// # Returns
/// All mapped rows.
///
/// # Errors
/// Returns an error if query execution or row mapping fails.
///
/// # Examples
/// ```text
/// let rows = collect_rows(&mut stmt, [], |row| Ok(row.get::<_, String>(0)?))?;
/// ```
pub(crate) fn collect_rows<T, P, F>(
    stmt: &mut rusqlite::Statement<'_>,
    params: P,
    mut map: F,
) -> anyhow::Result<Vec<T>>
where
    P: rusqlite::Params,
    F: FnMut(&Row<'_>) -> anyhow::Result<T>,
{
    let mut rows = stmt.query(params)?;
    let mut values = Vec::new();
    while let Some(row) = rows.next()? {
        values.push(map(row)?);
    }
    Ok(values)
}

/// Insert an alert using an existing connection or transaction.
///
/// # Arguments
/// - `conn`: Connection or transaction.
/// - `batch_id`: Owning batch.
/// - `system_id`: Optional business system.
/// - `kind`: Alert kind.
/// - `severity`: Severity.
/// - `subject`: Alert subject.
/// - `old_value`: Value before the change.
/// - `new_value`: Value after the change.
/// - `details`: Extra JSON/text.
///
/// # Returns
/// none
///
/// # Errors
/// Returns an error if `INSERT` fails.
///
/// # Examples
/// ```text
/// insert_alert_in_tx(&tx, batch_id, Some(system_id), "port_change", "high", ip, None, None, None)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub(crate) fn insert_alert_in_tx(
    conn: &Connection,
    batch_id: &str,
    system_id: Option<&str>,
    kind: &str,
    severity: &str,
    subject: &str,
    old_value: Option<&str>,
    new_value: Option<&str>,
    details: Option<&str>,
) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO alerts (id, batch_id, system_id, kind, severity, subject, old_value, new_value, details, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            new_id(),
            batch_id,
            system_id,
            kind,
            severity,
            subject,
            old_value,
            new_value,
            details,
            now()
        ],
    )?;
    Ok(())
}

/// Serialize changed ports into one IP-level alert detail payload.
///
/// # Arguments
/// - `ports`: Changed-port list.
///
/// # Returns
/// JSON string with `count` and `ports`.
///
/// # Examples
/// ```text
/// let details = port_change_details(&[80, 443]);
/// ```
pub(crate) fn port_change_details(ports: &[u16]) -> String {
    serde_json::json!({
        "count": ports.len(),
        "ports": ports,
    })
    .to_string()
}

/// Compact a port list into comma-separated scan-summary text.
///
/// # Arguments
/// - `ports`: Port list.
///
/// # Returns
/// Returns `None` for an empty list, otherwise `"80,443"` form.
///
/// # Examples
/// ```text
/// assert_eq!(compact_port_list(&[80, 443]).as_deref(), Some("80,443"));
/// ```
pub(crate) fn compact_port_list(ports: &[u16]) -> Option<String> {
    if ports.is_empty() {
        None
    } else {
        Some(
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

/// Insert or return an existing business-system id inside a transaction.
///
/// # Arguments
/// - `tx`: Current transaction.
/// - `name`: Business system name.
///
/// # Returns
/// System primary key.
///
/// # Errors
/// Returns an error if the insert or lookup fails.
///
/// # Examples
/// ```text
/// let system_id = ensure_system_in_tx(&tx, "core")?;
/// ```
pub(crate) fn ensure_system_in_tx(
    tx: &rusqlite::Transaction<'_>,
    name: &str,
) -> anyhow::Result<String> {
    tx.execute(
        "INSERT OR IGNORE INTO systems (id, name, created_at) VALUES (?1, ?2, ?3)",
        params![new_id(), name, now()],
    )?;
    Ok(
        tx.query_row("SELECT id FROM systems WHERE name = ?1", [name], |row| {
            row.get(0)
        })?,
    )
}

/// Look up a system id from the import cache, inserting and backfilling the cache on a miss.
///
/// # Arguments
/// - `cache`: Local name-to-id cache.
/// - `select_system`: `SELECT id FROM systems WHERE name = ?1`.
/// - `insert_system`: `INSERT OR IGNORE INTO systems ...`.
/// - `name`: Business system name.
///
/// # Returns
/// System primary key.
///
/// # Errors
/// Returns an error if statement execution or the lookup fails.
///
/// # Examples
/// ```text
/// let system_id = cached_system_id(&mut cache, &mut select_system, &mut insert_system, "core")?;
/// ```
pub(crate) fn cached_system_id(
    cache: &mut HashMap<String, String>,
    select_system: &mut rusqlite::Statement<'_>,
    insert_system: &mut rusqlite::Statement<'_>,
    name: &str,
) -> anyhow::Result<String> {
    if let Some(id) = cache.get(name) {
        return Ok(id.clone());
    }
    insert_system.execute(params![new_id(), name, now()])?;
    let id = select_system.query_row([name], |row| row.get::<_, String>(0))?;
    cache.insert(name.to_string(), id.clone());
    Ok(id)
}

/// Trim optional text; treat an empty string as missing.
///
/// # Arguments
/// - `value`: Optional raw text.
///
/// # Returns
/// Trimmed non-empty slice, otherwise `None`.
///
/// # Examples
/// ```text
/// assert_eq!(trimmed_opt(Some("  a  ")), Some("a"));
/// ```
pub(crate) fn trimmed_opt(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// Map a query row to [`BatchRow`].
///
/// # Arguments
/// - `row`: Batch query row.
///
/// # Returns
/// Batch record.
///
/// # Errors
/// Returns a rusqlite error if a column type does not match.
///
/// # Examples
/// ```text
/// let batch = conn.query_row(sql, [], map_batch)?;
/// ```
pub(crate) fn map_batch(row: &Row<'_>) -> rusqlite::Result<BatchRow> {
    Ok(BatchRow {
        id: row.get(0)?,
        status: row.get(1)?,
        started_at: row.get(2)?,
        ended_at: row.get(3)?,
        report_zip: row.get(4)?,
    })
}

/// Map a query row to [`IpAsset`].
///
/// # Arguments
/// - `row`: IP-asset query row.
///
/// # Returns
/// IP asset.
///
/// # Errors
/// Returns a rusqlite error if a column type does not match.
///
/// # Examples
/// ```text
/// collect_rows(&mut stmt, [], |row| Ok(map_ip(row)?))
/// ```
pub(crate) fn map_ip(row: &Row<'_>) -> rusqlite::Result<IpAsset> {
    Ok(IpAsset {
        id: row.get(0)?,
        system_id: row.get(1)?,
        system_name: row.get(2)?,
        ip: row.get(3)?,
        source: row.get(4)?,
        is_baseline: row.get::<_, i64>(5)? == 1,
    })
}

/// Map a query row to [`PortAsset`].
///
/// # Arguments
/// - `row`: Port-asset query row.
///
/// # Returns
/// Port asset.
///
/// # Errors
/// Returns a rusqlite error if a column type does not match.
///
/// # Examples
/// ```text
/// collect_rows(&mut stmt, [], |row| Ok(map_port(row)?))
/// ```
pub(crate) fn map_port(row: &Row<'_>) -> rusqlite::Result<PortAsset> {
    Ok(PortAsset {
        id: row.get(0)?,
        system_id: row.get(1)?,
        system_name: row.get(2)?,
        ip_id: row.get(3)?,
        ip: row.get(4)?,
        port: row.get::<_, i64>(5)? as u16,
        state: row.get(6)?,
        service: row.get(7)?,
        fingerprint: row.get(8)?,
        is_web: row.get::<_, i64>(9)? == 1,
        scheme: row.get(10)?,
        is_baseline: row.get::<_, i64>(11)? == 1,
    })
}

/// Map a query row to [`UrlAsset`].
///
/// # Arguments
/// - `row`: URL-asset query row.
///
/// # Returns
/// URL asset.
///
/// # Errors
/// Returns a rusqlite error if a column type does not match.
///
/// # Examples
/// ```text
/// collect_rows(&mut stmt, [], |row| Ok(map_url(row)?))
/// ```
pub(crate) fn map_url(row: &Row<'_>) -> rusqlite::Result<UrlAsset> {
    Ok(UrlAsset {
        id: row.get(0)?,
        system_id: row.get(1)?,
        system_name: row.get(2)?,
        url: row.get(3)?,
        source: row.get(4)?,
        status_code: row.get::<_, Option<i64>>(5)?.map(|v| v as u16),
        value_score: row.get(6)?,
        is_baseline: row.get::<_, i64>(7)? == 1,
    })
}

/// Map a query row to [`LogRow`].
///
/// # Arguments
/// - `row`: Application-log query row.
///
/// # Returns
/// Log record.
///
/// # Errors
/// Returns an error if a column cannot be read.
///
/// # Examples
/// ```text
/// collect_rows(&mut stmt, params, map_log)
/// ```
pub(crate) fn map_log(row: &Row<'_>) -> anyhow::Result<LogRow> {
    Ok(LogRow {
        id: row.get(0)?,
        created_at: row.get(1)?,
        level: row.get(2)?,
        target: row.get(3)?,
        message: row.get(4)?,
        fields: row.get(5)?,
    })
}

/// Generate a new UUID string.
///
/// # Arguments
/// none
///
/// # Returns
/// New primary key.
///
/// # Examples
/// ```text
/// let id = new_id();
/// ```
pub(crate) fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// Return the current UTC time as RFC3339 text.
///
/// # Arguments
/// none
///
/// # Returns
/// RFC3339 timestamp.
///
/// # Examples
/// ```text
/// let ts = now();
/// ```
pub(crate) fn now() -> String {
    Utc::now().to_rfc3339()
}

/// Normalize a dictionary path: trim whitespace and add a leading `/`.
///
/// # Arguments
/// - `path`: Raw path.
///
/// # Returns
/// Normalized path; blank input returns an empty string.
///
/// # Examples
/// ```text
/// assert_eq!(normalize_path("admin"), "/admin");
/// ```
pub(crate) fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Render a boolean as table-output `true`/`false`.
///
/// # Arguments
/// - `value`: Boolean value.
///
/// # Returns
/// `"true"` or `"false"`.
///
/// # Examples
/// ```text
/// assert_eq!(bool_text(true), "true");
/// ```
pub(crate) fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

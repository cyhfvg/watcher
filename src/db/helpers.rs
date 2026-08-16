//! 数据库模块内部共享辅助函数.

use std::collections::HashMap;

use chrono::Utc;
use rusqlite::{Connection, Row, params};
use uuid::Uuid;

use crate::models::{BatchRow, IpAsset, LogRow, PortAsset, UrlAsset};

/// 收集 rusqlite 语句的全部结果行.
///
/// # 参数
/// - `stmt`: 已 prepare 的查询语句.
/// - `params`: 绑定参数.
/// - `map`: 将一行映射为目标类型.
///
/// # 返回
/// 映射后的全部行.
///
/// # Errors
/// 查询执行失败或行映射失败时返回错误.
///
/// # 示例
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

/// 使用已有连接或事务插入一条告警.
///
/// # 参数
/// - `conn`: 连接或事务.
/// - `batch_id`: 所属批次.
/// - `system_id`: 可选业务系统.
/// - `kind`: 告警类型.
/// - `severity`: 严重级别.
/// - `subject`: 告警主体.
/// - `old_value`: 变更前值.
/// - `new_value`: 变更后值.
/// - `details`: 附加 JSON/文本.
///
/// # 返回
/// 无
///
/// # Errors
/// `INSERT` 失败时返回错误.
///
/// # 示例
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

/// 将变更端口序列化为一条 IP 级告警详情.
///
/// # 参数
/// - `ports`: 变更端口列表.
///
/// # 返回
/// 含 `count` 与 `ports` 的 JSON 字符串.
///
/// # 示例
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

/// 将端口列表压成扫描摘要用的逗号分隔文本.
///
/// # 参数
/// - `ports`: 端口列表.
///
/// # 返回
/// 空列表返回 `None`, 否则返回 `"80,443"` 形式.
///
/// # 示例
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

/// 在事务内插入或返回已有业务系统 id.
///
/// # 参数
/// - `tx`: 当前事务.
/// - `name`: 业务系统名称.
///
/// # 返回
/// 系统主键.
///
/// # Errors
/// 插入或查询失败时返回错误.
///
/// # 示例
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

/// 从导入缓存取系统 id, 未命中则插入并回填缓存.
///
/// # 参数
/// - `cache`: 名称到 id 的本地缓存.
/// - `select_system`: `SELECT id FROM systems WHERE name = ?1`.
/// - `insert_system`: `INSERT OR IGNORE INTO systems ...`.
/// - `name`: 业务系统名称.
///
/// # 返回
/// 系统主键.
///
/// # Errors
/// 语句执行或查询失败时返回错误.
///
/// # 示例
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

/// 去掉可选文本两端空白, 空串视为缺失.
///
/// # 参数
/// - `value`: 可选原始文本.
///
/// # 返回
/// 非空修剪后的切片, 否则 `None`.
///
/// # 示例
/// ```text
/// assert_eq!(trimmed_opt(Some("  a  ")), Some("a"));
/// ```
pub(crate) fn trimmed_opt(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// 将查询行映射为 [`BatchRow`].
///
/// # 参数
/// - `row`: 批次查询行.
///
/// # 返回
/// 批次记录.
///
/// # Errors
/// 列类型不匹配时返回 rusqlite 错误.
///
/// # 示例
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

/// 将查询行映射为 [`IpAsset`].
///
/// # 参数
/// - `row`: IP 资产查询行.
///
/// # 返回
/// IP 资产.
///
/// # Errors
/// 列类型不匹配时返回 rusqlite 错误.
///
/// # 示例
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

/// 将查询行映射为 [`PortAsset`].
///
/// # 参数
/// - `row`: 端口资产查询行.
///
/// # 返回
/// 端口资产.
///
/// # Errors
/// 列类型不匹配时返回 rusqlite 错误.
///
/// # 示例
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

/// 将查询行映射为 [`UrlAsset`].
///
/// # 参数
/// - `row`: URL 资产查询行.
///
/// # 返回
/// URL 资产.
///
/// # Errors
/// 列类型不匹配时返回 rusqlite 错误.
///
/// # 示例
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

/// 将查询行映射为 [`LogRow`].
///
/// # 参数
/// - `row`: 应用日志查询行.
///
/// # 返回
/// 日志记录.
///
/// # Errors
/// 列读取失败时返回错误.
///
/// # 示例
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

/// 生成新的 UUID 字符串.
///
/// # 参数
/// 无
///
/// # 返回
/// 新主键.
///
/// # 示例
/// ```text
/// let id = new_id();
/// ```
pub(crate) fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// 返回当前 UTC 时间的 RFC3339 文本.
///
/// # 参数
/// 无
///
/// # 返回
/// RFC3339 时间戳.
///
/// # 示例
/// ```text
/// let ts = now();
/// ```
pub(crate) fn now() -> String {
    Utc::now().to_rfc3339()
}

/// 规范化路径字典条目: 去空白并补前导 `/`.
///
/// # 参数
/// - `path`: 原始路径.
///
/// # 返回
/// 规范化路径; 空白输入返回空串.
///
/// # 示例
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

/// 将布尔值渲染为表格输出用的 `true`/`false`.
///
/// # 参数
/// - `value`: 布尔值.
///
/// # 返回
/// `"true"` 或 `"false"`.
///
/// # 示例
/// ```text
/// assert_eq!(bool_text(true), "true");
/// ```
pub(crate) fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

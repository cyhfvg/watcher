//! Excel asset importer.

use std::{collections::HashMap, path::Path};

use anyhow::Context;

use crate::db::{BaselineImportRow, BaselineImportSummary, Database};

/// Import counters returned after an Excel import.
pub type ImportSummary = BaselineImportSummary;

/// 从 Excel 第一个工作表导入 watcher 资产.
///
/// 必填表头为 `system`, `real_ip`, `port`; 可选表头为 `servername`,
/// `servername_bind_ip`, `url`. Excel `id` 列会被忽略.
///
/// # 参数
///
/// - `db`: 用于写入基准资产的数据库.
/// - `path`: `.xlsx` 文件路径.
///
/// # 返回
///
/// 导入计数摘要.
///
/// # Errors
///
/// 打不开工作簿, 缺少工作表 / 必填表头, 端口单元格无法解析, 或写入数据库失败时返回错误.
///
/// # 示例
///
/// ```no_run
/// # use std::path::Path;
/// # use watcher::{db::Database, import::excel};
/// # fn demo(db: &Database, path: &Path) -> anyhow::Result<()> {
/// let summary = excel::import_excel(db, path)?;
/// println!("imported {}", summary.systems);
/// # Ok(())
/// # }
/// ```
pub fn import_excel(db: &Database, path: &Path) -> anyhow::Result<ImportSummary> {
    let workbook = umya_spreadsheet::reader::xlsx::read(path)
        .with_context(|| format!("failed to open workbook {}", path.display()))?;
    let worksheet = workbook
        .get_sheet_collection()
        .first()
        .context("workbook has no worksheet")?;
    let max_row = worksheet.get_highest_row();
    let max_column = worksheet.get_highest_column();
    anyhow::ensure!(max_row >= 1, "worksheet has no header row");

    let header = read_row(worksheet, 1, max_column);
    let indexes = header_indexes(header);
    require_header(&indexes, "system")?;

    let mut rows = Vec::new();
    for row_number in 2..=max_row {
        let row = read_row(worksheet, row_number, max_column);
        let system = cell(&row, &indexes, "system");
        if system.is_empty() {
            continue;
        }

        let servername = cell(&row, &indexes, "servername");
        let bind_ip = cell(&row, &indexes, "servername_bind_ip");
        let real_ip = cell(&row, &indexes, "real_ip");
        let port_text = cell(&row, &indexes, "port");
        let url = cell(&row, &indexes, "url");
        rows.push(BaselineImportRow {
            system,
            name: (!servername.is_empty()).then_some(servername),
            bind_ip: (!bind_ip.is_empty()).then_some(bind_ip),
            ip: (!real_ip.is_empty()).then_some(real_ip),
            ports: if port_text.is_empty() {
                Vec::new()
            } else {
                parse_ports(&port_text)?
            },
            url: (!url.is_empty()).then_some(url),
        });
    }

    db.import_baseline_rows(&rows, "imported")
}

/// 读取工作表一行, 每个单元格做 trim.
///
/// # 参数
///
/// - `worksheet`: Excel 工作表.
/// - `row_number`: 1-based 行号.
/// - `max_column`: 需要读取的最大列号.
///
/// # 返回
///
/// 该行各列的字符串值, 空单元格为空串.
///
/// # 示例
///
/// ```text
/// let header = read_row(worksheet, 1, max_column);
/// ```
fn read_row(
    worksheet: &umya_spreadsheet::structs::Worksheet,
    row_number: u32,
    max_column: u32,
) -> Vec<String> {
    (1..=max_column)
        .map(|column| worksheet.get_value((column, row_number)).trim().to_string())
        .collect()
}

/// 构建小写表头名到列下标的映射.
///
/// # 参数
///
/// - `header`: 第一行单元格文本.
///
/// # 返回
///
/// 忽略空表头后的 `name -> index` 映射.
///
/// # 示例
///
/// ```text
/// let indexes = header_indexes(header);
/// ```
fn header_indexes(header: Vec<String>) -> HashMap<String, usize> {
    header
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            let key = value.trim().to_ascii_lowercase();
            (!key.is_empty()).then_some((key, index))
        })
        .collect()
}

/// 确认必填表头存在.
///
/// # 参数
///
/// - `indexes`: 表头映射.
/// - `name`: 期望的小写表头名.
///
/// # 返回
///
/// 表头存在时返回 `Ok(())`.
///
/// # Errors
///
/// 缺少该列时返回错误.
///
/// # 示例
///
/// ```text
/// require_header(&indexes, "system")?;
/// ```
fn require_header(indexes: &HashMap<String, usize>, name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        indexes.contains_key(name),
        "missing required excel column `{name}`"
    );
    Ok(())
}

/// 按表头名读取单元格并 trim.
///
/// # 参数
///
/// - `row`: 已读取的行数据.
/// - `indexes`: 表头映射.
/// - `name`: 列名.
///
/// # 返回
///
/// 单元格文本; 缺列或缺单元格时返回空串.
///
/// # 示例
///
/// ```text
/// let system = cell(&row, &indexes, "system");
/// ```
fn cell(row: &[String], indexes: &HashMap<String, usize>, name: &str) -> String {
    indexes
        .get(name)
        .and_then(|index| row.get(*index))
        .cloned()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// 解析逗号, 分号, 斜杠或空白分隔的端口单元格.
///
/// # 参数
///
/// - `value`: 端口单元格文本.
///
/// # 返回
///
/// 解析出的端口列表, 顺序与输入一致.
///
/// # Errors
///
/// 任一端口 token 无法解析时返回错误.
///
/// # 示例
///
/// ```text
/// let ports = parse_ports("80,443/8080")?;
/// ```
fn parse_ports(value: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in value
        .split([',', ';', '/', ' '])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        ports.push(parse_port(part)?);
    }
    Ok(ports)
}

/// 解析单个端口 token, 接受 Excel 整数形态如 `443.0`.
///
/// # 参数
///
/// - `value`: 单个端口文本.
///
/// # 返回
///
/// `u16` 端口号.
///
/// # Errors
///
/// 不是整数, 带小数, 或超出 `u16` 范围时返回错误.
///
/// # 示例
///
/// ```text
/// let port = parse_port("443.0")?;
/// ```
fn parse_port(value: &str) -> anyhow::Result<u16> {
    if let Ok(port) = value.parse::<u16>() {
        return Ok(port);
    }
    let number = value
        .parse::<f64>()
        .with_context(|| format!("invalid port `{value}`"))?;
    anyhow::ensure!(
        number.fract() == 0.0 && (0.0..=u16::MAX as f64).contains(&number),
        "invalid port `{value}`"
    );
    Ok(number as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_ports() {
        assert_eq!(parse_ports("80,443/8080").unwrap(), vec![80, 443, 8080]);
    }

    #[test]
    fn parses_excel_integer_like_ports() {
        assert_eq!(parse_ports("80.0;443").unwrap(), vec![80, 443]);
    }
}

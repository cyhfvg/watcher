//! 将报告目录压缩为 zip.

use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

use anyhow::Context;
use zip::{ZipWriter, write::SimpleFileOptions};

/// 把报告目录中的文件打包为 zip.
///
/// # 参数
/// - `source_dir`: 已写好的报告目录
/// - `zip_path`: 目标 zip 路径
///
/// # 返回
/// 打包成功时返回 `()`
///
/// # Errors
/// 当无法创建 zip, 读取源文件, 或写入压缩条目失败时返回错误.
///
/// # 示例
///
/// ```text
/// zip_dir(&report_dir, &zip_path)?;
/// ```
pub(crate) fn zip_dir(source_dir: &Path, zip_path: &Path) -> anyhow::Result<()> {
    let file = File::create(zip_path)
        .with_context(|| format!("failed to create {}", zip_path.display()))?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for entry in fs::read_dir(source_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("report file has invalid name")?;
        zip.start_file(name, options)?;
        let mut input = File::open(&path)?;
        let mut buffer = Vec::new();
        input.read_to_end(&mut buffer)?;
        zip.write_all(&buffer)?;
    }
    zip.finish()?;
    Ok(())
}

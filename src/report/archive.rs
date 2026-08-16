//! Compresses a report directory into a zip archive.

use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

use anyhow::Context;
use zip::{ZipWriter, write::SimpleFileOptions};

/// Packs the files in a report directory into a zip archive.
///
/// # Arguments
/// - `source_dir`: report directory that has already been written
/// - `zip_path`: destination zip path
///
/// # Returns
/// `()` when packaging succeeds
///
/// # Errors
/// Returns an error when the zip cannot be created, a source file cannot be
/// read, or a compressed entry cannot be written.
///
/// # Examples
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

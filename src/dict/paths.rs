//! Path dictionary import, export, query, and delete helpers.

use std::path::Path;

use anyhow::Context;

use crate::db::Database;

/// Imports newline-delimited path dictionary entries from a file.
///
/// # Arguments
///
/// - `db`: database that holds the path dictionary.
/// - `file`: newline-delimited path list.
///
/// # Returns
///
/// `Ok(())` after printing the imported count.
///
/// # Errors
///
/// Returns an error if the file cannot be read or the import fails.
///
/// # Examples
///
/// ```
/// # use std::io::Write;
/// # use watcher::{db::Database, dict};
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// # let file = dir.path().join("paths.txt");
/// # std::fs::File::create(&file)?.write_all(b"/admin\n")?;
/// dict::paths::import_file(&db, &file)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn import_file(db: &Database, file: &Path) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    let paths = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let count = db.import_dict_paths(&paths)?;
    println!("imported {count}");
    Ok(())
}

/// Exports path dictionary entries to a CSV file.
///
/// # Arguments
///
/// - `db`: database that holds the path dictionary.
/// - `file`: CSV output path.
///
/// # Returns
///
/// `Ok(())` after printing the output path.
///
/// # Errors
///
/// Returns an error if the export fails.
///
/// # Examples
///
/// ```
/// # use watcher::{db::Database, dict};
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// dict::paths::export_file(&db, &dir.path().join("paths.csv"))?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn export_file(db: &Database, file: &Path) -> anyhow::Result<()> {
    db.export_dict_paths(file)?;
    println!("{}", file.display());
    Ok(())
}

/// Prints matching path dictionary entries.
///
/// # Arguments
///
/// - `db`: database that holds the path dictionary.
/// - `keyword`: optional SQL LIKE keyword.
/// - `limit`: maximum rows to print.
///
/// # Returns
///
/// `Ok(())` after printing matching rows.
///
/// # Errors
///
/// Returns an error if the query fails.
///
/// # Examples
///
/// ```
/// # use watcher::{db::Database, dict};
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// dict::paths::query(&db, None, 10)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn query(db: &Database, keyword: Option<&str>, limit: usize) -> anyhow::Result<()> {
    for row in db.query_dict_paths(keyword, limit)? {
        println!("{}", row.join("\t"));
    }
    Ok(())
}

/// Deletes one path dictionary entry.
///
/// # Arguments
///
/// - `db`: database that holds the path dictionary.
/// - `path`: exact dictionary path to delete.
///
/// # Returns
///
/// `Ok(())` after printing the deleted path.
///
/// # Errors
///
/// Returns an error if the delete fails.
///
/// # Examples
///
/// ```
/// # use watcher::{db::Database, dict};
/// # let dir = tempfile::tempdir()?;
/// # let db = Database::open(&dir.path().join("watcher.db"))?;
/// # db.migrate()?;
/// dict::paths::delete(&db, "/missing")?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn delete(db: &Database, path: &str) -> anyhow::Result<()> {
    db.delete_dict_path(path)?;
    println!("deleted path: {path}");
    Ok(())
}

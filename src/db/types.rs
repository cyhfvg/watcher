//! Database handle and public import/pending-work types.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use rusqlite::Connection;

/// SQLite database handle. Each operation opens a short-lived connection, so the handle is cheap to clone.
#[derive(Debug, Clone)]
pub struct Database {
    path: Arc<PathBuf>,
}

/// One normalized record from a structured baseline-asset import.
#[derive(Debug, Clone, Default)]
pub struct BaselineImportRow {
    /// Business system name.
    pub system: String,
    /// Domain name; `None` means this row has no domain.
    pub name: Option<String>,
    /// IP bound to the domain.
    pub bind_ip: Option<String>,
    /// Real IP address.
    pub ip: Option<String>,
    /// Port list.
    pub ports: Vec<u16>,
    /// URL.
    pub url: Option<String>,
}

/// Counts after a bulk baseline import finishes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BaselineImportSummary {
    /// Number of business-system rows processed.
    pub systems: usize,
    /// Number of domain names imported.
    pub names: usize,
    /// Number of IP addresses imported.
    pub ips: usize,
    /// Number of ports imported.
    pub ports: usize,
    /// Number of URLs imported.
    pub urls: usize,
}

/// Pending work item for later batch replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWorkItem {
    /// Pending work primary key.
    pub id: String,
    /// Business system the target belongs to.
    pub system_id: String,
    /// URL or other task-specific target to process.
    pub target: String,
}

impl Database {
    /// Open a database handle for the given SQLite file, creating parent directories if needed.
    ///
    /// # Arguments
    /// - `path`: SQLite file path.
    ///
    /// # Returns
    /// Cloneable [`Database`] handle.
    ///
    /// # Errors
    /// Returns an error if the parent directory cannot be created.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// let db = Database::open(&dir.path().join("watcher.db"))?;
    /// assert!(db.path().ends_with("watcher.db"));
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        Ok(Self {
            path: Arc::new(path.to_path_buf()),
        })
    }

    /// Return the underlying SQLite file path.
    ///
    /// # Arguments
    /// none
    ///
    /// # Returns
    /// Path passed when the handle was opened.
    ///
    /// # Examples
    /// ```
    /// # use watcher::db::Database;
    /// # let dir = tempfile::tempdir()?;
    /// # let path = dir.path().join("watcher.db");
    /// # let db = Database::open(&path)?;
    /// assert_eq!(db.path(), path.as_path());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open a SQLite connection with foreign keys enabled.
    ///
    /// # Arguments
    /// none
    ///
    /// # Returns
    /// New rusqlite connection.
    ///
    /// # Errors
    /// Returns an error if the database file cannot be opened or a `PRAGMA` fails.
    ///
    /// # Examples
    /// ```text
    /// let conn = db.conn()?;
    /// ```
    pub(crate) fn conn(&self) -> anyhow::Result<Connection> {
        let conn = Connection::open(self.path())?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(conn)
    }
}

//! Database handle and public import/pending-work types.

use std::{
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::Context;
use rusqlite::Connection;

const POOL_CAP: usize = 8;

struct ConnPool {
    idle: Mutex<Vec<Connection>>,
}

impl std::fmt::Debug for ConnPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConnPool")
    }
}

/// Checked-out SQLite connection. Drop returns it to the pool.
pub(crate) struct PooledConn {
    conn: Option<Connection>,
    pool: Arc<ConnPool>,
}

impl Deref for PooledConn {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().expect("pooled connection is present")
    }
}

impl DerefMut for PooledConn {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn.as_mut().expect("pooled connection is present")
    }
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else {
            return;
        };
        let mut idle = self
            .pool
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if idle.len() < POOL_CAP {
            idle.push(conn);
        }
    }
}

/// SQLite database handle. Connections are reused from a small pool.
#[derive(Debug, Clone)]
pub struct Database {
    path: Arc<PathBuf>,
    pool: Arc<ConnPool>,
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
            pool: Arc::new(ConnPool {
                idle: Mutex::new(Vec::new()),
            }),
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

    /// Open a pooled SQLite connection.
    ///
    /// New connections set `foreign_keys`, `busy_timeout = 1000`, and
    /// `synchronous = NORMAL`. Idle connections are reused up to 8.
    ///
    /// # Arguments
    /// none
    ///
    /// # Returns
    /// Pooled connection guard.
    ///
    /// # Errors
    /// Returns an error if the database file cannot be opened or a `PRAGMA` fails.
    ///
    /// # Examples
    /// ```text
    /// let conn = db.conn()?;
    /// ```
    pub(crate) fn conn(&self) -> anyhow::Result<PooledConn> {
        let mut idle = self
            .pool
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(conn) = idle.pop() {
            return Ok(PooledConn {
                conn: Some(conn),
                pool: Arc::clone(&self.pool),
            });
        }
        drop(idle);
        Ok(PooledConn {
            conn: Some(open_configured(self.path())?),
            pool: Arc::clone(&self.pool),
        })
    }
}

fn open_configured(path: &Path) -> anyhow::Result<Connection> {
    let conn =
        Connection::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    conn.execute_batch(
        "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 1000; PRAGMA synchronous = NORMAL;",
    )?;
    Ok(conn)
}

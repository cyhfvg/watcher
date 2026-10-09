//! Database handle and public import/pending-work types.

use std::{
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use rusqlite::{Connection, Transaction, TransactionBehavior};

const POOL_CAP: usize = 8;
const BUSY_TIMEOUT: Duration = Duration::from_millis(30_000);

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
    /// New connections set `foreign_keys`, `busy_timeout = 30000`,
    /// `synchronous = NORMAL`, and `journal_mode = WAL`. Idle connections
    /// are reused up to 8.
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

    /// Run `f` inside a `BEGIN IMMEDIATE` transaction.
    ///
    /// Concurrent writers wait for the write lock at `BEGIN` instead of
    /// failing with `database is locked` after a deferred snapshot upgrade.
    ///
    /// # Arguments
    /// - `f`: Body that uses the open transaction.
    ///
    /// # Returns
    /// Value returned by `f`.
    ///
    /// # Errors
    /// Returns an error if the transaction cannot start, `f` fails, or commit fails.
    ///
    /// # Examples
    /// ```text
    /// db.with_immediate_tx(|tx| {
    ///     tx.execute("UPDATE ports SET last_seen = ?1 WHERE id = ?2", params![now, id])?;
    ///     Ok(())
    /// })?;
    /// ```
    pub(crate) fn with_immediate_tx<T>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }
}

/// Open a SQLite file with WAL and a 30s busy timeout.
///
/// # Arguments
/// - `path`: SQLite file path.
///
/// # Returns
/// Configured connection.
///
/// # Errors
/// Returns an error if the file cannot be opened or a `PRAGMA` fails.
///
/// # Examples
/// ```text
/// let conn = open_configured(path)?;
/// ```
fn open_configured(path: &Path) -> anyhow::Result<Connection> {
    let conn =
        Connection::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;")?;
    let journal_mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        anyhow::bail!("failed to enable sqlite wal, journal_mode={journal_mode}");
    }
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_connections_use_wal_and_30s_busy_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("watcher.db")).unwrap();
        db.migrate().unwrap();
        let conn = db.conn().unwrap();
        let timeout_ms: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(timeout_ms, 30_000);
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
    }
}

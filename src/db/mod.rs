//! SQLite persistence layer.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, Row, params};
use uuid::Uuid;

use crate::{
    local_time,
    models::{
        Alert, BatchContext, BatchRow, BatchStatus, DomainAsset, IpAsset, LogRow, PortAsset,
        UrlAsset, Vulnerability,
    },
};

/// SQLite database handle. Each operation opens a short-lived connection so the handle is cheap to clone.
#[derive(Debug, Clone)]
pub struct Database {
    path: Arc<PathBuf>,
}

/// One normalized row from a structured baseline asset import.
#[derive(Debug, Clone, Default)]
pub struct BaselineImportRow {
    pub system: String,
    pub name: Option<String>,
    pub bind_ip: Option<String>,
    pub ip: Option<String>,
    pub ports: Vec<u16>,
    pub url: Option<String>,
}

/// Import counters returned after a bulk baseline import.
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

impl Database {
    /// Opens a database handle for the supplied file path.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        Ok(Self {
            path: Arc::new(path.to_path_buf()),
        })
    }

    /// Returns the underlying SQLite path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Applies idempotent database migrations.
    pub fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS systems (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS domains (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                bind_ip TEXT,
                last_resolved_ips TEXT,
                is_baseline INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(system_id, name)
            );

            CREATE TABLE IF NOT EXISTS ip_addresses (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                source TEXT NOT NULL,
                is_baseline INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(system_id, ip)
            );

            CREATE TABLE IF NOT EXISTS ports (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
                ip_id TEXT REFERENCES ip_addresses(id) ON DELETE CASCADE,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                state TEXT NOT NULL DEFAULT 'unknown',
                source TEXT NOT NULL,
                service TEXT,
                fingerprint TEXT,
                is_web INTEGER NOT NULL DEFAULT 0,
                scheme TEXT,
                is_baseline INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(system_id, ip_id, port)
            );

            CREATE TABLE IF NOT EXISTS urls (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                source TEXT NOT NULL,
                status_code INTEGER,
                title TEXT,
                value_score INTEGER NOT NULL DEFAULT 0,
                is_baseline INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(system_id, url)
            );

            CREATE TABLE IF NOT EXISTS dict_paths (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS batches (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                stop_requested INTEGER NOT NULL DEFAULT 0,
                report_zip TEXT,
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
                system_id TEXT REFERENCES systems(id) ON DELETE SET NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                subject TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                details TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
                system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                poc TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(batch_id, system_id, url, poc)
            );

            CREATE TABLE IF NOT EXISTS pending_work (
                id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL,
                system_id TEXT NOT NULL,
                task_kind TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                priority INTEGER NOT NULL DEFAULT 100,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(task_kind, target)
            );

            CREATE TABLE IF NOT EXISTS logs (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                level TEXT NOT NULL,
                target TEXT NOT NULL,
                message TEXT NOT NULL,
                fields TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(name);
            CREATE INDEX IF NOT EXISTS idx_domains_system_baseline_name ON domains(system_id, is_baseline, name);
            CREATE INDEX IF NOT EXISTS idx_domains_baseline_name ON domains(is_baseline, name);
            CREATE INDEX IF NOT EXISTS idx_ips_ip ON ip_addresses(ip);
            CREATE INDEX IF NOT EXISTS idx_ips_system_baseline_ip ON ip_addresses(system_id, is_baseline, ip);
            CREATE INDEX IF NOT EXISTS idx_ips_baseline_ip ON ip_addresses(is_baseline, ip);
            CREATE INDEX IF NOT EXISTS idx_ips_source_ip ON ip_addresses(source, ip);
            CREATE INDEX IF NOT EXISTS idx_ports_state ON ports(state);
            CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
            CREATE INDEX IF NOT EXISTS idx_ports_system_baseline_port ON ports(system_id, is_baseline, port);
            CREATE INDEX IF NOT EXISTS idx_ports_baseline_port ON ports(is_baseline, port);
            CREATE INDEX IF NOT EXISTS idx_ports_state_web ON ports(state, is_web);
            CREATE INDEX IF NOT EXISTS idx_urls_url ON urls(url);
            CREATE INDEX IF NOT EXISTS idx_urls_system_baseline_url ON urls(system_id, is_baseline, url);
            CREATE INDEX IF NOT EXISTS idx_urls_baseline_url ON urls(is_baseline, url);
            CREATE INDEX IF NOT EXISTS idx_dict_paths_enabled_path ON dict_paths(enabled, path);
            CREATE INDEX IF NOT EXISTS idx_alerts_batch ON alerts(batch_id);
            CREATE INDEX IF NOT EXISTS idx_vulns_batch ON vulnerabilities(batch_id);
            CREATE INDEX IF NOT EXISTS idx_pending_work_take ON pending_work(task_kind, status, priority, created_at);
            CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at);
            CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
            "#,
        )?;
        drop(conn);
        let added_domains =
            self.ensure_column("domains", "is_baseline", "INTEGER NOT NULL DEFAULT 0")?;
        let added_ips =
            self.ensure_column("ip_addresses", "is_baseline", "INTEGER NOT NULL DEFAULT 0")?;
        let added_ports =
            self.ensure_column("ports", "is_baseline", "INTEGER NOT NULL DEFAULT 0")?;
        let added_urls = self.ensure_column("urls", "is_baseline", "INTEGER NOT NULL DEFAULT 0")?;
        if added_domains || added_ips || added_ports || added_urls {
            self.mark_existing_imports_as_baseline(
                added_domains,
                added_ips,
                added_ports,
                added_urls,
            )?;
        }
        Ok(())
    }

    /// Inserts or returns a business system id.
    pub fn upsert_system(&self, name: &str) -> anyhow::Result<String> {
        let name = name.trim();
        anyhow::ensure!(!name.is_empty(), "system name must not be empty");
        let conn = self.conn()?;
        if let Some(id) = conn
            .query_row("SELECT id FROM systems WHERE name = ?1", [name], |row| {
                row.get(0)
            })
            .optional()?
        {
            return Ok(id);
        }
        let id = new_id();
        conn.execute(
            "INSERT INTO systems (id, name, created_at) VALUES (?1, ?2, ?3)",
            params![id, name, now()],
        )?;
        Ok(id)
    }

    /// Renames a business system and returns affected row count.
    pub fn rename_system(&self, old_name: &str, new_name: &str) -> anyhow::Result<usize> {
        let old_name = old_name.trim();
        let new_name = new_name.trim();
        anyhow::ensure!(!old_name.is_empty(), "old system name must not be empty");
        anyhow::ensure!(!new_name.is_empty(), "new system name must not be empty");
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE systems SET name = ?1 WHERE name = ?2",
            params![new_name, old_name],
        )?;
        Ok(changed)
    }

    /// Deletes a business system by name. Child assets are removed by foreign-key cascade.
    pub fn delete_system(&self, name: &str) -> anyhow::Result<usize> {
        let name = name.trim();
        anyhow::ensure!(!name.is_empty(), "system name must not be empty");
        let conn = self.conn()?;
        Ok(conn.execute("DELETE FROM systems WHERE name = ?1", [name])?)
    }

    /// Queries business systems with asset counters.
    pub fn query_systems(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let conn = self.conn()?;
        let mut stmt = conn.prepare(SYSTEM_SUMMARY_SQL)?;
        collect_rows(
            &mut stmt,
            params![pattern, limit as i64],
            map_system_summary,
        )
    }

    /// Exports business systems with asset counters to CSV.
    pub fn export_systems(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            SYSTEM_EXPORT_SQL,
            &[
                "system",
                "names",
                "ips",
                "ports",
                "urls",
                "baseline_names",
                "baseline_ips",
                "baseline_ports",
                "baseline_urls",
                "created_at",
            ],
        )
    }

    /// Inserts or updates a domain asset for a business system.
    pub fn upsert_domain_for_system(
        &self,
        system: &str,
        name: &str,
        bind_ip: Option<&str>,
    ) -> anyhow::Result<String> {
        let system_id = self.upsert_system(system)?;
        self.upsert_domain(&system_id, name, bind_ip)
    }

    /// Inserts or updates a baseline domain asset for a business system.
    pub fn upsert_baseline_domain_for_system(
        &self,
        system: &str,
        name: &str,
        bind_ip: Option<&str>,
    ) -> anyhow::Result<String> {
        let id = self.upsert_domain_for_system(system, name, bind_ip)?;
        self.set_domain_baseline_by_id(&id, true)?;
        Ok(id)
    }

    /// Bulk-import structured baseline rows inside one SQLite transaction.
    pub fn import_baseline_rows(
        &self,
        rows: &[BaselineImportRow],
        source: &str,
    ) -> anyhow::Result<BaselineImportSummary> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let mut system_cache = HashMap::<String, String>::new();
        let mut summary = BaselineImportSummary::default();

        {
            let mut select_system = tx.prepare("SELECT id FROM systems WHERE name = ?1")?;
            let mut insert_system = tx.prepare(
                "INSERT OR IGNORE INTO systems (id, name, created_at) VALUES (?1, ?2, ?3)",
            )?;
            let mut upsert_domain = tx.prepare(
                "INSERT INTO domains (id, system_id, name, bind_ip, is_baseline, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
                 ON CONFLICT(system_id, name) DO UPDATE SET
                    bind_ip = COALESCE(excluded.bind_ip, domains.bind_ip),
                    is_baseline = 1,
                    updated_at = excluded.updated_at",
            )?;
            let mut upsert_ip = tx.prepare(
                "INSERT INTO ip_addresses (id, system_id, ip, source, is_baseline, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
                 ON CONFLICT(system_id, ip) DO UPDATE SET
                    source = CASE WHEN ip_addresses.source = 'resolved' THEN excluded.source ELSE ip_addresses.source END,
                    is_baseline = 1,
                    updated_at = excluded.updated_at",
            )?;
            let mut select_ip =
                tx.prepare("SELECT id FROM ip_addresses WHERE system_id = ?1 AND ip = ?2")?;
            let mut select_port = tx.prepare(
                "SELECT id FROM ports
                 WHERE system_id = ?1
                   AND ((ip_id IS NULL AND ?2 IS NULL) OR ip_id = ?2)
                   AND port = ?3",
            )?;
            let mut insert_port = tx.prepare(
                "INSERT INTO ports (id, system_id, ip_id, port, source, is_baseline, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
            )?;
            let mut mark_port_baseline =
                tx.prepare("UPDATE ports SET is_baseline = 1, last_seen = ?1 WHERE id = ?2")?;
            let mut upsert_url = tx.prepare(
                "INSERT INTO urls (id, system_id, url, source, value_score, is_baseline, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 10, 1, ?5, ?5)
                 ON CONFLICT(system_id, url) DO UPDATE SET
                    source = CASE WHEN urls.source = 'imported' THEN urls.source ELSE excluded.source END,
                    value_score = MAX(urls.value_score, excluded.value_score),
                    is_baseline = 1,
                    updated_at = excluded.updated_at",
            )?;

            for row in rows {
                let system = row.system.trim();
                if system.is_empty() {
                    continue;
                }
                summary.systems += 1;
                let system_id = cached_system_id(
                    &mut system_cache,
                    &mut select_system,
                    &mut insert_system,
                    system,
                )?;

                if let Some(name) = trimmed_opt(row.name.as_deref()) {
                    let name = name.trim_end_matches('.');
                    if name.is_empty() {
                        continue;
                    }
                    upsert_domain.execute(params![
                        new_id(),
                        system_id,
                        name,
                        trimmed_opt(row.bind_ip.as_deref()),
                        now()
                    ])?;
                    summary.names += 1;
                }

                let ip_id = if let Some(ip) = trimmed_opt(row.ip.as_deref()) {
                    upsert_ip.execute(params![new_id(), system_id, ip, source, now()])?;
                    let id: String =
                        select_ip.query_row(params![system_id, ip], |row| row.get(0))?;
                    summary.ips += 1;
                    Some(id)
                } else {
                    None
                };

                for port in &row.ports {
                    if let Some(id) = select_port
                        .query_row(params![system_id, ip_id.as_deref(), *port], |row| {
                            row.get::<_, String>(0)
                        })
                        .optional()?
                    {
                        mark_port_baseline.execute(params![now(), id])?;
                    } else {
                        insert_port.execute(params![
                            new_id(),
                            system_id,
                            ip_id.as_deref(),
                            *port,
                            source,
                            now()
                        ])?;
                    }
                    summary.ports += 1;
                }

                if let Some(url) = trimmed_opt(row.url.as_deref()) {
                    upsert_url.execute(params![new_id(), system_id, url, source, now()])?;
                    summary.urls += 1;
                }
            }
        }

        tx.commit()?;
        Ok(summary)
    }

    /// Bulk-import URL baseline values for one business system.
    pub fn import_baseline_urls_for_system(
        &self,
        system: &str,
        values: &[String],
        source: &str,
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO urls (id, system_id, url, source, value_score, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, 1, ?5, ?5)
             ON CONFLICT(system_id, url) DO UPDATE SET
                source = CASE WHEN urls.source = 'imported' THEN urls.source ELSE excluded.source END,
                is_baseline = 1,
                updated_at = excluded.updated_at",
            Some(source),
            false,
        )
    }

    /// Bulk-import non-baseline URL values for one business system.
    pub fn import_urls_for_system(
        &self,
        system: &str,
        values: &[String],
        source: &str,
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO urls (id, system_id, url, source, value_score, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, ?5)
             ON CONFLICT(system_id, url) DO UPDATE SET
                source = CASE WHEN urls.source = 'imported' THEN urls.source ELSE excluded.source END,
                updated_at = excluded.updated_at",
            Some(source),
            false,
        )
    }

    /// Bulk-import IP baseline values for one business system.
    pub fn import_baseline_ips_for_system(
        &self,
        system: &str,
        values: &[String],
        source: &str,
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO ip_addresses (id, system_id, ip, source, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
             ON CONFLICT(system_id, ip) DO UPDATE SET
                source = CASE WHEN ip_addresses.source = 'resolved' THEN excluded.source ELSE ip_addresses.source END,
                is_baseline = 1,
                updated_at = excluded.updated_at",
            Some(source),
            false,
        )
    }

    /// Bulk-import non-baseline IP values for one business system.
    pub fn import_ips_for_system(
        &self,
        system: &str,
        values: &[String],
        source: &str,
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO ip_addresses (id, system_id, ip, source, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)
             ON CONFLICT(system_id, ip) DO UPDATE SET
                source = CASE WHEN ip_addresses.source = 'resolved' THEN excluded.source ELSE ip_addresses.source END,
                updated_at = excluded.updated_at",
            Some(source),
            false,
        )
    }

    /// Bulk-import domain-name baseline values for one business system.
    pub fn import_baseline_names_for_system(
        &self,
        system: &str,
        values: &[String],
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO domains (id, system_id, name, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, ?5, ?5)
             ON CONFLICT(system_id, name) DO UPDATE SET
                is_baseline = 1,
                updated_at = excluded.updated_at",
            None,
            true,
        )
    }

    /// Bulk-import non-baseline domain-name values for one business system.
    pub fn import_names_for_system(
        &self,
        system: &str,
        values: &[String],
        bind_ip: Option<&str>,
    ) -> anyhow::Result<usize> {
        self.import_values_for_system(
            system,
            values,
            "INSERT INTO domains (id, system_id, name, bind_ip, is_baseline, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)
             ON CONFLICT(system_id, name) DO UPDATE SET
                bind_ip = COALESCE(excluded.bind_ip, domains.bind_ip),
                updated_at = excluded.updated_at",
            trimmed_opt(bind_ip),
            true,
        )
    }

    /// Bulk-import port baseline values for one business system and optional IP.
    pub fn import_baseline_ports_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        ports: &[u16],
        source: &str,
    ) -> anyhow::Result<usize> {
        let system = system.trim();
        anyhow::ensure!(!system.is_empty(), "system name must not be empty");
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let system_id = ensure_system_in_tx(&tx, system)?;
        let ip_id = if let Some(ip) = trimmed_opt(ip) {
            tx.execute(
                "INSERT INTO ip_addresses (id, system_id, ip, source, is_baseline, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
                 ON CONFLICT(system_id, ip) DO UPDATE SET
                    source = CASE WHEN ip_addresses.source = 'resolved' THEN excluded.source ELSE ip_addresses.source END,
                    is_baseline = 1,
                    updated_at = excluded.updated_at",
                params![new_id(), system_id, ip, source, now()],
            )?;
            Some(tx.query_row(
                "SELECT id FROM ip_addresses WHERE system_id = ?1 AND ip = ?2",
                params![system_id, ip],
                |row| row.get::<_, String>(0),
            )?)
        } else {
            None
        };
        let mut count = 0usize;
        {
            let mut select_port = tx.prepare(
                "SELECT id FROM ports
                 WHERE system_id = ?1
                   AND ((ip_id IS NULL AND ?2 IS NULL) OR ip_id = ?2)
                   AND port = ?3",
            )?;
            let mut insert_port = tx.prepare(
                "INSERT INTO ports (id, system_id, ip_id, port, source, is_baseline, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
            )?;
            let mut mark_port_baseline =
                tx.prepare("UPDATE ports SET is_baseline = 1, last_seen = ?1 WHERE id = ?2")?;
            for port in ports {
                if let Some(id) = select_port
                    .query_row(params![system_id, ip_id.as_deref(), *port], |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()?
                {
                    mark_port_baseline.execute(params![now(), id])?;
                } else {
                    insert_port.execute(params![
                        new_id(),
                        system_id,
                        ip_id.as_deref(),
                        *port,
                        source,
                        now()
                    ])?;
                }
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// Bulk-import non-baseline port values for one business system and optional IP.
    pub fn import_ports_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        ports: &[u16],
        source: &str,
    ) -> anyhow::Result<usize> {
        let system = system.trim();
        anyhow::ensure!(!system.is_empty(), "system name must not be empty");
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let system_id = ensure_system_in_tx(&tx, system)?;
        let ip_id = if let Some(ip) = trimmed_opt(ip) {
            tx.execute(
                "INSERT INTO ip_addresses (id, system_id, ip, source, is_baseline, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)
                 ON CONFLICT(system_id, ip) DO UPDATE SET
                    source = CASE WHEN ip_addresses.source = 'resolved' THEN excluded.source ELSE ip_addresses.source END,
                    updated_at = excluded.updated_at",
                params![new_id(), system_id, ip, source, now()],
            )?;
            Some(tx.query_row(
                "SELECT id FROM ip_addresses WHERE system_id = ?1 AND ip = ?2",
                params![system_id, ip],
                |row| row.get::<_, String>(0),
            )?)
        } else {
            None
        };
        let mut count = 0usize;
        {
            let mut select_port = tx.prepare(
                "SELECT id FROM ports
                 WHERE system_id = ?1
                   AND ((ip_id IS NULL AND ?2 IS NULL) OR ip_id = ?2)
                   AND port = ?3",
            )?;
            let mut insert_port = tx.prepare(
                "INSERT INTO ports (id, system_id, ip_id, port, source, is_baseline, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?6)",
            )?;
            let mut touch_port = tx.prepare("UPDATE ports SET last_seen = ?1 WHERE id = ?2")?;
            for port in ports {
                if let Some(id) = select_port
                    .query_row(params![system_id, ip_id.as_deref(), *port], |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()?
                {
                    touch_port.execute(params![now(), id])?;
                } else {
                    insert_port.execute(params![
                        new_id(),
                        system_id,
                        ip_id.as_deref(),
                        *port,
                        source,
                        now()
                    ])?;
                }
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// Inserts or updates a domain asset by system id.
    pub fn upsert_domain(
        &self,
        system_id: &str,
        name: &str,
        bind_ip: Option<&str>,
    ) -> anyhow::Result<String> {
        let name = name.trim().trim_end_matches('.');
        anyhow::ensure!(!name.is_empty(), "domain name must not be empty");
        let conn = self.conn()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM domains WHERE system_id = ?1 AND name = ?2",
                params![system_id, name],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => {
                conn.execute(
                    "UPDATE domains SET bind_ip = COALESCE(?1, bind_ip), updated_at = ?2 WHERE id = ?3",
                    params![bind_ip, now(), id],
                )?;
                Ok(id)
            }
            None => {
                let id = new_id();
                conn.execute(
                    "INSERT INTO domains (id, system_id, name, bind_ip, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                    params![id, system_id, name, bind_ip, now()],
                )?;
                Ok(id)
            }
        }
    }

    /// Inserts or updates an IP asset for a business system.
    pub fn upsert_ip_for_system(
        &self,
        system: &str,
        ip: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let system_id = self.upsert_system(system)?;
        self.upsert_ip(&system_id, ip, source)
    }

    /// Inserts or updates a baseline IP asset for a business system.
    pub fn upsert_baseline_ip_for_system(
        &self,
        system: &str,
        ip: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let id = self.upsert_ip_for_system(system, ip, source)?;
        self.set_ip_baseline_by_id(&id, true)?;
        Ok(id)
    }

    /// Inserts or updates an IP asset by system id.
    pub fn upsert_ip(&self, system_id: &str, ip: &str, source: &str) -> anyhow::Result<String> {
        let ip = ip.trim();
        anyhow::ensure!(!ip.is_empty(), "ip must not be empty");
        let conn = self.conn()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM ip_addresses WHERE system_id = ?1 AND ip = ?2",
                params![system_id, ip],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => {
                conn.execute(
                    "UPDATE ip_addresses SET source = CASE WHEN source = 'resolved' THEN ?1 ELSE source END, updated_at = ?2 WHERE id = ?3",
                    params![source, now(), id],
                )?;
                Ok(id)
            }
            None => {
                let id = new_id();
                conn.execute(
                    "INSERT INTO ip_addresses (id, system_id, ip, source, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                    params![id, system_id, ip, source, now()],
                )?;
                Ok(id)
            }
        }
    }

    /// Inserts or updates a URL asset for a business system.
    pub fn upsert_url_for_system(
        &self,
        system: &str,
        url: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let system_id = self.upsert_system(system)?;
        self.upsert_url(&system_id, url, source, None, 0)
    }

    /// Inserts or updates a baseline URL asset for a business system.
    pub fn upsert_baseline_url_for_system(
        &self,
        system: &str,
        url: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let id = self.upsert_url_for_system(system, url, source)?;
        self.set_url_baseline_by_id(&id, true)?;
        Ok(id)
    }

    /// Inserts or updates a URL asset by system id.
    pub fn upsert_url(
        &self,
        system_id: &str,
        url: &str,
        source: &str,
        status_code: Option<u16>,
        value_score: i64,
    ) -> anyhow::Result<String> {
        let url = url.trim();
        anyhow::ensure!(!url.is_empty(), "url must not be empty");
        let conn = self.conn()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM urls WHERE system_id = ?1 AND url = ?2",
                params![system_id, url],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => {
                conn.execute(
                    "UPDATE urls
                     SET source = CASE WHEN source = 'imported' THEN source ELSE ?1 END,
                         status_code = COALESCE(?2, status_code),
                         value_score = MAX(value_score, ?3),
                         updated_at = ?4
                     WHERE id = ?5",
                    params![source, status_code, value_score, now(), id],
                )?;
                Ok(id)
            }
            None => {
                let id = new_id();
                conn.execute(
                    "INSERT INTO urls (id, system_id, url, source, status_code, value_score, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                    params![id, system_id, url, source, status_code, value_score, now()],
                )?;
                Ok(id)
            }
        }
    }

    /// Inserts or updates a port asset for a business system.
    pub fn upsert_port_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        port: u16,
        source: &str,
    ) -> anyhow::Result<String> {
        let system_id = self.upsert_system(system)?;
        let ip_id = match ip {
            Some(ip) if !ip.trim().is_empty() => Some(self.upsert_ip(&system_id, ip, source)?),
            _ => None,
        };
        self.upsert_port(&system_id, ip_id.as_deref(), port, source)
    }

    /// Inserts or updates a baseline port asset for a business system.
    pub fn upsert_baseline_port_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        port: u16,
        source: &str,
    ) -> anyhow::Result<String> {
        let id = self.upsert_port_for_system(system, ip, port, source)?;
        self.set_port_baseline_by_id(&id, true)?;
        Ok(id)
    }

    /// Inserts or updates a port by system id and optional IP id.
    pub fn upsert_port(
        &self,
        system_id: &str,
        ip_id: Option<&str>,
        port: u16,
        source: &str,
    ) -> anyhow::Result<String> {
        let conn = self.conn()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM ports WHERE system_id = ?1 AND ((ip_id IS NULL AND ?2 IS NULL) OR ip_id = ?2) AND port = ?3",
                params![system_id, ip_id, port],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => Ok(id),
            None => {
                let id = new_id();
                conn.execute(
                    "INSERT INTO ports (id, system_id, ip_id, port, source, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    params![id, system_id, ip_id, port, source, now()],
                )?;
                Ok(id)
            }
        }
    }

    /// Marks a domain row as baseline or non-baseline by id.
    pub fn set_domain_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("domains", id, is_baseline)
    }

    /// Marks an IP row as baseline or non-baseline by id.
    pub fn set_ip_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("ip_addresses", id, is_baseline)
    }

    /// Marks a port row as baseline or non-baseline by id.
    pub fn set_port_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("ports", id, is_baseline)
    }

    /// Marks a URL row as baseline or non-baseline by id.
    pub fn set_url_baseline_by_id(&self, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        self.set_baseline_by_id("urls", id, is_baseline)
    }

    /// Marks a URL in one business system as baseline or non-baseline.
    pub fn set_url_baseline_for_system(
        &self,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        self.set_baseline_by_system_value("urls", "url", system, value, is_baseline)
    }

    /// Marks a port in one business system, optionally bound to one IP, as baseline or non-baseline.
    pub fn set_port_baseline_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        port: u16,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "UPDATE ports
             SET is_baseline = ?1
             WHERE system_id = (SELECT id FROM systems WHERE name = ?2)
               AND port = ?3
               AND (?4 IS NULL OR ip_id IN (
                   SELECT id FROM ip_addresses
                   WHERE system_id = ports.system_id AND ip = ?4
               ))",
            params![is_baseline as i64, system, port, ip],
        )?)
    }

    /// Marks an IP in one business system as baseline or non-baseline.
    pub fn set_ip_baseline_for_system(
        &self,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        self.set_baseline_by_system_value("ip_addresses", "ip", system, value, is_baseline)
    }

    /// Marks a domain in one business system as baseline or non-baseline.
    pub fn set_name_baseline_for_system(
        &self,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        self.set_baseline_by_system_value("domains", "name", system, value, is_baseline)
    }

    /// Records a port scan result and creates change alerts when the state changes.
    pub fn record_port_state(
        &self,
        batch_id: &str,
        system_id: &str,
        ip_id: &str,
        ip: &str,
        port: u16,
        open: bool,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        let existing: Option<(String, String)> = conn
            .query_row(
                "SELECT id, state FROM ports WHERE system_id = ?1 AND ip_id = ?2 AND port = ?3",
                params![system_id, ip_id, port],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        // Avoid storing every closed port from large/full scans. Closed results are only
        // meaningful when we already had a historical/imported row to compare against.
        let (port_id, old_state) = match existing {
            Some(existing) => existing,
            None if open => {
                let port_id = self.upsert_port(system_id, Some(ip_id), port, "scan")?;
                (port_id, "unknown".to_string())
            }
            None => return Ok(()),
        };
        let new_state = if open { "open" } else { "closed" };
        conn.execute(
            "UPDATE ports SET state = ?1, last_seen = ?2 WHERE id = ?3",
            params![new_state, now(), port_id],
        )?;
        if old_state != new_state && (old_state != "unknown" || open) {
            self.add_alert(
                batch_id,
                Some(system_id),
                "port_change",
                if open { "high" } else { "medium" },
                &format!("{ip}:{port}"),
                Some(&old_state),
                Some(new_state),
                None,
            )?;
        }
        Ok(())
    }

    /// Updates service fingerprint information for a port.
    pub fn update_port_fingerprint(
        &self,
        port_id: &str,
        service: Option<&str>,
        fingerprint: Option<&str>,
        is_web: bool,
        scheme: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE ports SET service = ?1, fingerprint = ?2, is_web = ?3, scheme = ?4, last_seen = ?5 WHERE id = ?6",
            params![service, fingerprint, is_web as i64, scheme, now(), port_id],
        )?;
        Ok(())
    }

    /// Updates DNS resolution state and writes an alert when it changes.
    pub fn update_domain_resolution(
        &self,
        batch_id: &str,
        domain: &DomainAsset,
        new_ips: &[String],
    ) -> anyhow::Result<()> {
        let new_value = new_ips.join(",");
        let old_value = domain.bind_ip.clone().unwrap_or_default();
        let conn = self.conn()?;
        conn.execute(
            "UPDATE domains SET bind_ip = ?1, last_resolved_ips = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_value, now(), domain.id],
        )?;
        for ip in new_ips {
            self.upsert_ip(&domain.system_id, ip, "resolved")?;
        }
        if old_value != new_value {
            self.add_alert(
                batch_id,
                Some(&domain.system_id),
                "dns_change",
                "medium",
                &domain.name,
                if old_value.is_empty() {
                    None
                } else {
                    Some(&old_value)
                },
                Some(&new_value),
                None,
            )?;
        }
        Ok(())
    }

    /// Adds an alert row.
    #[allow(clippy::too_many_arguments)]
    pub fn add_alert(
        &self,
        batch_id: &str,
        system_id: Option<&str>,
        kind: &str,
        severity: &str,
        subject: &str,
        old_value: Option<&str>,
        new_value: Option<&str>,
        details: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO alerts (id, batch_id, system_id, kind, severity, subject, old_value, new_value, details, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![new_id(), batch_id, system_id, kind, severity, subject, old_value, new_value, details, now()],
        )?;
        Ok(())
    }

    /// Adds or ignores a vulnerability finding.
    pub fn add_vulnerability(
        &self,
        batch_id: &str,
        system_id: &str,
        url: &str,
        poc: &str,
        severity: &str,
        evidence: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO vulnerabilities (id, batch_id, system_id, url, poc, severity, evidence, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![new_id(), batch_id, system_id, url, poc, severity, evidence, now()],
        )?;
        self.upsert_url(system_id, url, "vuln", None, 100)?;
        Ok(())
    }

    /// Creates a new monitoring batch.
    pub fn create_batch(&self) -> anyhow::Result<BatchContext> {
        self.interrupt_running_batches("previous watcher process exited before finalizing batch")?;
        let id = new_id();
        let started_at = Utc::now();
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO batches (id, status, started_at) VALUES (?1, 'running', ?2)",
            params![id, started_at.to_rfc3339()],
        )?;
        Ok(BatchContext { id, started_at })
    }

    /// Marks leftover running batches as interrupted.
    pub fn interrupt_running_batches(&self, reason: &str) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "UPDATE batches
             SET status = 'interrupted', ended_at = ?1, error = ?2, stop_requested = 1
             WHERE status = 'running'",
            params![now(), reason],
        )?)
    }

    /// Finishes a batch with a final status.
    pub fn finish_batch(
        &self,
        batch_id: &str,
        status: &str,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE batches SET status = ?1, ended_at = ?2, error = ?3 WHERE id = ?4",
            params![status, now(), error, batch_id],
        )?;
        Ok(())
    }

    /// Stores the report zip path for a batch.
    pub fn set_batch_report(&self, batch_id: &str, path: &Path) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE batches SET report_zip = ?1 WHERE id = ?2",
            params![path.display().to_string(), batch_id],
        )?;
        Ok(())
    }

    /// Requests that a running batch stop at the next checkpoint.
    pub fn request_batch_stop(&self, batch: Option<&str>) -> anyhow::Result<()> {
        let conn = self.conn()?;
        if let Some(batch) = batch {
            conn.execute(
                "UPDATE batches SET stop_requested = 1 WHERE id = ?1",
                [batch],
            )?;
        } else {
            conn.execute(
                "UPDATE batches SET stop_requested = 1 WHERE status = 'running'",
                [],
            )?;
        }
        Ok(())
    }

    /// Returns true if a batch has been asked to stop.
    pub fn should_stop_batch(&self, batch_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn()?;
        let value: i64 = conn.query_row(
            "SELECT stop_requested FROM batches WHERE id = ?1",
            [batch_id],
            |row| row.get(0),
        )?;
        Ok(value == 1)
    }

    /// Lists domain assets.
    pub fn list_domains(&self) -> anyhow::Result<Vec<DomainAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT d.id, d.system_id, s.name, d.name, d.bind_ip, d.is_baseline
             FROM domains d JOIN systems s ON s.id = d.system_id
             ORDER BY s.name, d.name",
        )?;
        collect_rows(&mut stmt, [], |row| {
            Ok(DomainAsset {
                id: row.get(0)?,
                system_id: row.get(1)?,
                system_name: row.get(2)?,
                name: row.get(3)?,
                bind_ip: row.get(4)?,
                is_baseline: row.get::<_, i64>(5)? == 1,
            })
        })
    }

    /// Lists domain assets for one business system id.
    pub fn list_domains_for_system(&self, system_id: &str) -> anyhow::Result<Vec<DomainAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT d.id, d.system_id, s.name, d.name, d.bind_ip, d.is_baseline
             FROM domains d JOIN systems s ON s.id = d.system_id
             WHERE d.system_id = ?1
             ORDER BY d.name",
        )?;
        collect_rows(&mut stmt, [system_id], |row| {
            Ok(DomainAsset {
                id: row.get(0)?,
                system_id: row.get(1)?,
                system_name: row.get(2)?,
                name: row.get(3)?,
                bind_ip: row.get(4)?,
                is_baseline: row.get::<_, i64>(5)? == 1,
            })
        })
    }

    /// Lists imported/manual real IP assets used for port scans.
    pub fn list_real_ips(&self) -> anyhow::Result<Vec<IpAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT i.id, i.system_id, s.name, i.ip, i.source, i.is_baseline
             FROM ip_addresses i JOIN systems s ON s.id = i.system_id
             WHERE i.source != 'resolved'
             ORDER BY s.name, i.ip",
        )?;
        collect_rows(&mut stmt, [], |row| Ok(map_ip(row)?))
    }

    /// Lists open ports.
    pub fn list_open_ports(&self) -> anyhow::Result<Vec<PortAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.system_id, s.name, p.ip_id, i.ip, p.port, p.state, p.service, p.fingerprint, p.is_web, p.scheme, p.is_baseline
             FROM ports p
             JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE p.state = 'open'
             ORDER BY s.name, i.ip, p.port",
        )?;
        collect_rows(&mut stmt, [], |row| Ok(map_port(row)?))
    }

    /// Lists web services identified by fingerprinting.
    pub fn list_web_services(&self) -> anyhow::Result<Vec<PortAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.system_id, s.name, p.ip_id, i.ip, p.port, p.state, p.service, p.fingerprint, p.is_web, p.scheme, p.is_baseline
             FROM ports p
             JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE p.state = 'open' AND p.is_web = 1
             ORDER BY s.name, i.ip, p.port",
        )?;
        collect_rows(&mut stmt, [], |row| Ok(map_port(row)?))
    }

    /// Lists URL assets.
    pub fn list_urls(&self) -> anyhow::Result<Vec<UrlAsset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT u.id, u.system_id, s.name, u.url, u.source, u.status_code, u.value_score, u.is_baseline
             FROM urls u JOIN systems s ON s.id = u.system_id
             ORDER BY s.name, u.url",
        )?;
        collect_rows(&mut stmt, [], |row| Ok(map_url(row)?))
    }

    /// Bulk-import dictionary paths inside one SQLite transaction.
    pub fn import_dict_paths(&self, paths: &[String]) -> anyhow::Result<usize> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let mut count = 0usize;
        {
            let mut insert = tx.prepare(
                "INSERT OR IGNORE INTO dict_paths (id, path, enabled, created_at)
                 VALUES (?1, ?2, 1, ?3)",
            )?;
            for path in paths {
                let normalized = normalize_path(path);
                if normalized.is_empty() {
                    continue;
                }
                insert.execute(params![new_id(), normalized, now()])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// Lists enabled dictionary paths.
    pub fn list_dict_paths(&self, limit: usize) -> anyhow::Result<Vec<String>> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare("SELECT path FROM dict_paths WHERE enabled = 1 ORDER BY path LIMIT ?1")?;
        collect_rows(&mut stmt, [limit as i64], |row| Ok(row.get(0)?))
    }

    /// Queries dictionary paths with an optional keyword.
    pub fn query_dict_paths(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_simple("dict_paths", "path", keyword, limit)
    }

    /// Deletes a dictionary path.
    pub fn delete_dict_path(&self, path: &str) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM dict_paths WHERE path = ?1",
            [normalize_path(path)],
        )?;
        Ok(())
    }

    /// Exports dictionary paths to CSV.
    pub fn export_dict_paths(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(file, "SELECT path FROM dict_paths ORDER BY path", &["path"])
    }

    /// Generic URL query.
    pub fn query_urls(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_joined("urls", "url", keyword, limit)
    }

    /// Queries baseline URL assets.
    pub fn query_baseline_urls(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_baseline_joined("urls", "url", keyword, limit)
    }

    /// Generic port query.
    pub fn query_ports(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT s.name, COALESCE(i.ip, '-'), p.port, p.state, COALESCE(p.service, '-'), COALESCE(p.scheme, '-'), p.is_baseline
             FROM ports p
             JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE CAST(p.port AS TEXT) LIKE ?1 OR COALESCE(i.ip, '') LIKE ?1
             ORDER BY s.name, i.ip, p.port LIMIT ?2",
        )?;
        collect_rows(&mut stmt, params![pattern, limit as i64], |row| {
            Ok(vec![
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?.to_string(),
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                bool_text(row.get::<_, i64>(6)? == 1).to_string(),
            ])
        })
    }

    /// Queries baseline port assets.
    pub fn query_baseline_ports(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT s.name, COALESCE(i.ip, '-'), p.port, p.state, COALESCE(p.service, '-'), COALESCE(p.scheme, '-')
             FROM ports p
             JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE p.is_baseline = 1 AND (CAST(p.port AS TEXT) LIKE ?1 OR COALESCE(i.ip, '') LIKE ?1 OR s.name LIKE ?1)
             ORDER BY s.name, i.ip, p.port LIMIT ?2",
        )?;
        collect_rows(&mut stmt, params![pattern, limit as i64], |row| {
            Ok(vec![
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?.to_string(),
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ])
        })
    }

    /// Generic IP query.
    pub fn query_ips(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_joined("ip_addresses", "ip", keyword, limit)
    }

    /// Queries baseline IP assets.
    pub fn query_baseline_ips(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_baseline_joined("ip_addresses", "ip", keyword, limit)
    }

    /// Generic domain query.
    pub fn query_names(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_joined("domains", "name", keyword, limit)
    }

    /// Queries baseline domain assets.
    pub fn query_baseline_names(
        &self,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        self.query_baseline_joined("domains", "name", keyword, limit)
    }

    /// Deletes a URL by exact value.
    pub fn delete_url(&self, value: &str) -> anyhow::Result<()> {
        self.delete_by_value("urls", "url", value)
    }

    /// Deletes a URL by business system and exact value.
    pub fn delete_url_for_system(&self, system: &str, value: &str) -> anyhow::Result<usize> {
        self.delete_by_system_value("urls", "url", system, value)
    }

    /// Deletes a port by exact number from all systems/IPs.
    pub fn delete_port(&self, value: u16) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM ports WHERE port = ?1", [value])?;
        Ok(())
    }

    /// Deletes a port by business system, optional IP and exact port.
    pub fn delete_port_for_system(
        &self,
        system: &str,
        ip: Option<&str>,
        port: u16,
    ) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute(
            "DELETE FROM ports
             WHERE system_id = (SELECT id FROM systems WHERE name = ?1)
               AND port = ?2
               AND (?3 IS NULL OR ip_id IN (
                   SELECT id FROM ip_addresses
                   WHERE system_id = ports.system_id AND ip = ?3
               ))",
            params![system, port, ip],
        )?)
    }

    /// Deletes an IP by exact value.
    pub fn delete_ip(&self, value: &str) -> anyhow::Result<()> {
        self.delete_by_value("ip_addresses", "ip", value)
    }

    /// Deletes an IP by business system and exact value.
    pub fn delete_ip_for_system(&self, system: &str, value: &str) -> anyhow::Result<usize> {
        self.delete_by_system_value("ip_addresses", "ip", system, value)
    }

    /// Deletes a domain by exact value.
    pub fn delete_name(&self, value: &str) -> anyhow::Result<()> {
        self.delete_by_value("domains", "name", value)
    }

    /// Deletes a domain by business system and exact value.
    pub fn delete_name_for_system(&self, system: &str, value: &str) -> anyhow::Result<usize> {
        self.delete_by_system_value("domains", "name", system, value)
    }

    /// Exports URLs to CSV.
    pub fn export_urls(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, u.url, u.source, COALESCE(u.status_code, ''), u.value_score, CASE WHEN u.is_baseline = 1 THEN 'true' ELSE 'false' END
             FROM urls u JOIN systems s ON s.id = u.system_id ORDER BY s.name, u.url",
            &["system", "url", "source", "status_code", "value_score", "baseline"],
        )
    }

    /// Exports baseline URLs to CSV.
    pub fn export_baseline_urls(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, u.url, u.source, COALESCE(u.status_code, ''), u.value_score
             FROM urls u JOIN systems s ON s.id = u.system_id
             WHERE u.is_baseline = 1
             ORDER BY s.name, u.url",
            &["system", "url", "source", "status_code", "value_score"],
        )
    }

    /// Exports ports to CSV.
    pub fn export_ports(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, COALESCE(i.ip, ''), p.port, p.state, COALESCE(p.service, ''), COALESCE(p.scheme, ''), CASE WHEN p.is_baseline = 1 THEN 'true' ELSE 'false' END
             FROM ports p JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id ORDER BY s.name, i.ip, p.port",
            &["system", "ip", "port", "state", "service", "scheme", "baseline"],
        )
    }

    /// Exports baseline ports to CSV.
    pub fn export_baseline_ports(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, COALESCE(i.ip, ''), p.port, p.state, COALESCE(p.service, ''), COALESCE(p.scheme, '')
             FROM ports p JOIN systems s ON s.id = p.system_id
             LEFT JOIN ip_addresses i ON i.id = p.ip_id
             WHERE p.is_baseline = 1
             ORDER BY s.name, i.ip, p.port",
            &["system", "ip", "port", "state", "service", "scheme"],
        )
    }

    /// Exports IPs to CSV.
    pub fn export_ips(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, i.ip, i.source, CASE WHEN i.is_baseline = 1 THEN 'true' ELSE 'false' END FROM ip_addresses i JOIN systems s ON s.id = i.system_id ORDER BY s.name, i.ip",
            &["system", "ip", "source", "baseline"],
        )
    }

    /// Exports baseline IPs to CSV.
    pub fn export_baseline_ips(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, i.ip, i.source
             FROM ip_addresses i JOIN systems s ON s.id = i.system_id
             WHERE i.is_baseline = 1
             ORDER BY s.name, i.ip",
            &["system", "ip", "source"],
        )
    }

    /// Exports domain names to CSV.
    pub fn export_names(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, d.name, COALESCE(d.bind_ip, ''), CASE WHEN d.is_baseline = 1 THEN 'true' ELSE 'false' END FROM domains d JOIN systems s ON s.id = d.system_id ORDER BY s.name, d.name",
            &["system", "name", "bind_ip", "baseline"],
        )
    }

    /// Exports baseline domain names to CSV.
    pub fn export_baseline_names(&self, file: &Path) -> anyhow::Result<()> {
        self.export_query(
            file,
            "SELECT s.name, d.name, COALESCE(d.bind_ip, '')
             FROM domains d JOIN systems s ON s.id = d.system_id
             WHERE d.is_baseline = 1
             ORDER BY s.name, d.name",
            &["system", "name", "bind_ip"],
        )
    }

    /// Lists recent batches.
    pub fn list_batches(&self, limit: usize) -> anyhow::Result<Vec<BatchRow>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, status, started_at, ended_at, report_zip FROM batches ORDER BY started_at DESC LIMIT ?1",
        )?;
        collect_rows(&mut stmt, [limit as i64], |row| {
            Ok(BatchRow {
                id: row.get(0)?,
                status: row.get(1)?,
                started_at: row.get(2)?,
                ended_at: row.get(3)?,
                report_zip: row.get(4)?,
            })
        })
    }

    /// Returns status for a specified or latest batch.
    pub fn batch_status(&self, batch: Option<&str>) -> anyhow::Result<BatchStatus> {
        let conn = self.conn()?;
        let row: BatchRow = match batch {
            Some(batch) => conn.query_row(
                "SELECT id, status, started_at, ended_at, report_zip FROM batches WHERE id = ?1",
                [batch],
                map_batch,
            )?,
            None => conn.query_row(
                "SELECT id, status, started_at, ended_at, report_zip FROM batches ORDER BY started_at DESC LIMIT 1",
                [],
                map_batch,
            )?,
        };
        let alerts: i64 = conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE batch_id = ?1",
            [&row.id],
            |r| r.get(0),
        )?;
        let vulnerabilities: i64 = conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE batch_id = ?1",
            [&row.id],
            |r| r.get(0),
        )?;
        Ok(BatchStatus {
            batch_id: row.id,
            status: row.status,
            started_at: row.started_at,
            ended_at: row.ended_at,
            alerts,
            vulnerabilities,
        })
    }

    /// Lists alerts for a batch.
    pub fn list_alerts(&self, batch_id: &str) -> anyhow::Result<Vec<Alert>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT a.id, a.batch_id, a.system_id, s.name, a.kind, a.severity, a.subject, a.old_value, a.new_value, a.details, a.created_at
             FROM alerts a
             LEFT JOIN systems s ON s.id = a.system_id
             WHERE a.batch_id = ?1
             ORDER BY a.created_at",
        )?;
        collect_rows(&mut stmt, [batch_id], |row| {
            let created_at: String = row.get(10)?;
            Ok(Alert {
                id: row.get(0)?,
                batch_id: row.get(1)?,
                system_id: row.get(2)?,
                system_name: row.get(3)?,
                kind: row.get(4)?,
                severity: row.get(5)?,
                subject: row.get(6)?,
                old_value: row.get(7)?,
                new_value: row.get(8)?,
                details: row.get(9)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            })
        })
    }

    /// Lists vulnerabilities for a batch.
    pub fn list_vulnerabilities(&self, batch_id: &str) -> anyhow::Result<Vec<Vulnerability>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT v.id, v.batch_id, v.system_id, s.name, v.url, v.poc, v.severity, v.evidence, v.created_at
             FROM vulnerabilities v
             JOIN systems s ON s.id = v.system_id
             WHERE v.batch_id = ?1
             ORDER BY v.created_at",
        )?;
        collect_rows(&mut stmt, [batch_id], |row| {
            let created_at: String = row.get(8)?;
            Ok(Vulnerability {
                id: row.get(0)?,
                batch_id: row.get(1)?,
                system_id: row.get(2)?,
                system_name: row.get(3)?,
                url: row.get(4)?,
                poc: row.get(5)?,
                severity: row.get(6)?,
                evidence: row.get(7)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            })
        })
    }

    /// Returns latest batch id.
    pub fn latest_batch_id(&self) -> anyhow::Result<String> {
        let conn = self.conn()?;
        Ok(conn.query_row(
            "SELECT id FROM batches ORDER BY started_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )?)
    }

    /// Adds pending work to be prioritized by future batches.
    pub fn add_pending_work(
        &self,
        batch_id: &str,
        system_id: &str,
        task_kind: &str,
        target: &str,
        priority: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO pending_work (id, batch_id, system_id, task_kind, target, status, priority, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7, ?7)
             ON CONFLICT(task_kind, target) DO UPDATE SET status = 'pending', priority = MIN(priority, excluded.priority), updated_at = excluded.updated_at",
            params![new_id(), batch_id, system_id, task_kind, target, priority, now()],
        )?;
        Ok(())
    }

    /// Takes pending work for a task kind.
    pub fn take_pending_work(
        &self,
        task_kind: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, target FROM pending_work WHERE task_kind = ?1 AND status = 'pending' ORDER BY priority, created_at LIMIT ?2",
        )?;
        let rows = collect_rows(&mut stmt, params![task_kind, limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for (id, _) in &rows {
            conn.execute(
                "UPDATE pending_work SET status = 'running', updated_at = ?1 WHERE id = ?2",
                params![now(), id],
            )?;
        }
        Ok(rows)
    }

    /// Marks pending work as done.
    pub fn finish_pending_work(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE pending_work SET status = 'done', updated_at = ?1 WHERE id = ?2",
            params![now(), id],
        )?;
        Ok(())
    }

    /// Stores an application log event.
    pub fn add_log(
        &self,
        level: &str,
        target: &str,
        message: &str,
        fields: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO logs (id, created_at, level, target, message, fields)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![new_id(), now(), level, target, message, fields],
        )?;
        Ok(())
    }

    /// Queries application logs, newest first.
    pub fn query_logs(
        &self,
        level: Option<&str>,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<LogRow>> {
        let level = level.map(|value| value.to_ascii_uppercase());
        let pattern = keyword
            .map(|value| format!("%{value}%"))
            .unwrap_or_else(|| "%".to_string());
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, created_at, level, target, message, fields
             FROM logs
             WHERE (?1 IS NULL OR level = ?1)
               AND (message LIKE ?2 OR COALESCE(fields, '') LIKE ?2 OR target LIKE ?2)
             ORDER BY created_at DESC
             LIMIT ?3",
        )?;
        collect_rows(
            &mut stmt,
            params![level.as_deref(), pattern, limit as i64],
            map_log,
        )
    }

    /// Exports logs to CSV.
    pub fn export_logs(
        &self,
        file: &Path,
        level: Option<&str>,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<()> {
        let mut writer = csv::Writer::from_path(file)
            .with_context(|| format!("failed to create {}", file.display()))?;
        writer.write_record(["created_at", "level", "target", "message", "fields"])?;
        for row in self.query_logs(level, keyword, limit)? {
            writer.write_record([
                local_time::rfc3339_to_local(&row.created_at),
                row.level,
                row.target,
                row.message,
                row.fields.unwrap_or_default(),
            ])?;
        }
        writer.flush()?;
        Ok(())
    }

    /// Clears application logs and returns the number of deleted rows.
    pub fn clear_logs(&self, before: Option<&str>) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        let deleted = match before {
            Some(before) => conn.execute("DELETE FROM logs WHERE created_at < ?1", [before])?,
            None => conn.execute("DELETE FROM logs", [])?,
        };
        Ok(deleted)
    }

    /// Opens a SQLite connection with foreign keys enabled.
    fn conn(&self) -> anyhow::Result<Connection> {
        let conn = Connection::open(self.path())?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(conn)
    }

    /// Bulk-import simple values for one business system using the supplied upsert SQL.
    fn import_values_for_system(
        &self,
        system: &str,
        values: &[String],
        upsert_sql: &str,
        parameter4: Option<&str>,
        trim_trailing_dot: bool,
    ) -> anyhow::Result<usize> {
        let system = system.trim();
        anyhow::ensure!(!system.is_empty(), "system name must not be empty");
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let system_id = ensure_system_in_tx(&tx, system)?;
        let mut count = 0usize;
        {
            let mut upsert = tx.prepare(upsert_sql)?;
            for value in values {
                let Some(value) = trimmed_opt(Some(value.as_str())) else {
                    continue;
                };
                let value = if trim_trailing_dot {
                    value.trim_end_matches('.')
                } else {
                    value
                };
                anyhow::ensure!(!value.is_empty(), "asset value must not be empty");
                upsert.execute(params![new_id(), system_id, value, parameter4, now()])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// Runs a joined system/value query for asset tables.
    fn query_joined(
        &self,
        table: &str,
        column: &str,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let sql = format!(
            "SELECT s.name, t.{column}, t.is_baseline FROM {table} t JOIN systems s ON s.id = t.system_id WHERE t.{column} LIKE ?1 ORDER BY s.name, t.{column} LIMIT ?2"
        );
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&sql)?;
        collect_rows(&mut stmt, params![pattern, limit as i64], |row| {
            Ok(vec![
                row.get(0)?,
                row.get(1)?,
                bool_text(row.get::<_, i64>(2)? == 1).to_string(),
            ])
        })
    }

    /// Runs a joined query for baseline rows in asset tables.
    fn query_baseline_joined(
        &self,
        table: &str,
        column: &str,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let sql = format!(
            "SELECT s.name, t.{column} FROM {table} t JOIN systems s ON s.id = t.system_id WHERE t.is_baseline = 1 AND (t.{column} LIKE ?1 OR s.name LIKE ?1) ORDER BY s.name, t.{column} LIMIT ?2"
        );
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&sql)?;
        collect_rows(&mut stmt, params![pattern, limit as i64], |row| {
            Ok(vec![row.get(0)?, row.get(1)?])
        })
    }

    /// Runs a simple query for non-system tables.
    fn query_simple(
        &self,
        table: &str,
        column: &str,
        keyword: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let pattern = keyword
            .map(|k| format!("%{k}%"))
            .unwrap_or_else(|| "%".to_string());
        let sql = format!(
            "SELECT {column} FROM {table} WHERE {column} LIKE ?1 ORDER BY {column} LIMIT ?2"
        );
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&sql)?;
        collect_rows(&mut stmt, params![pattern, limit as i64], |row| {
            Ok(vec![row.get(0)?])
        })
    }

    /// Deletes exact value from a table.
    fn delete_by_value(&self, table: &str, column: &str, value: &str) -> anyhow::Result<()> {
        let conn = self.conn()?;
        let sql = format!("DELETE FROM {table} WHERE {column} = ?1");
        conn.execute(&sql, [value])?;
        Ok(())
    }

    /// Deletes exact value from one business system and returns affected rows.
    fn delete_by_system_value(
        &self,
        table: &str,
        column: &str,
        system: &str,
        value: &str,
    ) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        let sql = format!(
            "DELETE FROM {table} WHERE system_id = (SELECT id FROM systems WHERE name = ?1) AND {column} = ?2"
        );
        Ok(conn.execute(&sql, params![system, value])?)
    }

    /// Sets baseline marker by primary key.
    fn set_baseline_by_id(&self, table: &str, id: &str, is_baseline: bool) -> anyhow::Result<()> {
        let conn = self.conn()?;
        let sql = format!("UPDATE {table} SET is_baseline = ?1 WHERE id = ?2");
        conn.execute(&sql, params![is_baseline as i64, id])?;
        Ok(())
    }

    /// Sets baseline marker for an exact value scoped to one business system.
    fn set_baseline_by_system_value(
        &self,
        table: &str,
        column: &str,
        system: &str,
        value: &str,
        is_baseline: bool,
    ) -> anyhow::Result<usize> {
        let conn = self.conn()?;
        let sql = format!(
            "UPDATE {table} SET is_baseline = ?1 WHERE system_id = (SELECT id FROM systems WHERE name = ?2) AND {column} = ?3"
        );
        Ok(conn.execute(&sql, params![is_baseline as i64, system, value])?)
    }

    /// Adds a column when an older SQLite database does not yet contain it.
    fn ensure_column(&self, table: &str, column: &str, definition: &str) -> anyhow::Result<bool> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = collect_rows(&mut stmt, [], |row| Ok(row.get::<_, String>(1)?))?;
        if columns.iter().any(|existing| existing == column) {
            return Ok(false);
        }
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )?;
        Ok(true)
    }

    /// Backfills baseline markers for older databases created before `is_baseline`.
    fn mark_existing_imports_as_baseline(
        &self,
        domains: bool,
        ips: bool,
        ports: bool,
        urls: bool,
    ) -> anyhow::Result<()> {
        let conn = self.conn()?;
        if domains {
            conn.execute(
                "UPDATE domains SET is_baseline = 1 WHERE is_baseline = 0",
                [],
            )?;
        }
        if ips {
            conn.execute(
                "UPDATE ip_addresses SET is_baseline = 1 WHERE is_baseline = 0 AND source IN ('imported', 'manual')",
                [],
            )?;
        }
        if ports {
            conn.execute(
                "UPDATE ports SET is_baseline = 1 WHERE is_baseline = 0 AND source IN ('imported', 'manual')",
                [],
            )?;
        }
        if urls {
            conn.execute(
                "UPDATE urls SET is_baseline = 1 WHERE is_baseline = 0 AND source IN ('imported', 'manual')",
                [],
            )?;
        }
        Ok(())
    }

    /// Exports a fixed query to CSV.
    fn export_query(&self, file: &Path, sql: &str, headers: &[&str]) -> anyhow::Result<()> {
        let mut writer = csv::Writer::from_path(file)
            .with_context(|| format!("failed to create {}", file.display()))?;
        writer.write_record(headers)?;
        let conn = self.conn()?;
        let mut stmt = conn.prepare(sql)?;
        let column_count = stmt.column_count();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let mut record = Vec::with_capacity(column_count);
            for index in 0..column_count {
                let value = row
                    .get_ref(index)?
                    .as_str()
                    .map(str::to_string)
                    .or_else(|_| row.get::<_, i64>(index).map(|v| v.to_string()))
                    .unwrap_or_default();
                record.push(value);
            }
            writer.write_record(record)?;
        }
        writer.flush()?;
        Ok(())
    }
}

/// Collects all rows from a rusqlite statement.
fn collect_rows<T, P, F>(
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

/// Returns an existing system id or inserts the system inside a transaction.
fn ensure_system_in_tx(tx: &rusqlite::Transaction<'_>, name: &str) -> anyhow::Result<String> {
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

/// Returns a system id from a local import cache, inserting and selecting it on cache miss.
fn cached_system_id(
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

/// Trims an optional text field and treats an empty value as absent.
fn trimmed_opt(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// Maps a batch row.
fn map_batch(row: &Row<'_>) -> rusqlite::Result<BatchRow> {
    Ok(BatchRow {
        id: row.get(0)?,
        status: row.get(1)?,
        started_at: row.get(2)?,
        ended_at: row.get(3)?,
        report_zip: row.get(4)?,
    })
}

/// Maps an IP row.
fn map_ip(row: &Row<'_>) -> rusqlite::Result<IpAsset> {
    Ok(IpAsset {
        id: row.get(0)?,
        system_id: row.get(1)?,
        system_name: row.get(2)?,
        ip: row.get(3)?,
        source: row.get(4)?,
        is_baseline: row.get::<_, i64>(5)? == 1,
    })
}

/// Maps a port row.
fn map_port(row: &Row<'_>) -> rusqlite::Result<PortAsset> {
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

/// Maps a URL row.
fn map_url(row: &Row<'_>) -> rusqlite::Result<UrlAsset> {
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

/// Maps an application log row.
fn map_log(row: &Row<'_>) -> anyhow::Result<LogRow> {
    Ok(LogRow {
        id: row.get(0)?,
        created_at: row.get(1)?,
        level: row.get(2)?,
        target: row.get(3)?,
        message: row.get(4)?,
        fields: row.get(5)?,
    })
}

/// Returns a new UUID string.
fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// Returns current UTC timestamp as RFC3339.
fn now() -> String {
    Utc::now().to_rfc3339()
}

/// Normalizes a path dictionary entry.
fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Renders a boolean for tabular output.
fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Query used by `system query`.
const SYSTEM_SUMMARY_SQL: &str = "
    SELECT
        s.name,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id) AS names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id) AS ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id) AS ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id) AS urls,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id AND d.is_baseline = 1) AS baseline_names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id AND i.is_baseline = 1) AS baseline_ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id AND p.is_baseline = 1) AS baseline_ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id AND u.is_baseline = 1) AS baseline_urls,
        s.created_at
    FROM systems s
    WHERE s.name LIKE ?1
    ORDER BY s.name
    LIMIT ?2";

/// Query used by `system export`.
const SYSTEM_EXPORT_SQL: &str = "
    SELECT
        s.name,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id) AS names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id) AS ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id) AS ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id) AS urls,
        (SELECT COUNT(*) FROM domains d WHERE d.system_id = s.id AND d.is_baseline = 1) AS baseline_names,
        (SELECT COUNT(*) FROM ip_addresses i WHERE i.system_id = s.id AND i.is_baseline = 1) AS baseline_ips,
        (SELECT COUNT(*) FROM ports p WHERE p.system_id = s.id AND p.is_baseline = 1) AS baseline_ports,
        (SELECT COUNT(*) FROM urls u WHERE u.system_id = s.id AND u.is_baseline = 1) AS baseline_urls,
        s.created_at
    FROM systems s
    ORDER BY s.name";

/// Maps a system summary row into tabular CLI output.
fn map_system_summary(row: &Row<'_>) -> anyhow::Result<Vec<String>> {
    Ok(vec![
        row.get::<_, String>(0)?,
        row.get::<_, i64>(1)?.to_string(),
        row.get::<_, i64>(2)?.to_string(),
        row.get::<_, i64>(3)?.to_string(),
        row.get::<_, i64>(4)?.to_string(),
        row.get::<_, i64>(5)?.to_string(),
        row.get::<_, i64>(6)?.to_string(),
        row.get::<_, i64>(7)?.to_string(),
        row.get::<_, i64>(8)?.to_string(),
        row.get::<_, String>(9)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_and_upserts_assets() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("watcher.db")).unwrap();
        db.migrate().unwrap();
        db.upsert_baseline_domain_for_system("core", "example.com", Some("1.1.1.1"))
            .unwrap();
        db.upsert_baseline_ip_for_system("core", "10.0.0.1", "imported")
            .unwrap();
        db.upsert_baseline_url_for_system("core", "https://example.com", "imported")
            .unwrap();
        db.import_dict_paths(&["admin".to_string()]).unwrap();
        db.add_log("INFO", "watcher::test", "hello", None).unwrap();

        assert_eq!(db.list_domains().unwrap().len(), 1);
        assert_eq!(db.list_real_ips().unwrap().len(), 1);
        assert_eq!(db.list_urls().unwrap().len(), 1);
        let systems = db.query_systems(None, 10).unwrap();
        assert_eq!(systems.len(), 1);
        assert_eq!(systems[0][0], "core");
        assert_eq!(systems[0][1], "1");
        assert_eq!(systems[0][2], "1");
        assert_eq!(systems[0][4], "1");
        assert_eq!(systems[0][5], "1");
        assert!(db.list_domains().unwrap()[0].is_baseline);
        assert!(db.list_real_ips().unwrap()[0].is_baseline);
        assert!(db.list_urls().unwrap()[0].is_baseline);
        assert_eq!(db.rename_system("core", "core-renamed").unwrap(), 1);
        assert_eq!(
            db.query_systems(Some("renamed"), 10).unwrap()[0][0],
            "core-renamed"
        );
        assert_eq!(
            db.set_name_baseline_for_system("core", "example.com", false)
                .unwrap(),
            0
        );
        db.migrate().unwrap();
        db.set_name_baseline_for_system("core-renamed", "example.com", false)
            .unwrap();
        assert!(!db.list_domains().unwrap()[0].is_baseline);
        assert_eq!(db.list_dict_paths(10).unwrap(), vec!["/admin"]);
        assert_eq!(
            db.query_logs(Some("INFO"), Some("hello"), 10)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(db.delete_system("core-renamed").unwrap(), 1);
        assert!(db.list_domains().unwrap().is_empty());
    }

    #[test]
    fn bulk_imports_baseline_assets_and_creates_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("watcher.db")).unwrap();
        db.migrate().unwrap();

        let summary = db
            .import_baseline_rows(
                &[
                    BaselineImportRow {
                        system: "core".to_string(),
                        name: Some("example.com.".to_string()),
                        bind_ip: Some("10.0.0.1".to_string()),
                        ip: Some("10.0.0.1".to_string()),
                        ports: vec![80, 443],
                        url: Some("https://example.com".to_string()),
                    },
                    BaselineImportRow {
                        system: "core".to_string(),
                        name: Some("example.com".to_string()),
                        bind_ip: None,
                        ip: Some("10.0.0.1".to_string()),
                        ports: vec![80],
                        url: Some("https://example.com".to_string()),
                    },
                ],
                "imported",
            )
            .unwrap();

        assert_eq!(summary.systems, 2);
        assert_eq!(summary.names, 2);
        assert_eq!(summary.ips, 2);
        assert_eq!(summary.ports, 3);
        assert_eq!(summary.urls, 2);

        let systems = db.query_systems(Some("core"), 10).unwrap();
        assert_eq!(systems[0][1], "1");
        assert_eq!(systems[0][2], "1");
        assert_eq!(systems[0][3], "2");
        assert_eq!(systems[0][4], "1");
        assert_eq!(systems[0][5], "1");
        assert_eq!(systems[0][6], "1");
        assert_eq!(systems[0][7], "2");
        assert_eq!(systems[0][8], "1");

        let imported = db
            .import_baseline_ports_for_system("core", None, &[8080, 8080], "manual")
            .unwrap();
        assert_eq!(imported, 2);
        assert_eq!(db.query_systems(Some("core"), 10).unwrap()[0][3], "3");

        let conn = db.conn().unwrap();
        let index_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN (
                    'idx_domains_system_baseline_name',
                    'idx_ips_system_baseline_ip',
                    'idx_ports_system_baseline_port',
                    'idx_urls_system_baseline_url',
                    'idx_pending_work_take'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index_count, 5);
    }

    #[test]
    fn bulk_imports_non_baseline_entity_assets() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("watcher.db")).unwrap();
        db.migrate().unwrap();

        db.upsert_baseline_ip_for_system("core", "10.0.0.1", "manual")
            .unwrap();
        db.upsert_baseline_url_for_system("core", "https://example.com", "manual")
            .unwrap();
        db.upsert_baseline_domain_for_system("core", "example.com", None)
            .unwrap();
        db.upsert_baseline_port_for_system("core", Some("10.0.0.1"), 443, "manual")
            .unwrap();

        assert_eq!(
            db.import_ips_for_system(
                "core",
                &["10.0.0.1".to_string(), "10.0.0.2".to_string()],
                "manual",
            )
            .unwrap(),
            2
        );
        assert_eq!(
            db.import_urls_for_system(
                "core",
                &[
                    "https://example.com".to_string(),
                    "https://example.com/login".to_string(),
                ],
                "manual",
            )
            .unwrap(),
            2
        );
        assert_eq!(
            db.import_names_for_system(
                "core",
                &["example.com.".to_string(), "www.example.com".to_string()],
                Some("10.0.0.2"),
            )
            .unwrap(),
            2
        );
        assert_eq!(
            db.import_ports_for_system("core", Some("10.0.0.1"), &[443, 8443], "manual")
                .unwrap(),
            2
        );

        let systems = db.query_systems(Some("core"), 10).unwrap();
        assert_eq!(systems[0][1], "2");
        assert_eq!(systems[0][2], "2");
        assert_eq!(systems[0][3], "2");
        assert_eq!(systems[0][4], "2");
        assert_eq!(systems[0][5], "1");
        assert_eq!(systems[0][6], "1");
        assert_eq!(systems[0][7], "1");
        assert_eq!(systems[0][8], "1");
    }

    #[test]
    fn bulk_imports_dict_paths() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("watcher.db")).unwrap();
        db.migrate().unwrap();

        let count = db
            .import_dict_paths(&[
                "admin".to_string(),
                "/login".to_string(),
                "admin".to_string(),
                " ".to_string(),
            ])
            .unwrap();

        assert_eq!(count, 3);
        assert_eq!(db.list_dict_paths(10).unwrap(), vec!["/admin", "/login"]);
    }

    #[test]
    fn interrupts_leftover_running_batches_before_new_batch() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("watcher.db")).unwrap();
        db.migrate().unwrap();

        let stale = db.create_batch().unwrap();
        let fresh = db.create_batch().unwrap();

        let stale_status = db.batch_status(Some(&stale.id)).unwrap();
        assert_eq!(stale_status.status, "interrupted");
        let fresh_status = db.batch_status(Some(&fresh.id)).unwrap();
        assert_eq!(fresh_status.status, "running");
    }
}

//! Slow and conservative TCP port scanning.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use futures::{StreamExt, stream};
use rand::seq::SliceRandom;
use tokio::{net::TcpStream, task::yield_now, time::timeout};
use tracing::{info, warn};

use crate::{config::AppConfig, db::Database, models::BatchContext};

/// Scans configured ports on every imported/manual real IP and records port changes.
pub async fn run(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
    let ips = db.list_real_ips()?;
    let ports = Arc::new(config.scan_ports()?);
    let ip_count = ips.len();
    let port_count = ports.len();
    let ip_concurrency = config.scan_ip_concurrency();
    let port_concurrency = config.scan_port_concurrency_per_ip();
    let timeout_duration = config.connect_timeout();
    let db_clone = db.clone();
    let started = Instant::now();
    let completed_ips = Arc::new(AtomicUsize::new(0));
    let open_ports = Arc::new(AtomicUsize::new(0));
    let progress_interval = port_scan_progress_interval(ip_count);

    info!(
        ip_concurrency,
        port_concurrency_per_ip = port_concurrency,
        effective_parallelism = ip_concurrency * port_concurrency,
        ip_count,
        port_count,
        "port scan started"
    );

    let scan_ports = Arc::clone(&ports);
    let scan_completed_ips = Arc::clone(&completed_ips);
    let scan_open_ports = Arc::clone(&open_ports);
    stream::iter(ips)
        .for_each_concurrent(ip_concurrency, move |ip| {
            let db = db_clone.clone();
            let ports = Arc::clone(&scan_ports);
            let batch_id = batch.id.clone();
            let completed_ips = Arc::clone(&scan_completed_ips);
            let open_ports = Arc::clone(&scan_open_ports);
            async move {
                let shuffled_ports = shuffled_ports(&ports);
                let scan_ip = ip.clone();
                let open_ports_for_ip = Arc::clone(&open_ports);
                stream::iter(shuffled_ports)
                    .for_each_concurrent(port_concurrency, move |port| {
                        let db = db.clone();
                        let ip = scan_ip.clone();
                        let batch_id = batch_id.clone();
                        let open_ports = Arc::clone(&open_ports_for_ip);
                        async move {
                            match db.should_stop_batch(&batch_id) {
                                Ok(true) => return,
                                Ok(false) => {}
                                Err(error) => {
                                    warn!(%error, "failed to check stop flag");
                                    return;
                                }
                            }
                            let open = is_open(&ip.ip, port, timeout_duration).await;
                            if open {
                                open_ports.fetch_add(1, Ordering::Relaxed);
                            }
                            if let Err(error) = db.record_port_state(
                                &batch_id,
                                &ip.system_id,
                                &ip.id,
                                &ip.ip,
                                port,
                                open,
                            ) {
                                warn!(ip = %ip.ip, port, %port, %error, "failed to record port state");
                            }

                            // Some networks fail closed ports immediately. Yield after each
                            // result so one IP cannot monopolize the executor and make other
                            // active IP scans appear sequential.
                            yield_now().await;
                        }
                    })
                    .await;
                let completed = completed_ips.fetch_add(1, Ordering::Relaxed) + 1;
                if should_log_port_scan_progress(completed, ip_count, progress_interval) {
                    info!(
                        completed_ips = completed,
                        ip_count,
                        progress = %format!("{completed}/{ip_count}"),
                        open_ports = open_ports.load(Ordering::Relaxed),
                        elapsed_ms = started.elapsed().as_millis(),
                        "port scan progress"
                    );
                }
            }
        })
        .await;

    info!(
        completed_ips = completed_ips.load(Ordering::Relaxed),
        ip_count,
        port_count,
        open_ports = open_ports.load(Ordering::Relaxed),
        elapsed_ms = started.elapsed().as_millis(),
        "port scan finished"
    );

    Ok(())
}

/// Returns how often port scan progress should be logged.
fn port_scan_progress_interval(ip_count: usize) -> usize {
    match ip_count {
        0..=100 => ip_count.max(1),
        _ => (ip_count / 100).max(100),
    }
}

/// Returns true when a completed-IP count should emit an aggregate progress log.
fn should_log_port_scan_progress(completed: usize, total: usize, interval: usize) -> bool {
    completed == total || completed.is_multiple_of(interval.max(1))
}

/// Returns a randomized copy of the configured port list for one IP scan.
fn shuffled_ports(ports: &[u16]) -> Vec<u16> {
    let mut ports = ports.to_vec();
    let mut rng = rand::rng();
    ports.shuffle(&mut rng);
    ports
}

/// Returns true when a TCP connection can be established within the timeout.
async fn is_open(ip: &str, port: u16, timeout_duration: std::time::Duration) -> bool {
    let target = format!("{ip}:{port}");
    matches!(
        timeout(timeout_duration, TcpStream::connect(target)).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffled_ports_preserves_port_set() {
        let ports = vec![1, 2, 3, 4, 5];
        let mut shuffled = shuffled_ports(&ports);
        shuffled.sort_unstable();
        assert_eq!(shuffled, ports);
    }

    #[test]
    fn progress_interval_keeps_large_scans_coarse() {
        assert_eq!(port_scan_progress_interval(0), 1);
        assert_eq!(port_scan_progress_interval(2), 2);
        assert_eq!(port_scan_progress_interval(10_000), 100);
        assert_eq!(port_scan_progress_interval(100_000), 1_000);
    }

    #[test]
    fn progress_logs_on_interval_and_completion() {
        assert!(!should_log_port_scan_progress(999, 100_000, 1_000));
        assert!(should_log_port_scan_progress(1_000, 100_000, 1_000));
        assert!(should_log_port_scan_progress(100_000, 100_000, 1_000));
    }
}

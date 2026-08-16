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

use crate::{
    config::AppConfig,
    db::Database,
    models::BatchContext,
    monitor::progress::{scan_progress_interval, should_log_scan_progress},
};

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
    let progress_interval = scan_progress_interval(ip_count);

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
                match db.should_stop_batch(&batch_id) {
                    Ok(true) => {
                        let completed = completed_ips.fetch_add(1, Ordering::Relaxed) + 1;
                        if should_log_scan_progress(completed, ip_count, progress_interval) {
                            info!(
                                completed_ips = completed,
                                ip_count,
                                progress = %format!("{completed}/{ip_count}"),
                                open_ports = open_ports.load(Ordering::Relaxed),
                                elapsed_ms = started.elapsed().as_millis(),
                                "port scan progress"
                            );
                        }
                        return;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        warn!(%error, "failed to check stop flag");
                        return;
                    }
                }

                let shuffled_ports = shuffled_ports(&ports);
                let probed_ports = u32::try_from(shuffled_ports.len()).unwrap_or(u32::MAX);
                let mut opened = Vec::new();
                let mut probes = stream::iter(shuffled_ports)
                    .map(|port| {
                        let ip_addr = ip.ip.clone();
                        async move {
                            let open = is_open(&ip_addr, port, timeout_duration).await;
                            yield_now().await;
                            (port, open)
                        }
                    })
                    .buffer_unordered(port_concurrency);

                while let Some((port, open)) = probes.next().await {
                    if open {
                        opened.push(port);
                        open_ports.fetch_add(1, Ordering::Relaxed);
                    }
                }

                opened.sort_unstable();
                if let Err(error) = db.record_ip_scan(
                    &batch_id,
                    &ip.system_id,
                    &ip.id,
                    &ip.ip,
                    &opened,
                    probed_ports,
                    true,
                ) {
                    warn!(ip = %ip.ip, %error, "failed to record ip scan");
                }

                let completed = completed_ips.fetch_add(1, Ordering::Relaxed) + 1;
                if should_log_scan_progress(completed, ip_count, progress_interval) {
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
}

//! Slow and conservative TCP port scanning.

use std::sync::Arc;

use futures::{StreamExt, stream};
use rand::seq::SliceRandom;
use tokio::{net::TcpStream, task::yield_now, time::timeout};
use tracing::{info, warn};

use crate::{config::AppConfig, db::Database, models::BatchContext};

/// Scans configured ports on every imported/manual real IP and records port changes.
pub async fn run(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
    let ips = db.list_real_ips()?;
    let ports = Arc::new(config.scan_ports()?);
    let ip_concurrency = config.scan_ip_concurrency();
    let port_concurrency = config.scan_port_concurrency_per_ip();
    let timeout_duration = config.connect_timeout();
    let db_clone = db.clone();

    info!(
        ip_concurrency,
        port_concurrency_per_ip = port_concurrency,
        effective_parallelism = ip_concurrency * port_concurrency,
        port_count = ports.len(),
        "port scan started"
    );

    stream::iter(ips)
        .for_each_concurrent(ip_concurrency, move |ip| {
            let db = db_clone.clone();
            let ports = Arc::clone(&ports);
            let batch_id = batch.id.clone();
            async move {
                info!(
                    ip = %ip.ip,
                    system = %ip.system_name,
                    port_count = ports.len(),
                    port_concurrency,
                    "port scan ip started"
                );
                let shuffled_ports = shuffled_ports(&ports);
                let scan_ip = ip.clone();
                stream::iter(shuffled_ports)
                    .for_each_concurrent(port_concurrency, move |port| {
                        let db = db.clone();
                        let ip = scan_ip.clone();
                        let batch_id = batch_id.clone();
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
                info!(
                    ip = %ip.ip,
                    system = %ip.system_name,
                    "port scan ip finished"
                );
            }
        })
        .await;

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

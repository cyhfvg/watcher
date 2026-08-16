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

/// 对每个已导入 / 手工真实 IP 扫描配置端口, 并记录端口变化.
///
/// # 参数
///
/// - `db`: IP 资产和扫描结果的数据库句柄.
/// - `config`: 读取扫描端口集, 并发和连接超时.
/// - `batch`: 当前监测批次.
///
/// # 返回
///
/// 全部 IP 处理完成后返回 `Ok(())`.
///
/// # Errors
///
/// 列出 IP 或展开扫描端口失败时返回错误. 单 IP 记录失败只记日志.
///
/// # 示例
///
/// ```no_run
/// # use watcher::{config::AppConfig, db::Database, models::BatchContext, monitor::ports};
/// # async fn demo(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
/// ports::run(db, config, batch).await?;
/// # Ok(())
/// # }
/// ```
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

/// 返回打乱顺序后的端口列表副本, 降低扫描规律性.
///
/// # 参数
///
/// - `ports`: 配置的端口集合.
///
/// # 返回
///
/// 元素相同但顺序随机的新 `Vec`.
///
/// # 示例
///
/// ```text
/// let shuffled = shuffled_ports(&ports);
/// ```
fn shuffled_ports(ports: &[u16]) -> Vec<u16> {
    let mut ports = ports.to_vec();
    let mut rng = rand::rng();
    ports.shuffle(&mut rng);
    ports
}

/// 在超时内尝试建立 TCP 连接, 判断端口是否开放.
///
/// # 参数
///
/// - `ip`: 目标 IP.
/// - `port`: 目标 TCP 端口.
/// - `timeout_duration`: 连接超时.
///
/// # 返回
///
/// 连接成功建立时返回 `true`.
///
/// # 示例
///
/// ```text
/// let open = is_open(&ip, port, timeout_duration).await;
/// ```
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

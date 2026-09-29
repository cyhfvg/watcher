//! Slow and conservative TCP port scanning.

use std::{
    io::ErrorKind,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
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

/// Scans configured ports on every imported / manual real IP and records
/// port changes.
///
/// # Arguments
///
/// - `db`: database handle for IP assets and scan results.
/// - `config`: reads the scan port set, concurrency, and connect timeout.
/// - `batch`: current monitoring batch.
///
/// # Returns
///
/// `Ok(())` after every IP has been processed.
///
/// # Errors
///
/// Returns an error if IPs cannot be listed or scan ports cannot be expanded.
/// Per-IP record failures are logged only.
///
/// # Examples
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
    let (ip_concurrency, port_concurrency) = config.scan_concurrency_budget();
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
                        info!(ip = %ip.ip, "port scan skipped ip because stop was requested");
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
                let mut confirmed_closed = Vec::new();
                let mut inconclusive = false;
                let mut stopped = false;
                let stop_new = Arc::new(AtomicBool::new(false));
                let mut seen = 0usize;
                let mut probes = stream::iter(shuffled_ports)
                    .map(|port| {
                        let ip_addr = ip.ip.clone();
                        let stop_new = Arc::clone(&stop_new);
                        async move {
                            if stop_new.load(Ordering::Relaxed) {
                                return (port, None);
                            }
                            let outcome = probe_port(&ip_addr, port, timeout_duration).await;
                            yield_now().await;
                            (port, Some(outcome))
                        }
                    })
                    .buffer_unordered(port_concurrency);

                while let Some((port, outcome)) = probes.next().await {
                    let Some(outcome) = outcome else {
                        stopped = true;
                        continue;
                    };
                    match outcome {
                        ProbeOutcome::Open => {
                            opened.push(port);
                            open_ports.fetch_add(1, Ordering::Relaxed);
                        }
                        ProbeOutcome::Refused => confirmed_closed.push(port),
                        ProbeOutcome::Inconclusive => inconclusive = true,
                    }
                    seen += 1;
                    if !stop_new.load(Ordering::Relaxed)
                        && seen.is_multiple_of(16)
                        && matches!(db.should_stop_batch(&batch_id), Ok(true))
                    {
                        stop_new.store(true, Ordering::Relaxed);
                        stopped = true;
                    }
                }

                opened.sort_unstable();
                confirmed_closed.sort_unstable();
                let scan_complete = !inconclusive && !stopped;
                if inconclusive || stopped {
                    warn!(
                        ip = %ip.ip,
                        open = opened.len(),
                        confirmed_closed = confirmed_closed.len(),
                        stopped,
                        "port scan incomplete; timed-out or unreachable ports keep previous state"
                    );
                }
                if let Err(error) = db.record_ip_scan(
                    &batch_id,
                    &ip.system_id,
                    &ip.id,
                    &ip.ip,
                    &opened,
                    &confirmed_closed,
                    probed_ports,
                    scan_complete,
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

/// Returns a shuffled copy of the port list to reduce scan regularity.
///
/// # Arguments
///
/// - `ports`: configured port set.
///
/// # Returns
///
/// New `Vec` with the same elements in random order.
///
/// # Examples
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

/// TCP probe result. Only a confirmed refusal is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeOutcome {
    /// Handshake completed.
    Open,
    /// `ECONNREFUSED` on the attempt that decides the result.
    Refused,
    /// Timeout, unreachable, reset, or an address that could not be parsed.
    Inconclusive,
}

/// Probes one TCP port. A refusal is probed once more before it can close a port.
///
/// # Arguments
///
/// - `ip`: target IP text. IPv6 literals are not rewritten.
/// - `port`: target TCP port.
/// - `timeout_duration`: per-attempt connect timeout.
///
/// # Returns
///
/// `Open` when either attempt connects. `Refused` only when the confirming
/// attempt is also refused. Every other failure is `Inconclusive`.
///
/// # Examples
///
/// ```text
/// let outcome = probe_port(&ip, port, timeout_duration).await;
/// ```
async fn probe_port(ip: &str, port: u16, timeout_duration: Duration) -> ProbeOutcome {
    match connect_once(ip, port, timeout_duration).await {
        ProbeOutcome::Refused => connect_once(ip, port, timeout_duration).await,
        other => other,
    }
}

/// Classifies one connect attempt.
///
/// # Arguments
///
/// - `ip`: target IP text.
/// - `port`: target TCP port.
/// - `timeout_duration`: connect timeout.
///
/// # Returns
///
/// `Open`, `Refused`, or `Inconclusive`.
///
/// # Examples
///
/// ```text
/// let outcome = connect_once(&ip, port, timeout_duration).await;
/// ```
async fn connect_once(ip: &str, port: u16, timeout_duration: Duration) -> ProbeOutcome {
    let target = format!("{ip}:{port}");
    match timeout(timeout_duration, TcpStream::connect(target)).await {
        Ok(Ok(_)) => ProbeOutcome::Open,
        Ok(Err(error)) => classify_connect_error(&error),
        Err(_) => ProbeOutcome::Inconclusive,
    }
}

/// Maps a connect error to a probe outcome.
///
/// # Arguments
///
/// - `error`: error returned by `TcpStream::connect`.
///
/// # Returns
///
/// `Refused` only for `ErrorKind::ConnectionRefused`.
///
/// # Examples
///
/// ```text
/// let outcome = classify_connect_error(&error);
/// ```
fn classify_connect_error(error: &std::io::Error) -> ProbeOutcome {
    if error.kind() == ErrorKind::ConnectionRefused {
        ProbeOutcome::Refused
    } else {
        ProbeOutcome::Inconclusive
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn shuffled_ports_preserves_port_set() {
        let ports = vec![1, 2, 3, 4, 5];
        let mut shuffled = shuffled_ports(&ports);
        shuffled.sort_unstable();
        assert_eq!(shuffled, ports);
    }

    #[test]
    fn only_connection_refused_is_a_close() {
        let refused = std::io::Error::from(ErrorKind::ConnectionRefused);
        assert_eq!(classify_connect_error(&refused), ProbeOutcome::Refused);
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
            ErrorKind::ConnectionReset,
            ErrorKind::InvalidInput,
        ] {
            let error = std::io::Error::from(kind);
            assert_eq!(classify_connect_error(&error), ProbeOutcome::Inconclusive);
        }
    }

    #[tokio::test]
    async fn open_listener_is_open_and_dropped_port_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let open = probe_port("127.0.0.1", port, Duration::from_secs(1)).await;
        assert_eq!(open, ProbeOutcome::Open);
        drop(listener);

        let refused = probe_port("127.0.0.1", port, Duration::from_secs(1)).await;
        assert_eq!(refused, ProbeOutcome::Refused);
    }

    #[tokio::test]
    async fn malformed_socket_text_is_inconclusive() {
        let outcome = probe_port("not a socket", 80, Duration::from_millis(200)).await;
        assert_eq!(outcome, ProbeOutcome::Inconclusive);
    }
}

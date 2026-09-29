//! Per-host request rate limiting for web enumeration.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use tokio::time::sleep;
use url::Url;

/// Serializes requests per host so one target sees at most one request per
/// delay window, while different hosts never wait on each other.
pub(super) struct HostLimiter {
    last: Mutex<HashMap<String, Instant>>,
}

impl HostLimiter {
    pub(super) fn new() -> Self {
        Self {
            last: Mutex::new(HashMap::new()),
        }
    }

    pub(super) async fn wait(&self, url: &str, delay: Duration) {
        if delay.is_zero() {
            return;
        }
        let host = Url::parse(url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_owned));
        let Some(host) = host else {
            sleep(delay).await;
            return;
        };
        let wait_for = {
            let mut last = self
                .last
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = Instant::now();
            let reserved = last
                .get(&host)
                .copied()
                .unwrap_or(now)
                .checked_add(delay)
                .unwrap_or(now);
            last.insert(host, reserved);
            reserved.saturating_duration_since(now)
        };
        if !wait_for.is_zero() {
            sleep(wait_for).await;
        }
    }
}

/// Returns the origin (`scheme://host:port`) of an absolute URL.
///
/// # Arguments
///
/// - `url`: absolute URL text.
///
/// # Returns
///
/// `None` when the URL cannot be parsed.
///
/// # Examples
///
/// ```text
/// let origin = url_origin("http://example.com/a");
/// ```
pub(super) fn url_origin(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .map(|parsed| parsed.origin().ascii_serialization())
}

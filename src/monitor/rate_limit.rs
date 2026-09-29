//! Per-key token-bucket rate limiting.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use tokio::time::sleep;

/// A token bucket per key.
///
/// Each key owns an independent bucket with `burst` tokens, refilled at one
/// token per `interval`. `acquire` blocks until a token is available, so a
/// single target never receives more than `burst` requests in a row and is
/// throttled to roughly one request per `interval` after the burst.
pub(crate) struct TokenBucket {
    interval: Duration,
    burst: u64,
    state: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: u64,
    last: Instant,
}

impl TokenBucket {
    /// Creates a token bucket. `burst = 0` or a zero interval disables limiting.
    ///
    /// # Arguments
    /// - `interval`: time to refill one token per key.
    /// - `burst`: bucket capacity; the maximum immediate burst per key.
    ///
    /// # Returns
    /// New [`TokenBucket`].
    ///
    /// # Examples
    /// ```text
    /// let bucket = TokenBucket::new(Duration::from_millis(100), 1);
    /// ```
    pub(crate) fn new(interval: Duration, burst: u64) -> Self {
        Self {
            interval,
            burst,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Waits for a token for `key`.
    ///
    /// # Arguments
    /// - `key`: target identity, e.g. an IP address or URL host.
    ///
    /// # Examples
    /// ```text
    /// bucket.acquire(&ip).await;
    /// ```
    pub(crate) async fn acquire(&self, key: &str) {
        if self.interval.is_zero() || self.burst == 0 {
            return;
        }
        let interval_nanos = self.interval.as_nanos().max(1) as u64;
        loop {
            let wait = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let now = Instant::now();
                let bucket = state.entry(key.to_string()).or_insert(Bucket {
                    tokens: self.burst,
                    last: now,
                });
                let elapsed = now.duration_since(bucket.last).as_nanos() as u64;
                let earned = elapsed / interval_nanos;
                if earned > 0 {
                    bucket.tokens = bucket.tokens.saturating_add(earned).min(self.burst);
                    bucket.last = now;
                }
                if bucket.tokens > 0 {
                    bucket.tokens -= 1;
                    None
                } else {
                    Some(Duration::from_nanos(
                        interval_nanos - elapsed % interval_nanos,
                    ))
                }
            };
            match wait {
                Some(wait) => sleep(wait).await,
                None => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn different_keys_do_not_block_each_other() {
        let bucket = TokenBucket::new(Duration::from_millis(100), 1);
        let started = Instant::now();
        bucket.acquire("a").await;
        bucket.acquire("b").await;
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn same_key_is_throttled_to_interval() {
        let bucket = TokenBucket::new(Duration::from_millis(50), 1);
        let started = Instant::now();
        bucket.acquire("a").await;
        bucket.acquire("a").await;
        assert!(started.elapsed() >= Duration::from_millis(40));
    }

    #[tokio::test]
    async fn zero_interval_disables_limiting() {
        let bucket = TokenBucket::new(Duration::ZERO, 1);
        let started = Instant::now();
        for _ in 0..100 {
            bucket.acquire("a").await;
        }
        assert!(started.elapsed() < Duration::from_millis(50));
    }
}

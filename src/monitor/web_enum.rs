//! Slow web directory enumeration and lightweight page parsing.

use std::collections::BTreeSet;

use futures::{StreamExt, stream};
use regex::Regex;
use reqwest::Client;
use tokio::time::sleep;
use tracing::warn;
use url::Url;

use crate::{
    config::AppConfig,
    db::Database,
    models::{BatchContext, PortAsset},
    monitor::fingerprint::http_client,
};

/// Enumerates paths for identified web services and records valuable URL assets.
pub async fn run(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
    let client = http_client(config)?;
    replay_pending_work(db, &client, config, batch).await?;

    let services = db.list_web_services()?;
    let dict = db.list_dict_paths(config.web.max_paths_per_service)?;
    let concurrency = config.probe.concurrency.clamp(1, 8);
    let db_clone = db.clone();

    stream::iter(services)
        .for_each_concurrent(concurrency, move |service| {
            let db = db_clone.clone();
            let client = client.clone();
            let dict = dict.clone();
            let batch_id = batch.id.clone();
            async move {
                if let Err(error) =
                    enumerate_service(&db, &client, config, &batch_id, &service, &dict).await
                {
                    warn!(service = ?service, %error, "web enumeration failed");
                }
            }
        })
        .await;
    Ok(())
}

/// Replays old unfinished web-enumeration URLs before new work.
async fn replay_pending_work(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch: &BatchContext,
) -> anyhow::Result<()> {
    for (id, target) in db.take_pending_work("web_enum", 100)? {
        if db.should_stop_batch(&batch.id)? {
            break;
        }
        let _ = fetch_candidate(client, &target, config).await;
        db.finish_pending_work(&id)?;
        sleep(config.per_target_delay()).await;
    }
    Ok(())
}

/// Enumerates one web service with dictionary paths and JS-discovered paths.
async fn enumerate_service(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch_id: &str,
    service: &PortAsset,
    dict: &[String],
) -> anyhow::Result<()> {
    let bases = service_base_urls(db, service)?;

    let mut js_paths = BTreeSet::new();
    for base in bases {
        db.upsert_url(&service.system_id, base.as_str(), "discovered", None, 20)?;

        if let Some(result) = fetch_candidate(client, base.as_str(), config).await? {
            db.upsert_url(
                &service.system_id,
                base.as_str(),
                "discovered",
                Some(result.status),
                result.score,
            )?;
            js_paths.extend(extract_interesting_paths(&result.body, &base));
        }

        for path in dict {
            if db.should_stop_batch(batch_id)? {
                db.add_pending_work(batch_id, &service.system_id, "web_enum", base.as_str(), 10)?;
                break;
            }
            let candidate = base.join(path.trim_start_matches('/'))?;
            if let Some(result) = fetch_candidate(client, candidate.as_str(), config).await?
                && result.score > 0
            {
                db.upsert_url(
                    &service.system_id,
                    candidate.as_str(),
                    "discovered",
                    Some(result.status),
                    result.score,
                )?;
                if result.status == 200 {
                    js_paths.extend(extract_interesting_paths(&result.body, &candidate));
                }
            }
            sleep(config.per_target_delay()).await;
        }
    }

    for target in js_paths
        .into_iter()
        .take(config.web.max_js_paths_per_service)
    {
        if db.should_stop_batch(batch_id)? {
            db.add_pending_work(batch_id, &service.system_id, "web_enum", &target, 5)?;
            continue;
        }
        if let Some(result) = fetch_candidate(client, &target, config).await?
            && result.score > 0
        {
            db.upsert_url(
                &service.system_id,
                &target,
                "js_discovered",
                Some(result.status),
                result.score,
            )?;
        }
        sleep(config.per_target_delay()).await;
    }

    Ok(())
}

/// HTTP fetch result for an enumeration candidate.
#[derive(Debug)]
struct CandidateResult {
    /// HTTP status code.
    status: u16,
    /// Response body prefix.
    body: String,
    /// Value score; zero means ignore.
    score: i64,
}

/// Fetches a candidate URL and scores whether it is valuable.
async fn fetch_candidate(
    client: &Client,
    url: &str,
    config: &AppConfig,
) -> anyhow::Result<Option<CandidateResult>> {
    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    let body_prefix = body.chars().take(256_000).collect::<String>();
    let score = value_score(status, &body_prefix, &config.web.negative_body_markers);
    Ok(Some(CandidateResult {
        status,
        body: body_prefix,
        score,
    }))
}

/// Assigns a value score for report prioritization.
fn value_score(status: u16, body: &str, negative_markers: &[String]) -> i64 {
    if negative_markers.iter().any(|marker| body.contains(marker)) {
        return 0;
    }
    match status {
        200 => 50,
        401 | 403 => 80,
        301 | 302 | 307 | 308 => 30,
        204 => 20,
        _ => 0,
    }
}

/// Builds base URLs for both `ip:port` and `name:port` web access.
fn service_base_urls(db: &Database, service: &PortAsset) -> anyhow::Result<Vec<Url>> {
    let mut values = BTreeSet::new();
    let scheme = service.scheme.as_deref().unwrap_or("http");
    let ip = service.ip.as_deref().unwrap_or("127.0.0.1");
    values.insert(host_base_url(scheme, ip, service.port)?);
    for domain in db.list_domains_for_system(&service.system_id)? {
        values.insert(host_base_url(scheme, &domain.name, service.port)?);
    }
    Ok(values.into_iter().collect())
}

/// Builds a base URL for one host and scheme/port combination.
fn host_base_url(scheme: &str, host: &str, port: u16) -> anyhow::Result<Url> {
    let text = if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        format!("{scheme}://{host}/")
    } else {
        format!("{scheme}://{host}:{port}/")
    };
    Ok(Url::parse(&text)?)
}

/// Extracts absolute URLs from HTML/JS path references.
fn extract_interesting_paths(body: &str, base: &Url) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let regex = Regex::new(r#"(?i)(?:src|href)\s*=\s*["']([^"']+)["']|["']((?:/[a-zA-Z0-9_./-]+|[a-zA-Z0-9_./-]+\.(?:js|html|json|action|do)))["']"#)
        .expect("static regex must compile");
    for capture in regex.captures_iter(body) {
        let candidate = capture
            .get(1)
            .or_else(|| capture.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        if candidate.starts_with("javascript:") || candidate.starts_with('#') {
            continue;
        }
        if let Ok(url) = base.join(candidate)
            && url.scheme().starts_with("http")
        {
            values.insert(url.to_string());
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_fake_gateway_200() {
        let markers = vec!["接口不存在".to_string(), "code=404".to_string()];
        assert_eq!(value_score(200, "xxx接口不存在，code=404", &markers), 0);
        assert_eq!(value_score(403, "forbidden", &markers), 80);
    }

    #[test]
    fn builds_host_base_urls_with_default_port_elision() {
        assert_eq!(
            host_base_url("http", "example.com", 80)
                .unwrap()
                .to_string(),
            "http://example.com/"
        );
        assert_eq!(
            host_base_url("https", "example.com", 8443)
                .unwrap()
                .to_string(),
            "https://example.com:8443/"
        );
    }
}

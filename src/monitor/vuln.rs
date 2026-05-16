//! Lightweight vulnerability checks.

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
    models::{BatchContext, UrlAsset},
    monitor::fingerprint::http_client,
};

/// Runs lightweight POCs against URL assets.
pub async fn run(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
    let client = http_client(config)?;
    replay_pending_work(db, &client, config, batch).await?;

    let urls = db.list_urls()?;
    let concurrency = config.probe.concurrency.clamp(1, 8);
    let db_clone = db.clone();

    stream::iter(urls)
        .for_each_concurrent(concurrency, move |asset| {
            let db = db_clone.clone();
            let client = client.clone();
            let batch_id = batch.id.clone();
            async move {
                if matches!(db.should_stop_batch(&batch_id), Ok(true)) {
                    let _ = db.add_pending_work(
                        &batch_id,
                        &asset.system_id,
                        "vuln_scan",
                        &asset.url,
                        5,
                    );
                    return;
                }
                if let Err(error) = check_sourcemap(&db, &client, config, &batch_id, &asset).await {
                    warn!(url = %asset.url, %error, "sourcemap poc failed");
                }
            }
        })
        .await;

    Ok(())
}

/// Replays old unfinished vulnerability scan URLs before new work.
async fn replay_pending_work(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch: &BatchContext,
) -> anyhow::Result<()> {
    for (id, target) in db.take_pending_work("vuln_scan", 100)? {
        if db.should_stop_batch(&batch.id)? {
            break;
        }
        let fake = UrlAsset {
            id: id.clone(),
            system_id: String::new(),
            system_name: String::new(),
            url: target,
            source: "pending".to_string(),
            status_code: None,
            value_score: 0,
            is_baseline: false,
        };
        let _ = collect_sourcemap_candidates(client, config, &fake.url).await;
        db.finish_pending_work(&id)?;
        sleep(config.per_target_delay()).await;
    }
    Ok(())
}

/// Checks whether webpack JavaScript source maps are exposed.
async fn check_sourcemap(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch_id: &str,
    asset: &UrlAsset,
) -> anyhow::Result<()> {
    let candidates = collect_sourcemap_candidates(client, config, &asset.url).await?;
    for map_url in candidates {
        sleep(config.per_target_delay()).await;
        let response = match client.get(&map_url).send().await {
            Ok(response) => response,
            Err(_) => continue,
        };
        if !response.status().is_success() {
            continue;
        }
        let body = response.text().await.unwrap_or_default();
        if looks_like_sourcemap(&body) {
            db.add_vulnerability(
                batch_id,
                &asset.system_id,
                &map_url,
                "webpack_sourcemap_disclosure",
                "medium",
                "JavaScript source map file is accessible",
            )?;
            db.add_alert(
                batch_id,
                Some(&asset.system_id),
                "vulnerability",
                "medium",
                &map_url,
                None,
                Some("webpack_sourcemap_disclosure"),
                None,
            )?;
        }
    }
    Ok(())
}

/// Collects source map candidate URLs by fetching a page or JS asset.
async fn collect_sourcemap_candidates(
    client: &Client,
    config: &AppConfig,
    url: &str,
) -> anyhow::Result<BTreeSet<String>> {
    let base = Url::parse(url)?;
    let mut candidates = BTreeSet::new();
    let body = match client.get(url).send().await {
        Ok(response) => response.text().await.unwrap_or_default(),
        Err(_) => String::new(),
    };

    let js_urls = if url.ends_with(".js") {
        BTreeSet::from([url.to_string()])
    } else {
        extract_script_urls(&body, &base)
    };

    for js_url in js_urls {
        sleep(config.per_target_delay()).await;
        let js_body = match client.get(&js_url).send().await {
            Ok(response) => response.text().await.unwrap_or_default(),
            Err(_) => continue,
        };
        if let Some(marker) = source_mapping_url(&js_body)
            && let Ok(js_base) = Url::parse(&js_url)
            && let Ok(map_url) = js_base.join(&marker)
        {
            candidates.insert(map_url.to_string());
        }
        if js_url.ends_with(".js") {
            candidates.insert(format!("{js_url}.map"));
        }
    }

    Ok(candidates)
}

/// Extracts script URLs from an HTML document.
fn extract_script_urls(body: &str, base: &Url) -> BTreeSet<String> {
    let regex = Regex::new(r#"(?i)<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']"#)
        .expect("static regex must compile");
    regex
        .captures_iter(body)
        .filter_map(|capture| capture.get(1))
        .filter_map(|m| base.join(m.as_str()).ok())
        .map(|url| url.to_string())
        .collect()
}

/// Finds a `sourceMappingURL` marker in JavaScript text.
fn source_mapping_url(body: &str) -> Option<String> {
    let regex =
        Regex::new(r#"(?m)//[#@]\s*sourceMappingURL=([^\s]+)"#).expect("static regex must compile");
    regex
        .captures(body)
        .and_then(|capture| capture.get(1))
        .map(|m| m.as_str().trim().to_string())
}

/// Returns true when a body has the common JSON shape of a source map.
fn looks_like_sourcemap(body: &str) -> bool {
    body.contains("\"version\"")
        && body.contains("\"sources\"")
        && (body.contains("\"mappings\"") || body.contains("\"sourcesContent\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_source_mapping_marker() {
        assert_eq!(
            source_mapping_url("console.log(1);\n//# sourceMappingURL=app.js.map"),
            Some("app.js.map".to_string())
        );
    }

    #[test]
    fn detects_sourcemap_shape() {
        assert!(looks_like_sourcemap(
            r#"{"version":3,"sources":["a.js"],"mappings":"AAAA"}"#
        ));
    }
}

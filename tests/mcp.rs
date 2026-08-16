//! Contract tests for the watcher MCP inventory surface.

use clap::Parser;
use watcher::cli::{Cli, Commands};
use watcher::db::Database;
use watcher::mcp::{PROMPT_NAMES, TOOL_NAMES, WatcherMcp, prompts};
use watcher::models::AssetQuery;

fn seeded_db() -> (tempfile::TempDir, Database) {
    let directory = tempfile::tempdir().unwrap();
    let db = Database::open(&directory.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();

    let core = db.upsert_system("core").unwrap();
    let other = db.upsert_system("other").unwrap();
    let core_ip = db.upsert_ip(&core, "10.0.0.1", "imported").unwrap();
    let other_ip = db.upsert_ip(&other, "10.0.0.2", "imported").unwrap();
    db.upsert_domain_for_system("core", "app.example.com", Some("10.0.0.1"))
        .unwrap();

    let batch = db.create_batch().unwrap();
    db.record_ip_scan(&batch.id, &core, &core_ip, "10.0.0.1", &[80, 22], 100, true)
        .unwrap();
    db.record_ip_scan(&batch.id, &other, &other_ip, "10.0.0.2", &[8080], 100, true)
        .unwrap();

    let http = db
        .list_open_ports()
        .unwrap()
        .into_iter()
        .find(|port| port.port == 80)
        .unwrap();
    db.update_port_fingerprint(&http.id, Some("http"), Some("nginx"), true, Some("http"))
        .unwrap();

    db.upsert_url(
        &core,
        "https://app.example.com/login",
        "enum",
        Some(200),
        10,
    )
    .unwrap();
    db.upsert_url(
        &core,
        "https://app.example.com/missing",
        "enum",
        Some(404),
        1,
    )
    .unwrap();
    db.upsert_url(
        &core,
        "https://app.example.com/pending",
        "imported",
        None,
        0,
    )
    .unwrap();
    db.upsert_url(&other, "https://other.example.com/", "enum", Some(302), 5)
        .unwrap();

    db.add_alert(
        &batch.id,
        Some(&core),
        "port_change",
        "high",
        "10.0.0.1",
        None,
        Some("open"),
        None,
    )
    .unwrap();
    db.add_vulnerability(
        &batch.id,
        &core,
        "https://app.example.com/login",
        "webpack_sourcemap_disclosure",
        "medium",
        "map found",
    )
    .unwrap();

    (directory, db)
}

#[test]
fn live_inventory_keeps_only_open_ports_and_successful_urls() {
    let (_directory, db) = seeded_db();
    let inventory = db.live_inventory(&AssetQuery::default()).unwrap();

    let mut ports = inventory
        .live_ports
        .items
        .iter()
        .map(|port| port.port)
        .collect::<Vec<_>>();
    ports.sort_unstable();
    assert_eq!(ports, vec![22, 80, 8080]);
    assert_eq!(inventory.live_ports.total, 3);
    assert!(!inventory.live_ports.has_more);
    assert!(
        inventory
            .live_ports
            .items
            .iter()
            .all(|port| port.state == "open")
    );

    assert_eq!(inventory.web_services.items.len(), 1);
    assert_eq!(inventory.web_services.items[0].port, 80);
    assert_eq!(
        inventory.web_services.items[0].scheme.as_deref(),
        Some("http")
    );

    let mut urls = inventory
        .live_urls
        .items
        .iter()
        .map(|url| url.url.as_str())
        .collect::<Vec<_>>();
    urls.sort_unstable();
    assert_eq!(
        urls,
        vec![
            "https://app.example.com/login",
            "https://other.example.com/"
        ]
    );
}

#[test]
fn inventory_filters_by_business_system() {
    let (_directory, db) = seeded_db();
    let query = AssetQuery {
        system: Some("core".into()),
        keyword: None,
        limit: 50,
        offset: 0,
    };

    let ports = db.list_open_ports_filtered(&query).unwrap();
    assert!(ports.items.iter().all(|port| port.system_name == "core"));
    assert_eq!(ports.items.len(), 2);
    assert_eq!(ports.total, 2);

    let urls = db.list_live_urls_filtered(&query).unwrap();
    assert_eq!(urls.items.len(), 1);
    assert_eq!(urls.items[0].url, "https://app.example.com/login");

    let context = db.system_context("core", &query).unwrap();
    assert_eq!(context.system.name, "core");
    assert_eq!(context.live_ports.items.len(), 2);
    assert_eq!(context.web_services.items.len(), 1);
    assert_eq!(context.live_urls.items.len(), 1);
    assert!(!context.alerts.items.is_empty());
    assert!(
        context
            .alerts
            .items
            .iter()
            .all(|alert| alert.system_name.as_deref() == Some("core"))
    );

    assert_eq!(context.vulnerabilities.items.len(), 1);
}

#[test]
fn keyword_filter_matches_web_fingerprint() {
    let (_directory, db) = seeded_db();
    let query = AssetQuery {
        system: None,
        keyword: Some("nginx".into()),
        limit: 50,
        offset: 0,
    };
    let web = db.list_web_services_filtered(&query).unwrap();
    assert_eq!(web.items.len(), 1);
    assert_eq!(web.items[0].port, 80);
}

#[test]
fn missing_system_context_is_an_error() {
    let (_directory, db) = seeded_db();
    let error = db
        .system_context("missing", &AssetQuery::default())
        .unwrap_err()
        .to_string();
    assert!(error.contains("business system not found"));
}

#[test]
fn mcp_catalog_advertises_inventory_tools_and_prompts() {
    let tools = WatcherMcp::tool_names();
    let prompts = WatcherMcp::prompt_names();
    for name in TOOL_NAMES {
        assert!(tools.iter().any(|item| item == name), "missing tool {name}");
    }
    for name in PROMPT_NAMES {
        assert!(
            prompts.iter().any(|item| item == name),
            "missing prompt {name}"
        );
    }
}

#[test]
fn pentest_prompt_includes_live_url() {
    let (_directory, db) = seeded_db();
    let context = db.system_context("core", &AssetQuery::default()).unwrap();
    let text = prompts::pentest_system_prompt(&context);
    assert!(text.contains("https://app.example.com/login"));
    assert!(text.contains("authorized"));
    assert!(!text.contains("https://app.example.com/missing"));
}

#[test]
fn live_port_pages_report_total_and_next_offset() {
    let (_directory, db) = seeded_db();
    let first = db
        .list_open_ports_filtered(&AssetQuery {
            limit: 2,
            offset: 0,
            ..AssetQuery::default()
        })
        .unwrap();
    assert_eq!(first.items.len(), 2);
    assert_eq!(first.total, 3);
    assert!(first.has_more);
    assert_eq!(first.next_offset, Some(2));

    let second = db
        .list_open_ports_filtered(&AssetQuery {
            limit: 2,
            offset: 2,
            ..AssetQuery::default()
        })
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.total, 3);
    assert!(!second.has_more);
    assert_eq!(second.next_offset, None);

    let beyond = db
        .list_open_ports_filtered(&AssetQuery {
            limit: 2,
            offset: 50,
            ..AssetQuery::default()
        })
        .unwrap();
    assert!(beyond.items.is_empty());
    assert_eq!(beyond.total, 3);
    assert!(!beyond.has_more);
}

#[test]
fn page_limit_is_capped_below_full_table_dumps() {
    let query = AssetQuery {
        limit: 10_000,
        offset: 0,
        ..AssetQuery::default()
    }
    .sanitized();
    assert_eq!(query.limit, watcher::models::MAX_ASSET_QUERY_LIMIT);
    assert_eq!(watcher::models::MAX_ASSET_QUERY_LIMIT, 200);
}

#[test]
fn parses_mcp_command() {
    let cli = Cli::try_parse_from(["watcher", "mcp"]).unwrap();
    assert!(matches!(cli.command, Some(Commands::Mcp)));
}

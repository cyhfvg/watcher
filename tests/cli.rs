//! `watcher::cli` 公开路径的集成测试.

use clap::Parser;
use watcher::cli::{
    Cli, Commands, EntityAddArgs, EntityCommands, handle_ips, handle_names, handle_ports,
    handle_urls,
};
use watcher::db::Database;

fn add_args(value: &str, ip: Option<&str>, bind_ip: Option<&str>) -> EntityAddArgs {
    EntityAddArgs {
        system: "core".to_string(),
        ip: ip.map(str::to_string),
        bind_ip: bind_ip.map(str::to_string),
        value: value.to_string(),
    }
}

#[test]
fn manually_adds_each_non_baseline_asset_type() {
    let directory = tempfile::tempdir().unwrap();
    let db = Database::open(&directory.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();

    handle_urls(
        &db,
        EntityCommands::Add(add_args("https://example.com/admin", None, None)),
    )
    .unwrap();
    handle_ports(
        &db,
        EntityCommands::Add(add_args("8443", Some("10.0.0.1"), None)),
    )
    .unwrap();
    handle_ips(&db, EntityCommands::Add(add_args("10.0.0.2", None, None))).unwrap();
    handle_names(
        &db,
        EntityCommands::Add(add_args("app.example.com", None, Some("10.0.0.1"))),
    )
    .unwrap();

    assert_eq!(db.query_urls(Some("admin"), 10).unwrap().len(), 1);
    assert_eq!(db.query_ports(Some("8443"), 10).unwrap().len(), 1);
    assert_eq!(db.query_ips(Some("10.0.0.2"), 10).unwrap().len(), 1);
    assert_eq!(
        db.query_names(Some("app.example.com"), 10).unwrap().len(),
        1
    );
    assert!(!db.list_urls().unwrap()[0].is_baseline);
}

#[test]
fn parses_single_asset_add_command() {
    let cli = Cli::try_parse_from([
        "watcher", "port", "add", "--system", "core", "--ip", "10.0.0.1", "443",
    ])
    .unwrap();

    let Some(Commands::Port(EntityCommands::Add(args))) = cli.command else {
        panic!("expected port add command");
    };
    assert_eq!(args.system, "core");
    assert_eq!(args.ip.as_deref(), Some("10.0.0.1"));
    assert_eq!(args.value, "443");
}

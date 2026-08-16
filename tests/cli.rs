//! Integration tests for public `watcher::cli` paths.

use clap::Parser;
use watcher::cli::{AddArgs, AddTarget, Cli, Commands, ImportTarget, InspectTarget, handle_add};
use watcher::db::Database;

fn add_args(
    target: AddTarget,
    value: &str,
    ip: Option<&str>,
    bind_ip: Option<&str>,
    baseline: bool,
) -> AddArgs {
    AddArgs {
        target,
        baseline,
        system: Some("core".to_string()),
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

    handle_add(
        &db,
        add_args(
            AddTarget::Url,
            "https://example.com/admin",
            None,
            None,
            false,
        ),
    )
    .unwrap();
    handle_add(
        &db,
        add_args(AddTarget::Port, "8443", Some("10.0.0.1"), None, false),
    )
    .unwrap();
    handle_add(&db, add_args(AddTarget::Ip, "10.0.0.2", None, None, false)).unwrap();
    handle_add(
        &db,
        add_args(
            AddTarget::Name,
            "app.example.com",
            None,
            Some("10.0.0.1"),
            false,
        ),
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
        "watcher", "add", "--type", "port", "--system", "core", "--ip", "10.0.0.1", "443",
    ])
    .unwrap();

    let Some(Commands::Add(args)) = cli.command else {
        panic!("expected add command");
    };
    assert_eq!(args.target, AddTarget::Port);
    assert!(!args.baseline);
    assert_eq!(args.system.as_deref(), Some("core"));
    assert_eq!(args.ip.as_deref(), Some("10.0.0.1"));
    assert_eq!(args.value, "443");
}

#[test]
fn parses_baseline_import_and_log_query() {
    let import =
        Cli::try_parse_from(["watcher", "import", "--type", "excel", "./assets.xlsx"]).unwrap();
    let Some(Commands::Import(args)) = import.command else {
        panic!("expected import command");
    };
    assert_eq!(args.target, ImportTarget::Excel);

    let query = Cli::try_parse_from(["watcher", "query", "--type", "log", "--limit", "5"]).unwrap();
    let Some(Commands::Query(args)) = query.command else {
        panic!("expected query command");
    };
    assert_eq!(args.target, InspectTarget::Log);
    assert_eq!(args.limit, 5);

    let list_alias = Cli::try_parse_from(["watcher", "list", "-t", "system"]).unwrap();
    assert!(matches!(
        list_alias.command,
        Some(Commands::Query(args)) if args.target == InspectTarget::System
    ));
}

#[test]
fn rejects_old_noun_first_commands() {
    assert!(Cli::try_parse_from(["watcher", "port", "add", "--system", "core", "443"]).is_err());
    assert!(Cli::try_parse_from(["watcher", "log", "query"]).is_err());
    assert!(Cli::try_parse_from(["watcher", "system", "add", "core"]).is_err());
    assert!(
        Cli::try_parse_from([
            "watcher",
            "baseline",
            "import",
            "--asset-type",
            "excel",
            "a.xlsx"
        ])
        .is_err()
    );
}

#[test]
fn adds_baseline_asset_through_action_flag() {
    let directory = tempfile::tempdir().unwrap();
    let db = Database::open(&directory.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();

    handle_add(&db, add_args(AddTarget::Ip, "10.0.0.8", None, None, true)).unwrap();

    let rows = db.query_baseline_ips(Some("10.0.0.8"), 10).unwrap();
    assert_eq!(rows.len(), 1);
}

#[test]
fn rejects_invalid_type_for_add() {
    assert!(Cli::try_parse_from(["watcher", "add", "--type", "excel", "x"]).is_err());
    assert!(Cli::try_parse_from(["watcher", "add", "--type", "log", "x"]).is_err());
    assert!(Cli::try_parse_from(["watcher", "query", "--type", "excel"]).is_err());
}

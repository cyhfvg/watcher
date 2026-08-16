//! Integration tests for the public database API.

use watcher::db::Database;

#[test]
fn dashboard_snapshot_aggregates_assets_progress_queue_and_risk() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();
    let system_id = db.upsert_system("core").unwrap();
    db.upsert_baseline_domain_for_system("core", "example.com", None)
        .unwrap();
    db.upsert_baseline_ip_for_system("core", "10.0.0.1", "imported")
        .unwrap();
    db.upsert_baseline_url_for_system("core", "https://example.com", "imported")
        .unwrap();
    db.import_dict_paths(&["admin".to_string()]).unwrap();
    let batch = db.create_batch().unwrap();
    db.start_batch_stage(&batch.id, "dns").unwrap();
    db.finish_batch_stage(&batch.id, "dns", "completed", None)
        .unwrap();
    db.add_pending_work(
        &batch.id,
        &system_id,
        "web_enum",
        "https://example.com/admin",
        10,
    )
    .unwrap();
    db.add_alert(
        &batch.id,
        Some(&system_id),
        "dns_change",
        "high",
        "example.com",
        Some("1.1.1.1"),
        Some("2.2.2.2"),
        None,
    )
    .unwrap();

    let snapshot = db.dashboard_snapshot().unwrap();
    assert_eq!(snapshot.assets.systems, 1);
    assert_eq!(snapshot.assets.domains, 1);
    assert_eq!(snapshot.assets.dictionary_paths, 1);
    assert_eq!(snapshot.queue.pending, 1);
    assert_eq!(snapshot.alert_severity.high, 1);
    assert_eq!(snapshot.stages.len(), 1);
    assert_eq!(snapshot.stages[0].status, "completed");
    assert_eq!(snapshot.recent_alerts.len(), 1);
    assert_eq!(
        snapshot.latest_batch.as_ref().map(|batch| &batch.id),
        Some(&batch.id)
    );
}

#[test]
fn interrupting_a_batch_marks_running_dashboard_stages_interrupted() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();
    let batch = db.create_batch().unwrap();
    db.start_batch_stage(&batch.id, "port_scan").unwrap();

    assert_eq!(db.interrupt_running_batches("process exited").unwrap(), 1);

    let snapshot = db.dashboard_snapshot().unwrap();
    assert_eq!(snapshot.stages[0].status, "interrupted");
    assert_eq!(snapshot.stages[0].detail.as_deref(), Some("process exited"));
}

#[test]
fn migrates_and_upserts_assets() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();
    db.upsert_baseline_domain_for_system("core", "example.com", Some("1.1.1.1"))
        .unwrap();
    db.upsert_baseline_ip_for_system("core", "10.0.0.1", "imported")
        .unwrap();
    db.upsert_baseline_url_for_system("core", "https://example.com", "imported")
        .unwrap();
    db.import_dict_paths(&["admin".to_string()]).unwrap();
    db.add_log("INFO", "watcher::test", "hello", None).unwrap();

    assert_eq!(db.list_domains().unwrap().len(), 1);
    assert_eq!(db.list_real_ips().unwrap().len(), 1);
    assert_eq!(db.list_urls().unwrap().len(), 1);
    let systems = db.query_systems(None, 10).unwrap();
    assert_eq!(systems.len(), 1);
    assert_eq!(systems[0][0], "core");
    assert_eq!(systems[0][1], "1");
    assert_eq!(systems[0][2], "1");
    assert_eq!(systems[0][4], "1");
    assert_eq!(systems[0][5], "1");
    assert!(db.list_domains().unwrap()[0].is_baseline);
    assert!(db.list_real_ips().unwrap()[0].is_baseline);
    assert!(db.list_urls().unwrap()[0].is_baseline);
    assert_eq!(db.rename_system("core", "core-renamed").unwrap(), 1);
    assert_eq!(
        db.query_systems(Some("renamed"), 10).unwrap()[0][0],
        "core-renamed"
    );
    assert_eq!(
        db.set_name_baseline_for_system("core", "example.com", false)
            .unwrap(),
        0
    );
    db.migrate().unwrap();
    db.set_name_baseline_for_system("core-renamed", "example.com", false)
        .unwrap();
    assert!(!db.list_domains().unwrap()[0].is_baseline);
    assert_eq!(db.list_dict_paths(10).unwrap(), vec!["/admin"]);
    assert_eq!(
        db.query_logs(Some("INFO"), Some("hello"), 10)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(db.delete_system("core-renamed").unwrap(), 1);
    assert!(db.list_domains().unwrap().is_empty());
}

#[test]
fn bulk_imports_non_baseline_entity_assets() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();

    db.upsert_baseline_ip_for_system("core", "10.0.0.1", "manual")
        .unwrap();
    db.upsert_baseline_url_for_system("core", "https://example.com", "manual")
        .unwrap();
    db.upsert_baseline_domain_for_system("core", "example.com", None)
        .unwrap();
    db.upsert_baseline_port_for_system("core", Some("10.0.0.1"), 443, "manual")
        .unwrap();

    assert_eq!(
        db.import_ips_for_system(
            "core",
            &["10.0.0.1".to_string(), "10.0.0.2".to_string()],
            "manual",
        )
        .unwrap(),
        2
    );
    assert_eq!(
        db.import_urls_for_system(
            "core",
            &[
                "https://example.com".to_string(),
                "https://example.com/login".to_string(),
            ],
            "manual",
        )
        .unwrap(),
        2
    );
    assert_eq!(
        db.import_names_for_system(
            "core",
            &["example.com.".to_string(), "www.example.com".to_string()],
            Some("10.0.0.2"),
        )
        .unwrap(),
        2
    );
    assert_eq!(
        db.import_ports_for_system("core", Some("10.0.0.1"), &[443, 8443], "manual")
            .unwrap(),
        2
    );

    let systems = db.query_systems(Some("core"), 10).unwrap();
    assert_eq!(systems[0][1], "2");
    assert_eq!(systems[0][2], "2");
    assert_eq!(systems[0][3], "2");
    assert_eq!(systems[0][4], "2");
    assert_eq!(systems[0][5], "1");
    assert_eq!(systems[0][6], "1");
    assert_eq!(systems[0][7], "1");
    assert_eq!(systems[0][8], "1");
}

#[test]
fn bulk_imports_dict_paths() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();

    let count = db
        .import_dict_paths(&[
            "admin".to_string(),
            "/login".to_string(),
            "admin".to_string(),
            " ".to_string(),
        ])
        .unwrap();

    assert_eq!(count, 3);
    assert_eq!(db.list_dict_paths(10).unwrap(), vec!["/admin", "/login"]);
}

#[test]
fn pending_work_replay_keeps_latest_system_context() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();
    let batch = db.create_batch().unwrap();

    db.add_pending_work(
        &batch.id,
        "system-a",
        "web_enum",
        "https://example.com/a",
        10,
    )
    .unwrap();
    db.add_pending_work(
        &batch.id,
        "system-b",
        "web_enum",
        "https://example.com/a",
        5,
    )
    .unwrap();

    let pending = db.take_pending_work("web_enum", 10).unwrap();

    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].system_id, "system-b");
    assert_eq!(pending[0].target, "https://example.com/a");
}

#[test]
fn interrupts_leftover_running_batches_before_new_batch() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();

    let stale = db.create_batch().unwrap();
    let fresh = db.create_batch().unwrap();

    let stale_status = db.batch_status(Some(&stale.id)).unwrap();
    assert_eq!(stale_status.status, "interrupted");
    let fresh_status = db.batch_status(Some(&fresh.id)).unwrap();
    assert_eq!(fresh_status.status, "running");
}

#[test]
fn record_ip_scan_stores_only_open_ports_and_aggregated_alerts() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();
    let system_id = db.upsert_system("core").unwrap();
    let ip_id = db.upsert_ip(&system_id, "10.0.0.1", "imported").unwrap();
    db.upsert_baseline_port_for_system("core", Some("10.0.0.1"), 22, "imported")
        .unwrap();
    let batch = db.create_batch().unwrap();
    db.record_ip_scan(&batch.id, &system_id, &ip_id, "10.0.0.1", &[22], 1, true)
        .unwrap();

    db.record_ip_scan(
        &batch.id,
        &system_id,
        &ip_id,
        "10.0.0.1",
        &[80, 443],
        65_535,
        true,
    )
    .unwrap();

    let ports = db.list_open_ports().unwrap();
    assert_eq!(
        ports.iter().map(|port| port.port).collect::<Vec<_>>(),
        vec![80, 443]
    );
    assert!(ports.iter().all(|port| port.state == "open"));

    let alerts = db.list_alerts(&batch.id).unwrap();
    let opened = alerts
        .iter()
        .filter(|alert| alert.new_value.as_deref() == Some("open"))
        .collect::<Vec<_>>();
    assert_eq!(opened.len(), 2);
    let latest_open = opened
        .iter()
        .find(|alert| {
            alert
                .details
                .as_deref()
                .is_some_and(|details| details.contains("80"))
        })
        .unwrap();
    assert_eq!(latest_open.subject, "10.0.0.1");
    let closed = alerts
        .iter()
        .find(|alert| alert.new_value.as_deref() == Some("closed"))
        .unwrap();
    assert!(closed.details.as_deref().unwrap().contains("22"));

    let summaries = db.list_scan_summaries(&batch.id).unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].probed_ports, 65_535);
    assert_eq!(summaries[0].open_count, 2);
    assert_eq!(summaries[0].opened_ports.as_deref(), Some("80,443"));
    assert_eq!(summaries[0].closed_ports.as_deref(), Some("22"));
}

#[test]
fn incomplete_ip_scan_does_not_close_existing_open_ports() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();
    let system_id = db.upsert_system("core").unwrap();
    let ip_id = db.upsert_ip(&system_id, "10.0.0.1", "imported").unwrap();
    let batch = db.create_batch().unwrap();
    db.record_ip_scan(
        &batch.id,
        &system_id,
        &ip_id,
        "10.0.0.1",
        &[80, 443],
        2,
        true,
    )
    .unwrap();

    db.record_ip_scan(&batch.id, &system_id, &ip_id, "10.0.0.1", &[22], 1, false)
        .unwrap();

    let mut ports = db
        .list_open_ports()
        .unwrap()
        .into_iter()
        .map(|port| port.port)
        .collect::<Vec<_>>();
    ports.sort_unstable();
    assert_eq!(ports, vec![22, 80, 443]);
}

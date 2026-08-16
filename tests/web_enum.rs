//! Integration tests for the public `web_enum::run` path.

use watcher::{config::AppConfig, db::Database, monitor::web_enum};

/// Starts an enumeration fixture that returns a useful body for `/good` and a
/// negative marker for `/fake`.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// Local listen port.
async fn serve_enumeration_fixture() -> u16 {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let size = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            let body = if request.starts_with("GET /good ") {
                "useful content"
            } else if request.starts_with("GET /fake ") {
                "gateway placeholder: not found marker"
            } else {
                "<html>home</html>"
            };
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(body.as_bytes()).await.unwrap();
        }
    });
    port
}

#[tokio::test]
async fn enumeration_persists_valuable_paths_and_filters_fake_successes() {
    let directory = tempfile::tempdir().unwrap();
    let db = Database::open(&directory.path().join("watcher.db")).unwrap();
    db.migrate().unwrap();
    let system_id = db.upsert_system("core").unwrap();
    let ip_id = db.upsert_ip(&system_id, "127.0.0.1", "manual").unwrap();
    let port = serve_enumeration_fixture().await;
    let port_id = db
        .upsert_port(&system_id, Some(&ip_id), port, "scan")
        .unwrap();
    let batch = db.create_batch().unwrap();
    db.record_ip_scan(&batch.id, &system_id, &ip_id, "127.0.0.1", &[port], 1, true)
        .unwrap();
    db.update_port_fingerprint(&port_id, Some("web"), None, true, Some("http"))
        .unwrap();
    db.import_dict_paths(&["good".to_string(), "fake".to_string()])
        .unwrap();

    let mut config: AppConfig = serde_yaml::from_str(&AppConfig::example_yaml().unwrap()).unwrap();
    config.probe.per_target_delay_ms = 0;
    config.web.max_js_paths_per_service = 0;
    config.web.negative_body_markers = vec!["not found marker".to_string()];

    web_enum::run(&db, &config, &batch).await.unwrap();

    let urls: Vec<_> = db
        .list_urls()
        .unwrap()
        .into_iter()
        .map(|asset| asset.url)
        .collect();
    assert!(urls.iter().any(|url| url.ends_with("/good")));
    assert!(!urls.iter().any(|url| url.ends_with("/fake")));
}

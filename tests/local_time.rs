//! Integration tests for the public timezone API.

#[test]
fn parses_display_timezones() {
    assert!(watcher::local_time::parse_timezone("+08:00").is_ok());
    assert!(watcher::local_time::parse_timezone("UTC+8").is_ok());
    assert!(watcher::local_time::parse_timezone("-0530").is_ok());
    assert!(watcher::local_time::parse_timezone("Asia/Shanghai").is_ok());

    watcher::local_time::configure("+08:00").unwrap();
    assert_eq!(watcher::local_time::configured_timezone(), "+08:00");
}

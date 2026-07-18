//! Public-library smoke tests for the watcher binary facade.

use watcher::config::AppConfig;

#[test]
fn library_exposes_the_default_configuration_example() {
    let example = AppConfig::example_yaml().unwrap();

    assert!(example.contains("scheduler:"));
    assert!(example.contains("probe:"));
}

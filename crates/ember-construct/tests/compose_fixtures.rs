//! T2 — Compose V2 YAML fixture round-trip tests.
//!
//! implementation-note-93. Parses the YAML
//! fixtures under `tests/fixtures/compose/` and asserts the key
//! fields land in the right bollard slots.
//!
//! Fixtures are checked into the repo so the test is deterministic
//! and doesn't depend on a live Docker engine.

use bollard::models::MountTypeEnum;
use ember_construct::docker::{compose_manifest_to_docker_spec, parse_compose_yaml};

const FIXTURE_DIR: &str = "tests/fixtures/compose";

fn load(name: &str) -> String {
    let path = format!("{FIXTURE_DIR}/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn minimal_fixture_translates() {
    let yaml = load("minimal.yaml");
    let manifest = parse_compose_yaml(&yaml).expect("parse");
    let spec = compose_manifest_to_docker_spec(&manifest).expect("translate");

    assert_eq!(spec.config.image.as_deref(), Some("alpine:3.20"));
    assert!(spec.config.cmd.is_none());
    assert!(spec.config.env.is_none());
    assert!(spec.host_config.mounts.is_none());
    assert!(spec.host_config.network_mode.is_none());
}

#[test]
fn full_fixture_round_trips_all_mapped_fields() {
    let yaml = load("full.yaml");
    let manifest = parse_compose_yaml(&yaml).expect("parse");
    let spec = compose_manifest_to_docker_spec(&manifest).expect("translate");

    // Image
    assert_eq!(
        spec.config.image.as_deref(),
        Some("ghcr.io/example/api:1.2.3")
    );

    // Command (list form)
    let cmd = spec.config.cmd.as_ref().expect("cmd present");
    assert_eq!(
        cmd,
        &vec!["sh".to_string(), "-c".to_string(), "echo hi".to_string()]
    );

    // Entrypoint (string form → split)
    let entrypoint = spec.config.entrypoint.as_ref().expect("entrypoint present");
    assert_eq!(entrypoint, &vec!["/bin/bash".to_string()]);

    // Environment (map form → KEY=VALUE pairs, order not asserted)
    let env = spec.config.env.as_ref().expect("env present");
    assert!(
        env.iter().any(|e| e == "LOG_LEVEL=debug"),
        "env missing LOG_LEVEL: {env:?}"
    );
    assert!(
        env.iter().any(|e| e == "MODE=production"),
        "env missing MODE: {env:?}"
    );

    // Mounts (bind, with explicit RW/RO)
    let mounts = spec.host_config.mounts.as_ref().expect("mounts present");
    assert_eq!(mounts.len(), 2);

    let data = mounts
        .iter()
        .find(|m| m.target.as_deref() == Some("/data"))
        .expect("/data mount present");
    assert_eq!(data.source.as_deref(), Some("/host/data"));
    assert_eq!(data.typ, Some(MountTypeEnum::BIND));
    assert_eq!(data.read_only, Some(false));

    let cache = mounts
        .iter()
        .find(|m| m.target.as_deref() == Some("/cache"))
        .expect("/cache mount present");
    assert_eq!(cache.source.as_deref(), Some("/host/cache"));
    assert_eq!(cache.read_only, Some(true));

    // Network mode
    assert_eq!(spec.host_config.network_mode.as_deref(), Some("bridge"));

    // Labels
    let labels = spec.config.labels.as_ref().expect("labels present");
    assert_eq!(labels.get("owner").map(String::as_str), Some("alice"));
    assert_eq!(labels.get("service").map(String::as_str), Some("api"));

    // HostConfig nests into config.
    assert!(spec.config.host_config.is_some());
}

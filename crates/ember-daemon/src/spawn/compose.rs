//! Compose V2 spawn lifecycle (daemon side).
//!
//! implementation-note-91 — wires the
//! ember-construct `compose_manifest_to_docker_spec` translator into a
//! daemon-side spawn helper. Given a [`ComposeManifest`] and a connected
//! [`bollard::Docker`] client, [`spawn_compose_service`] composes the
//! `Config<String>` / `HostConfig` pair and dispatches via the same
//! `create_container` + `start_container` engine roundtrip Slice B's
//! `docker_engine_spawn` audits. We deliberately reach for
//! `Docker::create_container` directly here rather than building a
//! `SpawnSpec` and dispatching through `docker_engine_spawn`, because
//! the Compose manifest already carries the merged `Config<String>` /
//! `HostConfig` pair and a re-construction round-trip would duplicate
//! the translator's work.
//!
//! ## Slice contract (this file)
//!
//! - **Translation:** delegate to
//!   [`ember_construct::docker::compose_manifest_to_docker_spec`].
//!   This module never duplicates the Compose→bollard mapping logic.
//! - **Label merge:** Slice B's [`crate::spawn::docker::SpawnSpec`]
//!   stamps `emberlink.persona_id` / `emberlink.agent_uuid` /
//!   `emberlink.task_id` / `emberlink.created_at`. The Compose
//!   manifest's `labels:` block is preserved AS-IS in the
//!   `DockerContainerSpec`; merging the canonical daemon labels in is
//!   the caller's responsibility. The helper here exposes
//!   [`merge_daemon_labels`] to centralise the merge order (Compose
//!   labels first, canonical `emberlink.*` last so they cannot be
//!   shadowed).
//! - **Network mode privilege guard:** the Construct argv classifier
//!   rejects `--network=host` at the shim boundary. This module
//!   re-asserts the same rule at the daemon boundary — a
//!   `network_mode: host` Compose entry is rejected as
//!   [`ComposeSpawnError::PrivilegedNetworkMode`] before the engine
//!   roundtrip. Defence in depth, not defence instead-of.
//!
//! ## Lifecycle wiring (out of scope here, sketched for context)
//!
//! The full Compose lifecycle — translate → label-merge → privilege
//! check → engine roundtrip via `docker_engine_spawn` — is staged in
//! this module. The follow-up slice
//! implementation-note-96 wires this entry
//! point into the broker's `docker.run` mediated path (so a
//! Construct-side `docker compose up` call lands here instead of
//! shelling out to the host `docker` binary). Until D lands, callers
//! reach this module directly from integration tests.
//!
//! Anchor: `fn spawn_compose_service`.

use bollard::Docker;
use ember_construct::docker::{
    ComposeManifest, ComposeTranslationError, DockerContainerSpec, compose_manifest_to_docker_spec,
};

use crate::spawn::docker::{RuntimeSpawnError, SpawnedContainer};

/// Failure modes for the daemon-side Compose spawn path.
///
/// Each variant carries enough provenance for the broker-side caller
/// to emit a typed `spawn-failed` event without re-parsing.
#[derive(Debug, thiserror::Error)]
pub enum ComposeSpawnError {
    /// The manifest failed Compose→Docker translation. Carries the
    /// underlying [`ComposeTranslationError`] verbatim.
    #[error("compose translation failed: {0}")]
    Translation(#[from] ComposeTranslationError),

    /// The translated spec asks for a privileged network mode
    /// (`host`). The Construct argv classifier rejects this at the
    /// shim boundary too; the daemon re-asserts to prevent a Compose
    /// path from bypassing the deny rule.
    #[error("privileged network_mode '{0}' refused by daemon spawn policy")]
    PrivilegedNetworkMode(String),

    /// The engine roundtrip (`create_container` / `start_container`)
    /// failed. Carries the underlying [`RuntimeSpawnError`] verbatim.
    #[error("engine spawn failed: {0}")]
    Engine(#[from] RuntimeSpawnError),
}

/// Spawn a Compose V2 service through the daemon's engine path.
///
/// Translation + privilege check + engine roundtrip in one step.
/// Returns the same [`SpawnedContainer`] handle Slice B's
/// `docker_engine_spawn` produces so reconciler / cleanup code paths
/// don't fork.
///
/// # Errors
///
/// - [`ComposeSpawnError::Translation`] when the manifest is malformed
///   (missing image, named volume, multi-service ambiguity, …).
/// - [`ComposeSpawnError::PrivilegedNetworkMode`] when the spec asks
///   for `host` networking.
/// - [`ComposeSpawnError::Engine`] when the engine rejects the create
///   or start call.
pub async fn spawn_compose_service(
    docker: &Docker,
    manifest: &ComposeManifest,
) -> Result<SpawnedContainer, ComposeSpawnError> {
    let spec = compose_manifest_to_docker_spec(manifest)?;
    assert_safe_network_mode(&spec)?;

    // The DockerContainerSpec carries config + host_config; the
    // host_config is also nested into config.host_config by the
    // translator, so the engine call only needs `spec.config`.
    let create_options: Option<bollard::container::CreateContainerOptions<String>> = None;
    let created = docker
        .create_container(create_options, spec.config)
        .await
        .map_err(RuntimeSpawnError::CreateFailed)?;

    docker
        .start_container(
            &created.id,
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .map_err(|e| RuntimeSpawnError::StartFailed {
            container_id: created.id.clone(),
            source: e,
        })?;

    Ok(SpawnedContainer {
        container_id: created.id,
        name: None,
    })
}

/// Reject privileged network modes at the daemon boundary.
///
/// The Construct argv classifier already refuses `--network=host` at
/// the shim layer; this asserts the same invariant at the engine
/// boundary so a Compose-spec'd spawn cannot route around the shim
/// classifier.
fn assert_safe_network_mode(spec: &DockerContainerSpec) -> Result<(), ComposeSpawnError> {
    if let Some(mode) = spec.host_config.network_mode.as_deref()
        && (mode == "host" || mode.starts_with("container:"))
    {
        // `container:<id>` shares the network namespace of an existing
        // container — same trust-surface concern as `host`.
        return Err(ComposeSpawnError::PrivilegedNetworkMode(mode.to_string()));
    }
    Ok(())
}

/// Merge the daemon's canonical labels into a Compose-spec'd label
/// map. Compose labels go first; the canonical `emberlink.*` set goes
/// last so it cannot be shadowed by user-supplied keys.
///
/// This is the shared helper Slice D will call from the broker
/// dispatch. Exposed here so unit tests can pin the merge order
/// without needing the full broker harness.
pub fn merge_daemon_labels(
    compose_labels: Option<&std::collections::HashMap<String, String>>,
    persona_id: &str,
    agent_uuid: &str,
    task_id: &str,
    created_at_rfc3339: &str,
) -> std::collections::HashMap<String, String> {
    let mut out: std::collections::HashMap<String, String> = compose_labels.cloned().unwrap_or_default();
    out.insert("emberlink.persona_id".to_string(), persona_id.to_string());
    out.insert("emberlink.agent_uuid".to_string(), agent_uuid.to_string());
    out.insert("emberlink.task_id".to_string(), task_id.to_string());
    out.insert(
        "emberlink.created_at".to_string(),
        created_at_rfc3339.to_string(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ember_construct::docker::{ComposeManifest, ComposeService, parse_compose_yaml};

    fn manifest_with_network(mode: Option<&str>) -> ComposeManifest {
        let mut services = std::collections::BTreeMap::new();
        services.insert(
            "app".to_string(),
            ComposeService {
                image: "alpine".to_string(),
                network_mode: mode.map(str::to_string),
                ..Default::default()
            },
        );
        ComposeManifest {
            version: None,
            services,
        }
    }

    #[test]
    fn safe_network_modes_pass_through() {
        for mode in [None, Some("bridge"), Some("none")] {
            let m = manifest_with_network(mode);
            let spec = compose_manifest_to_docker_spec(&m).unwrap();
            assert!(
                assert_safe_network_mode(&spec).is_ok(),
                "mode {mode:?} should be allowed"
            );
        }
    }

    #[test]
    fn host_network_mode_is_refused() {
        let m = manifest_with_network(Some("host"));
        let spec = compose_manifest_to_docker_spec(&m).unwrap();
        match assert_safe_network_mode(&spec) {
            Err(ComposeSpawnError::PrivilegedNetworkMode(s)) => assert_eq!(s, "host"),
            other => panic!("expected PrivilegedNetworkMode, got {other:?}"),
        }
    }

    #[test]
    fn container_share_network_mode_is_refused() {
        let m = manifest_with_network(Some("container:abc123"));
        let spec = compose_manifest_to_docker_spec(&m).unwrap();
        match assert_safe_network_mode(&spec) {
            Err(ComposeSpawnError::PrivilegedNetworkMode(s)) => {
                assert_eq!(s, "container:abc123");
            }
            other => panic!("expected PrivilegedNetworkMode, got {other:?}"),
        }
    }

    #[test]
    fn translation_error_propagates() {
        // Empty image triggers MissingImage upstream.
        let mut services = std::collections::BTreeMap::new();
        services.insert(
            "app".to_string(),
            ComposeService {
                image: String::new(),
                ..Default::default()
            },
        );
        let m = ComposeManifest {
            version: None,
            services,
        };
        // We can't actually run the engine roundtrip without a Docker
        // client; verify that translation failure surfaces through the
        // ComposeSpawnError::Translation variant by translating
        // directly.
        let err = compose_manifest_to_docker_spec(&m).expect_err("missing image");
        let wrapped: ComposeSpawnError = err.into();
        match wrapped {
            ComposeSpawnError::Translation(ComposeTranslationError::MissingImage { service }) => {
                assert_eq!(service, "app");
            }
            other => panic!("expected Translation(MissingImage), got {other:?}"),
        }
    }

    #[test]
    fn merge_daemon_labels_preserves_compose_keys() {
        let mut compose = std::collections::HashMap::new();
        compose.insert("owner".to_string(), "alice".to_string());
        compose.insert("service".to_string(), "api".to_string());

        let merged = merge_daemon_labels(Some(&compose), "p1", "a1", "t1", "2026-05-21T00:00:00Z");
        assert_eq!(merged.get("owner").map(String::as_str), Some("alice"));
        assert_eq!(merged.get("service").map(String::as_str), Some("api"));
        assert_eq!(
            merged.get("emberlink.persona_id").map(String::as_str),
            Some("p1")
        );
        assert_eq!(
            merged.get("emberlink.agent_uuid").map(String::as_str),
            Some("a1")
        );
        assert_eq!(
            merged.get("emberlink.task_id").map(String::as_str),
            Some("t1")
        );
    }

    #[test]
    fn merge_daemon_labels_canonical_overrides_user() {
        let mut compose = std::collections::HashMap::new();
        // User tries to shadow the canonical persona_id label.
        compose.insert("emberlink.persona_id".to_string(), "evil".to_string());
        let merged = merge_daemon_labels(Some(&compose), "real-persona", "a", "t", "ts");
        assert_eq!(
            merged.get("emberlink.persona_id").map(String::as_str),
            Some("real-persona"),
            "canonical persona_id must override user-supplied shadow"
        );
    }

    #[test]
    fn end_to_end_yaml_translates_without_engine() {
        // T2 — round-trip the YAML fixture through the translator and
        // verify the daemon-side spec is well-formed. We don't touch a
        // real engine; that requires DOCKER_E2E gating and a live socket.
        let yaml = r#"
services:
  app:
    image: alpine:3.20
    command: ["echo", "hello"]
    environment:
      MODE: production
    network_mode: bridge
"#;
        let manifest = parse_compose_yaml(yaml).expect("parse");
        let spec = compose_manifest_to_docker_spec(&manifest).expect("translate");
        assert!(assert_safe_network_mode(&spec).is_ok());
        assert_eq!(spec.config.image.as_deref(), Some("alpine:3.20"));
    }
}
